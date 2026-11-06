/*
 * Copyright (c) 2026 ivfzhou
 * ipasigner is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/**
 * @file signing.cpp
 * @brief Mach-O 代码签名与动态库注入实现。
 *
 * 本文件是 ipasigner 的核心模块，实现了完整的 Apple CodeSignature 协议：
 * 1. 构建 CodeSignature SuperBlob 的各个 Slot：
 *    - Requirements Slot（签名需求表达式，含 Bundle ID 与证书 CN）
 *    - Entitlements Slot（权限配置 XML）
 *    - DER Entitlements Slot（ASN.1 DER 编码的权限配置）
 *    - CodeDirectory Slot（唯一的 SHA256 主版本，对齐 codesign/zsign）
 *    - CMS Signature Slot（基于 OpenSSL CMS 的数字签名）
 * 2. 组装完整的 __LINKEDIT 段 CodeSignature SuperBlob
 * 3. 解析 Mach-O 文件格式并执行单架构签名（支持自动扩展 __LINKEDIT 空间）
 * 4. Fat Binary 多架构遍历签名
 * 5. 向 Mach-O 注入 LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB 加载命令
 */

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <pugixml.hpp>

#include "Logger.tpp"
#include "ScopeGuard.hpp"
#include "common.hpp"
#include "crypto.hpp"
#include "macho.hpp"
#include "signing.hpp"

namespace com::gitee::ivfzhou::ipasigner {

/**
 * @brief 构建 Requirements Slot（CSSLOT_REQUIREMENTS）。
 *
 * 构建一个 Apple 专有的二进制需求表达式（Requirement Blob），
 * 指定签名证书的 subject.CN 必须与给定值匹配，且应用的标识符为指定 Bundle ID。
 * 当 bundleId 或 subjectCN 为空时，返回一个空的 Requirements Blob。
 *
 * 内部使用 0xfade0c00/0xfade0c01 magic 和 TLV 编码格式，
 * 嵌套表达 identifier "bundleId" and anchor apple generic and
 * certificate leaf[subject.CN] = "subjectCN" and
 * certificate 1[field.1.2.840.113635.100.6.2.1] exists
 *
 * @param bundleId 应用的 Bundle ID 标识符。
 * @param subjectCN 签名证书的主体通用名称（Common Name）。
 * @return 序列化的 Requirements Slot 二进制数据。
 */
static std::string slotBuildRequirements(const std::string_view bundleId, const std::string_view subjectCN) {
    if (bundleId.empty() || subjectCN.empty())
        return std::string("\xfa\xde\x0c\x01\x00\x00\x00\x0c\x00\x00\x00\x00", 12);

    std::string paddedBundleId(bundleId);
    paddedBundleId.append((4 - bundleId.size() % 4) % 4, '\0');
    std::string paddedSubjectCN(subjectCN);
    paddedSubjectCN.append((4 - subjectCN.size() % 4) % 4, '\0');

    std::uint8_t magic1[]{0xfa, 0xde, 0x0c, 0x01};
    std::uint8_t pack1[]{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x14};
    std::uint8_t magic2[]{0xfa, 0xde, 0x0c, 0x00};
    std::uint8_t pack2[]{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x02};
    std::uint8_t pack3[]{0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
                         0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x73, 0x75, 0x62, 0x6a,
                         0x65, 0x63, 0x74, 0x2e, 0x43, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    std::uint8_t pack4[]{0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x2a, 0x86,
                         0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    auto bundleIdLen = static_cast<std::uint32_t>(bundleId.size());
    auto subjectCNLen = static_cast<std::uint32_t>(subjectCN.size());

    std::uint32_t len2 = sizeof(magic2) + 4 + sizeof(pack2) + 4 + paddedBundleId.size() + sizeof(pack3) + 4 +
        paddedSubjectCN.size() + sizeof(pack4);
    std::uint32_t len1 = sizeof(magic1) + 4 + sizeof(pack1) + len2;

    auto bLen1 = Swap(len1);
    auto bLen2 = Swap(len2);
    auto bBundleIdLen = Swap(bundleIdLen);
    auto bSubjectCNLen = Swap(subjectCNLen);

    std::string out{};
    out.reserve(len1);
    out.append(reinterpret_cast<const char*>(magic1), sizeof(magic1));
    out.append(reinterpret_cast<const char*>(&bLen1), 4);
    out.append(reinterpret_cast<const char*>(pack1), sizeof(pack1));
    out.append(reinterpret_cast<const char*>(magic2), sizeof(magic2));
    out.append(reinterpret_cast<const char*>(&bLen2), 4);
    out.append(reinterpret_cast<const char*>(pack2), sizeof(pack2));
    out.append(reinterpret_cast<const char*>(&bBundleIdLen), 4);
    out.append(paddedBundleId);
    out.append(reinterpret_cast<const char*>(pack3), sizeof(pack3));
    out.append(reinterpret_cast<const char*>(&bSubjectCNLen), 4);
    out.append(paddedSubjectCN);
    out.append(reinterpret_cast<const char*>(pack4), sizeof(pack4));
    return out;
}

/**
 * @brief 构建 Entitlements Slot（CSSLOT_ENTITLEMENTS）。
 *
 * 将权限配置 XML 数据包装为 CSMAGIC_EMBEDDED_ENTITLEMENTS Blob 格式，
 * 即在原始 XML 前加上 4 字节 magic + 4 字节大端长度头。
 *
 * @param entitlements 权限配置 XML 字符串，为空时返回空结果。
 * @return 序列化的 Entitlements Slot 二进制数据。
 */
/// 把描述文件里取出的裸 <dict> 片段规范化为完整 XML plist 文档。
/// CSSLOT_ENTITLEMENTS 必须是完整 plist（裸 <dict> 会被 amfid / codesign 解析
/// 拒绝），且 DER 槽要基于同一份内容，否则两个槽语义分叉。
static std::string normalizeEntitlementsPlist(const std::string_view entitlements) {
    if (entitlements.empty()) return {};
    // 二进制 plist 本身已是完整文档，不能按文本 trim。
    if (entitlements.starts_with("bplist")) return std::string(entitlements);
    auto body = StringTrimBlank(entitlements);
    if (body.empty()) return {};
    if (body.find("<plist") != std::string::npos) return body;
    std::string out = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
)";
    out += body;
    out += "\n</plist>\n";
    return out;
}

static std::string slotBuildEntitlements(const std::string_view entitlements) {
    auto plist = normalizeEntitlementsPlist(entitlements);
    if (plist.empty()) return {};
    auto magic = Swap(CSMAGIC_EMBEDDED_ENTITLEMENTS);
    auto length = Swap(static_cast<std::uint32_t>(plist.size() + 8));
    std::string out{};
    out.append(reinterpret_cast<const char*>(&magic), 4);
    out.append(reinterpret_cast<const char*>(&length), 4);
    out.append(plist);
    return out;
}

/**
 * @brief ASN.1 DER 编码写入长度字段。
 *
 * 按照 DER（Distinguished Encoding Rules）规范将长度值编码并追加到 blob 末尾。
 * - 若 len < 128，使用短形式：直接写一字节
 * - 否则使用长形式：首字节为 0x80 | byteCount，后续字节为大端序长度值
 *
 * @param blob 目标字符串，编码结果将被追加到末尾。
 * @param len 待编码的长度值。
 */
static void derLength(std::string& blob, const std::uint64_t len) {
    if (len < 128) {
        blob.append(1, static_cast<char>(len));
    } else {
        int byteCount = 0;
        auto tmp = len;
        while (tmp > 0) {
            ++byteCount;
            tmp >>= 8;
        }
        blob.append(1, static_cast<char>(0x80 | byteCount));
        for (int i = byteCount - 1; i >= 0; --i) blob.append(1, static_cast<char>(len >> (i * 8) & 0xff));
    }
}

/**
 * @brief 递归将 pugixml plist XML 节点转换为 ASN.1 DER 编码。
 *
 * 支持 Apple plist 中的以下数据类型到 ASN.1 类型的映射：
 * - <true/> / <false/> -> BOOLEAN (tag 0x01)
 * - <integer>           -> INTEGER (tag 0x02)
 * - <string>            -> UTF8String (tag 0x0c)
 * - <array>             -> SEQUENCE (tag 0x30)，递归编码子元素
 * - <dict>              -> SET (tag 0x31) of SEQUENCE { UTF8String(key), value }，键值对
 *
 * @param node pugixml XML 节点（plist 的子节点之一）。
 * @return 该节点的 DER 编码二进制字符串。
 */
/// 按 DER TLV 包装：tag + 长度 + 内容。
static std::string derWrap(const std::uint8_t tag, std::string content) {
    std::string out(1, static_cast<char>(tag));
    derLength(out, content.size());
    out += content;
    return out;
}

/// UTF8String。
static std::string derString(const std::string_view text) { return derWrap(0x0c, std::string(text)); }

/// 有符号 INTEGER：按最小补码字节数编码（去掉多余的 0x00 / 0xFF 前导字节）。
static std::string derSignedInt(const std::int64_t value) {
    auto bits = static_cast<std::uint64_t>(value);
    std::uint8_t raw[8]{};
    for (int i = 7; i >= 0; --i) {
        raw[i] = static_cast<std::uint8_t>(bits & 0xff);
        bits >>= 8;
    }
    int start = 0;
    if (value >= 0) {
        while (start < 7 && raw[start] == 0x00 && (raw[start + 1] & 0x80) == 0) ++start;
    } else {
        while (start < 7 && raw[start] == 0xff && (raw[start + 1] & 0x80) != 0) ++start;
    }
    return derWrap(0x02, std::string(reinterpret_cast<const char*>(raw + start), 8 - start));
}

/// 超出 int64 的正整数：最高位为 1 时前置 0x00，保证 DER 解释为无符号正数。
static std::string derUnsignedInt(const std::uint64_t value) {
    std::uint8_t raw[9]{};
    auto bits = value;
    for (int i = 8; i >= 1; --i) {
        raw[i] = static_cast<std::uint8_t>(bits & 0xff);
        bits >>= 8;
    }
    int start = 0;
    while (start < 8 && raw[start] == 0x00 && (raw[start + 1] & 0x80) == 0) ++start;
    return derWrap(0x02, std::string(reinterpret_cast<const char*>(raw + start), 9 - start));
}

/// plist <integer> -> DER INTEGER，兼容十进制、十六进制、负数与 >INT64_MAX 的正整数。
static std::string derInteger(const std::string_view text) {
    auto s = StringTrimBlank(text);
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s.erase(0, 2);
    } else if (!s.empty() && s.front() == '+') {
        s.erase(0, 1);
    }
    if (s.empty()) return derSignedInt(0);
    if (std::int64_t signedValue{}; std::from_chars(s.data(), s.data() + s.size(), signedValue, base).ec == std::errc{})
        return derSignedInt(signedValue);
    if (std::uint64_t unsignedValue{};
        std::from_chars(s.data(), s.data() + s.size(), unsignedValue, base).ec == std::errc{})
        return derUnsignedInt(unsignedValue);
    Logger::warn("invalid entitlements integer:", std::string(text));
    return {};
}

/// plist <data> 的 Base64 解码（忽略空白，遇 '=' 结束）。
static std::string derBase64Decode(const std::string_view text) {
    auto valueOf = [](const char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::string out{};
    std::uint32_t acc{};
    int bits{};
    for (auto c : text) {
        if (c == '=') break;
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        auto v = valueOf(c);
        if (v < 0) return {};
        acc = (acc << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.append(1, static_cast<char>(acc >> bits & 0xff));
        }
    }
    return out;
}

static std::string nodeToDer(const pugi::xml_node& node) {
    const auto name = std::string_view(node.name());
    if (name == PLIST_TAG_TRUE) return derWrap(0x01, std::string(1, '\xff'));
    if (name == PLIST_TAG_FALSE) return derWrap(0x01, std::string(1, '\0'));
    if (name == PLIST_TAG_INTEGER) return derInteger(node.child_value());
    if (name == PLIST_TAG_STRING) return derString(node.child_value());
    if (name == "data") return derWrap(0x04, derBase64Decode(node.child_value()));
    if (name == PLIST_TAG_ARRAY) {
        std::string content{};
        for (auto child = node.first_child(); child; child = child.next_sibling()) {
            if (child.type() != pugi::node_element) continue;
            content += nodeToDer(child);
        }
        return derWrap(0x30, std::move(content));
    }
    if (name == PLIST_TAG_DICT) {
        // codesign / CoreEntitlements 按 key 的 UTF-8 字节序输出字典，
        // Apple Silicon 会用同一规则重算 DER 并与槽内字节比较，顺序不一致会导致安装失败。
        std::vector<std::pair<std::string, std::string>> pairs{};
        for (auto child = node.first_child(); child; child = child.next_sibling()) {
            if (child.type() != pugi::node_element || std::string_view(child.name()) != PLIST_TAG_KEY) continue;
            auto valueNode = child.next_sibling();
            while (valueNode && valueNode.type() != pugi::node_element) valueNode = valueNode.next_sibling();
            if (!valueNode) break;
            auto valueDer = nodeToDer(valueNode);
            if (valueDer.empty()) {
                Logger::warn("unsupported entitlements value for key:", child.child_value());
                continue;
            }
            pairs.emplace_back(std::string(child.child_value()), std::move(valueDer));
        }
        std::sort(pairs.begin(), pairs.end(), [](const auto& a, const auto& b) {
            return std::lexicographical_compare(
                a.first.begin(), a.first.end(), b.first.begin(), b.first.end(), [](const char x, const char y) {
                    return static_cast<unsigned char>(x) < static_cast<unsigned char>(y);
                });
        });
        std::string content{};
        for (auto&& [key, value] : pairs) {
            auto kv = derString(key);
            kv += value;
            content += derWrap(0x30, std::move(kv));
        }
        return derWrap(0x31, std::move(content));
    }
    return {};
}

/**
 * @brief 构建 DER 格式 Entitlements Slot（CSSLOT_DER_ENTITLEMENTS）。
 *
 * 将 plist XML 格式的 Entitlements 解析后，递归转换为 ASN.1 DER 编码，
 * 再包装为 CSMAGIC_EMBEDDED_DER_ENTITLEMENTS Blob 格式。
 * 这是 iOS/macOS 代码签名中的可选 Slot，用于以二进制形式嵌入权限信息。
 *
 * @param entitlements 权限配置 XML 字符串（plist 格式），为空时返回空结果。
 * @return 序列化的 DER Entitlements Slot 二进制数据，解析失败时返回空。
 */
static std::string slotBuildDerEntitlements(const std::string_view entitlements) {
    if (entitlements.empty()) return {};

    // 与 slotBuildEntitlements 共用同一份规范化 plist，保证两个槽语义一致。
    auto xml = normalizeEntitlementsPlist(entitlements);
    if (xml.empty()) return {};
    pugi::xml_document doc{};
    if (!doc.load_string(xml.c_str())) return {};

    // 找到 <plist><dict> 根节点。
    auto dictNode = doc.select_node(std::format("/{}/{}", PLIST_TAG_ROOT, PLIST_TAG_DICT).c_str()).node();
    if (!dictNode) dictNode = doc.select_node(PLIST_TAG_DICT).node();
    if (!dictNode) return {};

    auto rawDer = nodeToDer(dictNode);
    if (rawDer.empty()) return {};

    auto magic = Swap(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS);
    auto length = Swap(static_cast<std::uint32_t>(rawDer.size() + 8));
    std::string out{};
    out.append(reinterpret_cast<const char*>(&magic), 4);
    out.append(reinterpret_cast<const char*>(&length), 4);
    out.append(rawDer);
    return out;
}

/**
 * @brief 构建唯一的主 CodeDirectory Slot（CSSLOT_CODEDIRECTORY，SHA256）。
 *
 * 对齐 zsign / codesign 的 SHA256-only 模式：arm64（M1 及后续芯片）与 iOS 27
 * 内核按页校验签名，主 CD 必须是 SHA256 且不能额外附带 SHA1 的 alternate CD；
 * 否则 cdhashes 集合与实际 CD 集合不一致，设备会拒绝安装。
 *
 * 特殊槽（从 -n 到 -1）：主可执行文件 7 个（DER、空、XML、空、CodeResources、
 * Requirements、Info.plist），framework/dylib 只有 3 个（无 entitlements）。
 *
 * @param execSegBase __TEXT.fileoff，对齐 codesign。
 * @param execSegLimit __TEXT.filesize，对齐 codesign。
 * @param isExecuteArch 是否为主可执行文件架构。
 */
static std::string slotBuildCodeDirectory(const std::uint8_t* codeBase, const std::uint32_t codeLength,
                                          const std::uint64_t execSegBase, const std::uint64_t execSegLimit,
                                          const std::uint64_t execSegFlags, const std::string_view bundleId,
                                          const std::string_view teamId, const std::string_view infoPlistSHA,
                                          const std::string_view requirementsSHA,
                                          const std::string_view codeResourcesSHA,
                                          const std::string_view entitlementsSHA,
                                          const std::string_view derEntitlementsSHA, const bool isExecuteArch) {
    if (!codeBase || codeLength == 0 || bundleId.empty() || teamId.empty()) return {};

    constexpr std::uint32_t version = 0x20400;
    CSCodeDirectory cd{};
    std::memset(&cd, 0, sizeof(cd));
    cd.magic = Swap(CSMAGIC_CODEDIRECTORY);
    cd.version = Swap(version);
    cd.codeLimit = Swap(codeLength);
    cd.hashSize = 32;
    cd.hashType = 2;
    cd.pageSize = 12;
    cd.execSegBase = Swap(execSegBase);
    cd.execSegLimit = Swap(execSegLimit);
    cd.execSegFlags = Swap(execSegFlags);

    std::string emptySHA(cd.hashSize, '\0');
    std::vector<std::string> specialSlots{};
    if (isExecuteArch) {
        specialSlots.push_back(derEntitlementsSHA.size() == cd.hashSize ? std::string(derEntitlementsSHA) : emptySHA);
        specialSlots.push_back(emptySHA);
        specialSlots.push_back(entitlementsSHA.size() == cd.hashSize ? std::string(entitlementsSHA) : emptySHA);
        specialSlots.push_back(emptySHA);
    }
    specialSlots.push_back(codeResourcesSHA.size() == cd.hashSize ? std::string(codeResourcesSHA) : emptySHA);
    specialSlots.push_back(requirementsSHA.size() == cd.hashSize ? std::string(requirementsSHA) : emptySHA);
    specialSlots.push_back(infoPlistSHA.size() == cd.hashSize ? std::string(infoPlistSHA) : emptySHA);

    std::uint32_t pageSize = 1u << cd.pageSize;
    std::uint32_t pages = codeLength / pageSize;
    std::uint32_t remain = codeLength % pageSize;
    std::uint32_t codeSlots = pages + (remain > 0 ? 1 : 0);

    // 计算头部长度（version 0x20400 完整）。
    constexpr std::uint32_t headerLen = 44 + 4 + 4 + 4 + 8 + 8 + 8 + 8; // 88 bytes。
    std::uint32_t bundleIdLen = static_cast<std::uint32_t>(bundleId.size()) + 1;
    std::uint32_t teamIdLen = static_cast<std::uint32_t>(teamId.size()) + 1;
    std::uint32_t specialSlotsLen = static_cast<std::uint32_t>(specialSlots.size()) * cd.hashSize;
    std::uint32_t codeSlotsLen = codeSlots * cd.hashSize;
    std::uint32_t slotLen = headerLen + bundleIdLen + teamIdLen + specialSlotsLen + codeSlotsLen;

    cd.length = Swap(slotLen);
    cd.identOffset = Swap(headerLen);
    cd.nSpecialSlots = Swap(static_cast<std::uint32_t>(specialSlots.size()));
    cd.nCodeSlots = Swap(codeSlots);
    cd.teamOffset = Swap(headerLen + bundleIdLen);
    cd.hashOffset = Swap(headerLen + bundleIdLen + teamIdLen + specialSlotsLen);

    std::string out{};
    out.reserve(slotLen);
    out.append(reinterpret_cast<const char*>(&cd), headerLen);
    out.append(bundleId.data(), bundleId.size());
    out.append(1, '\0');
    out.append(teamId.data(), teamId.size());
    out.append(1, '\0');
    for (auto&& s : specialSlots) out.append(s);
    for (std::uint32_t i{}; i < pages; ++i) out.append(SHARaw(cd.hashType, codeBase + pageSize * i, pageSize));
    if (remain > 0) out.append(SHARaw(cd.hashType, codeBase + pageSize * pages, remain));
    return out;
}

/// 内嵌的 Apple CA 证书（G1~G6 WWDR + 两代 Apple Root）。
/// 新版签名证书可能由 G2/G4/G5/G6 签发，不能无条件写死 G3。
static const char* const kAppleCACertificates[] = {
    CERTIFICATE_APPLE_DEV_CA,    CERTIFICATE_APPLE_DEV_G2_CA, CERTIFICATE_APPLE_DEV_G3_CA, CERTIFICATE_APPLE_DEV_G4_CA,
    CERTIFICATE_APPLE_DEV_G5_CA, CERTIFICATE_APPLE_DEV_G6_CA, CERTIFICATE_APPLE_ROOT_CA,   CERTIFICATE_APPLE_ROOT_G3_CA,
};

static X509* parseAppleCACert(const char* pem) {
    auto bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return nullptr;
    auto* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

/// 按叶子证书的 Issuer 选择 WWDR 中间证书，再按该中间证书的 Issuer 选择根证书。
/// 匹配不到时只嵌入叶子，避免把错误的 G3 写入链里导致 macOS/设备校验失败。
static STACK_OF(X509) * selectAppleCACerts(X509* leaf) {
    auto chain = sk_X509_new_null();
    if (!chain) return nullptr;

    X509* intermediate{};
    for (auto pem : kAppleCACertificates) {
        auto ca = parseAppleCACert(pem);
        if (!ca) continue;
        const bool selfSigned = X509_NAME_cmp(X509_get_subject_name(ca), X509_get_issuer_name(ca)) == 0;
        if (!selfSigned && X509_NAME_cmp(X509_get_subject_name(ca), X509_get_issuer_name(leaf)) == 0) {
            sk_X509_push(chain, ca);
            intermediate = ca;
            break;
        }
        X509_free(ca);
    }
    if (!intermediate) {
        Logger::warn("no matching Apple WWDR intermediate for signing certificate; embedding leaf only");
        return chain;
    }

    for (auto pem : kAppleCACertificates) {
        auto ca = parseAppleCACert(pem);
        if (!ca) continue;
        if (X509_NAME_cmp(X509_get_subject_name(ca), X509_get_issuer_name(intermediate)) == 0) {
            sk_X509_push(chain, ca);
            break;
        }
        X509_free(ca);
    }
    return chain;
}

/**
 * @brief 构建 CMS 签名 Slot（CSSLOT_SIGNATURESLOT）。
 *
 * SHA256-only 模式（对齐 zsign / codesign）：
 * - detached eContent / messageDigest = 主 CodeDirectory（SHA256 版）原始字节；
 * - cdhashes plist（OID 1.2.840.113635.100.9.1）只有 1 条，等于 SHA256(CD) 前 20 字节；
 * - OID 1.2.840.113635.100.9.2 属性 = 完整的 SHA256(CD)（32 字节）；
 * - 证书链按叶子 Issuer 匹配 WWDR，再匹配对应 Apple Root。
 */
static std::optional<std::string> slotBuildCMSSignature(X509* cert, EVP_PKEY* pkey,
                                                        const std::string_view codeDirectorySlot) {
    if (!cert || !pkey || codeDirectorySlot.empty()) return std::nullopt;

    auto cdHashSHA256 = SHARaw(2, codeDirectorySlot.data(), codeDirectorySlot.size());
    if (cdHashSHA256.size() != 32) return std::nullopt;

    // 每个条目对应签名中实际存在的一个 CodeDirectory；SHA256-only 模式只写 1 条。
    std::string cdHashesPlist = std::format(R"++(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>cdhashes</key>
<array><data>{}</data></array>
</dict>
</plist>
)++",
                                            Base64Encode(std::string_view(cdHashSHA256).substr(0, 20)));

    auto otherCerts = selectAppleCACerts(cert);
    if (!otherCerts) return std::nullopt;
    ScopeGuard certsGuard{[&otherCerts] { sk_X509_pop_free(otherCerts, X509_free); }};

    auto in = BIO_new_mem_buf(codeDirectorySlot.data(), static_cast<int>(codeDirectorySlot.size()));
    if (!in) return std::nullopt;
    ScopeGuard inGuard{[&in] { BIO_free(in); }};

    int flags = CMS_PARTIAL | CMS_DETACHED | CMS_NOSMIMECAP | CMS_BINARY;
    auto cms = CMS_sign(nullptr, nullptr, otherCerts, nullptr, flags);
    if (!cms) return std::nullopt;
    ScopeGuard cmsGuard{[&cms] { CMS_ContentInfo_free(cms); }};

    auto si = CMS_add1_signer(cms, cert, pkey, EVP_sha256(), flags);
    if (!si) return std::nullopt;

    // 添加 CDHashes plist 属性 (OID 1.2.840.113635.100.9.1)。
    auto obj1 = OBJ_txt2obj("1.2.840.113635.100.9.1", 1);
    if (!obj1) return std::nullopt;
    ScopeGuard obj1Guard{[&obj1] { ASN1_OBJECT_free(obj1); }};
    CMS_signed_add1_attr_by_OBJ(si, obj1, 0x04, cdHashesPlist.c_str(), static_cast<int>(cdHashesPlist.size()));

    // 添加 CDHash SHA256 属性 (OID 1.2.840.113635.100.9.2)：完整 32 字节。
    std::string sha256Hex{};
    for (auto c : cdHashSHA256) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned char>(c));
        sha256Hex += buf;
    }
    if (auto obj2 = OBJ_txt2obj("1.2.840.113635.100.9.2", 1)) {
        ScopeGuard obj2Guard{[&obj2] { ASN1_OBJECT_free(obj2); }};
        std::string confStr = "asn1=SEQUENCE:A\n[A]\nC=OBJECT:sha256\nB=FORMAT:HEX,OCT:" + sha256Hex + "\n";
        long errline = -1;
        auto ldapbio = BIO_new(BIO_s_mem());
        auto cnf = NCONF_new(nullptr);
        if (ldapbio && cnf) {
            BIO_puts(ldapbio, confStr.c_str());
            NCONF_load_bio(cnf, ldapbio, &errline);
            if (auto genstr = NCONF_get_string(cnf, "default", "asn1")) {
                if (auto type256 = ASN1_generate_nconf(genstr, cnf)) {
                    auto attr = X509_ATTRIBUTE_new();
                    X509_ATTRIBUTE_set1_object(attr, obj2);
                    X509_ATTRIBUTE_set1_data(attr, V_ASN1_SEQUENCE, type256->value.asn1_string->data,
                                             type256->value.asn1_string->length);
                    CMS_signed_add1_attr(si, attr);
                    X509_ATTRIBUTE_free(attr);
                    ASN1_TYPE_free(type256);
                }
            }
        }
        if (ldapbio) BIO_free(ldapbio);
        if (cnf) NCONF_free(cnf);
    }

    if (!CMS_final(cms, in, nullptr, flags)) return std::nullopt;

    auto out = BIO_new(BIO_s_mem());
    if (!out) return std::nullopt;
    ScopeGuard outGuard{[&out] { BIO_free(out); }};
    if (!i2d_CMS_bio(out, cms)) return std::nullopt;

    BUF_MEM* bptr{};
    BIO_get_mem_ptr(out, &bptr);
    if (!bptr) return std::nullopt;

    std::string cmsData(bptr->data, bptr->length);

    // 包装为 BLOBWRAPPER。
    auto blobMagic = Swap(CSMAGIC_BLOBWRAPPER);
    auto blobLen = Swap(static_cast<std::uint32_t>(cmsData.size() + 8));
    std::string result{};
    result.append(reinterpret_cast<const char*>(&blobMagic), 4);
    result.append(reinterpret_cast<const char*>(&blobLen), 4);
    result.append(cmsData);
    return result;
}

/**
 * @brief 组装完整的 CodeSignature SuperBlob（CSMAGIC_EMBEDDED_SIGNATURE）。
 *
 * 按以下顺序构建各 Slot 并组装为 SuperBlob：
 * 1. Requirements Slot（签名需求表达式）
 * 2. Entitlements Slot（权限 XML，仅主可执行文件）
 * 3. DER Entitlements Slot（DER 编码权限，仅主可执行文件）
 * 4. CodeDirectory Slot（唯一的 SHA256 主版本）
 * 5. CMS Signature Slot（数字签名）
 *
 * 主可执行文件恒置 CS_EXECSEG_MAIN_BINARY；CS_EXECSEG_ALLOW_UNSIGNED 只用于
 * 调试签名，不应出现在企业分发签名中。
 *
 * @param execSegBase __TEXT 文件内偏移（fileoff）。
 * @param execSegLimit __TEXT 文件大小（filesize）。
 * @param infoPlistSHA256 Info.plist 的 SHA256 哈希。
 * @param codeResourcesSHA256 CodeResources 的 SHA256 哈希。
 * @return 序列化的完整 SuperBlob 二进制数据。
 */
static std::string buildCodeSignature(X509* cert, EVP_PKEY* pkey, const std::uint8_t* codeBase,
                                      const std::uint32_t codeLength, const std::uint64_t execSegBase,
                                      const std::uint64_t execSegLimit, const bool isExecute,
                                      const std::string_view bundleId, const std::string_view teamId,
                                      const std::string_view subjectCN, const std::string_view entitlements,
                                      const std::string_view infoPlistSHA256,
                                      const std::string_view codeResourcesSHA256) {
    auto reqSlot = slotBuildRequirements(bundleId, subjectCN);

    // framework/dylib 不写 entitlements 槽：空 XML + 无 DER 会在 Apple Silicon /
    // iOS 27 按页校验时被拒。
    auto entSlot = isExecute ? slotBuildEntitlements(entitlements) : std::string{};
    auto derEntSlot = isExecute ? slotBuildDerEntitlements(entitlements) : std::string{};

    auto sha256Of = [](const std::string& data) {
        return data.empty() ? std::string(32, '\0') : SHARaw(2, data.data(), data.size());
    };
    auto reqSHA256 = sha256Of(reqSlot);
    auto entSHA256 = sha256Of(entSlot);
    auto derEntSHA256 = sha256Of(derEntSlot);

    const std::uint64_t execSegFlags = isExecute ? CS_EXECSEG_MAIN_BINARY : 0;

    auto cdSlot =
        slotBuildCodeDirectory(codeBase, codeLength, execSegBase, execSegLimit, execSegFlags, bundleId, teamId,
                               infoPlistSHA256, reqSHA256, codeResourcesSHA256, entSHA256, derEntSHA256, isExecute);
    auto cmsSlotOpt = slotBuildCMSSignature(cert, pkey, cdSlot);
    std::string cmsSlot = cmsSlotOpt ? *cmsSlotOpt : std::string{};

    // 计算 blob 数量和长度。
    std::vector<std::pair<std::uint32_t, std::string*>> blobs{};
    if (!cdSlot.empty()) blobs.push_back({CSSLOT_CODEDIRECTORY, &cdSlot});
    if (!reqSlot.empty()) blobs.push_back({CSSLOT_REQUIREMENTS, &reqSlot});
    if (!entSlot.empty()) blobs.push_back({CSSLOT_ENTITLEMENTS, &entSlot});
    if (!derEntSlot.empty()) blobs.push_back({CSSLOT_DER_ENTITLEMENTS, &derEntSlot});
    if (!cmsSlot.empty()) blobs.push_back({CSSLOT_SIGNATURESLOT, &cmsSlot});

    std::uint32_t headerLen = sizeof(CSSuperBlob) + static_cast<std::uint32_t>(blobs.size()) * sizeof(CSBlobIndex);
    std::uint32_t totalLen = headerLen;
    for (auto& s : blobs | std::views::values) totalLen += static_cast<std::uint32_t>(s->size());

    CSSuperBlob sb{};
    sb.magic = Swap(CSMAGIC_EMBEDDED_SIGNATURE);
    sb.length = Swap(totalLen);
    sb.count = Swap(static_cast<std::uint32_t>(blobs.size()));

    std::string result{};
    result.reserve(totalLen);
    result.append(reinterpret_cast<const char*>(&sb), sizeof(sb));

    std::uint32_t offset = headerLen;
    for (auto&& [type, slot] : blobs) {
        CSBlobIndex bi{};
        bi.type = Swap(type);
        bi.offset = Swap(offset);
        result.append(reinterpret_cast<const char*>(&bi), sizeof(bi));
        offset += static_cast<std::uint32_t>(slot->size());
    }
    for (auto&& s : blobs | std::views::values) result.append(*s);
    return result;
}

/**
 * @brief 解析单个架构的 Mach-O 文件并执行代码签名。
 *
 * 执行流程：
 * 1. 解析 Mach-O 头部，确定 32/64 位、大小端、文件类型
 * 2. 遍历 Load Commands，定位 __TEXT（execSegLimit）、__LINKEDIT、LC_CODE_SIGNATURE
 * 3. 调用 buildCodeSignature() 构建完整的签名数据
 * 4. 若现有空间不足，自动扩展 __LINKEDIT 段并重建签名
 * 5. 将签名数据写入 LC_CODE_SIGNATURE.dataoff 指定的偏移处
 *
 * @param data 整个文件的二进制数据引用（可能因扩展而被修改）。
 * @param archOffset 当前架构在 Fat Binary 或单架构文件中的起始偏移。
 * @param archLength 当前架构的原始长度。
 * @param cert 签名证书。
 * @param pkey 签名私钥。
 * @param bundleId Bundle ID。
 * @param teamId 团队 ID。
 * @param subjectCN 证书主体名称。
 * @param entitlements 权限配置 XML。
 * @param infoPlistSHA256 Info.plist SHA256 哈希。
 * @param codeResourcesData CodeResources 文件内容（用于计算哈希）。
 * @return 成功返回 true，失败返回 false。
 */
static bool signSingleArch(std::string& data, const std::uint32_t archOffset, const std::uint32_t archLength,
                           X509* cert, EVP_PKEY* pkey, const std::string_view bundleId, const std::string_view teamId,
                           const std::string_view subjectCN, const std::string_view entitlements,
                           const std::string_view infoPlistSHA256, const std::string_view codeResourcesData) {
    auto base = reinterpret_cast<std::uint8_t*>(data.data()) + archOffset;
    auto length = archLength;
    auto header = reinterpret_cast<MachHeader*>(base);
    bool is64 = header->magic == MH_MAGIC_64_VAL || header->magic == MH_CIGAM_64_VAL;
    bool bigEndian = header->magic == MH_CIGAM_VAL || header->magic == MH_CIGAM_64_VAL;
    auto BO = [bigEndian](const std::uint32_t v) -> std::uint32_t { return bigEndian ? Swap(v) : v; };
    auto BO64 = [bigEndian](const std::uint64_t v) -> std::uint64_t { return bigEndian ? Swap(v) : v; };
    std::uint32_t headerSize = is64 ? sizeof(MachHeader64) : sizeof(MachHeader);
    bool isExecute = BO(header->filetype) == MH_EXECUTE_VAL;

    if (length < headerSize + sizeof(LoadCommand)) {
        Logger::error("mach-o slice is too small");
        return false;
    }

    // 逐条扫描 load commands。全部用「相对 base 的偏移」记录，因为后续
    // data.insert() 会重新分配缓冲区，裸指针会失效。
    std::uint32_t codeLength = length % 16 == 0 ? length : length + 16 - length % 16;
    std::uint64_t execSegBase{};
    std::uint64_t execSegLimit{};
    std::uint32_t linkEditOff{}; ///< 0 表示没有 __LINKEDIT。
    std::uint32_t csCmdOff{}; ///< 0 表示没有 LC_CODE_SIGNATURE。
    std::uint32_t originalDataSize{};
    std::uint32_t minDataOffset = length; ///< load commands 之后第一段文件数据的偏移。
    bool linkEditIs64 = false;

    auto pLC = base + headerSize;
    for (std::uint32_t i{}; i < BO(header->ncmds); ++i) {
        auto lc = reinterpret_cast<LoadCommand*>(pLC);
        const auto cmd = BO(lc->cmd);
        const auto cmdsize = BO(lc->cmdsize);
        const auto lcOff = static_cast<std::uint32_t>(pLC - base);
        if (cmdsize < sizeof(LoadCommand) || static_cast<std::uint64_t>(lcOff) + cmdsize > length) {
            Logger::error("invalid mach-o load command size");
            return false;
        }
        if (cmd == LC_SEGMENT_VAL || cmd == LC_SEGMENT_64_VAL) {
            const bool segIs64 = cmd == LC_SEGMENT_64_VAL;
            const char* segName{};
            std::uint32_t nsects{};
            std::uint64_t fileoff{};
            if (segIs64) {
                auto seg = reinterpret_cast<SegmentCommand64*>(pLC);
                segName = seg->segname;
                nsects = BO(seg->nsects);
                fileoff = BO64(seg->fileoff);
                if (std::strcmp(segName, "__TEXT") == 0) {
                    execSegBase = fileoff;
                    execSegLimit = BO64(seg->filesize);
                }
            } else {
                auto seg = reinterpret_cast<SegmentCommand*>(pLC);
                segName = seg->segname;
                nsects = BO(seg->nsects);
                fileoff = BO(seg->fileoff);
                if (std::strcmp(segName, "__TEXT") == 0) {
                    execSegBase = fileoff;
                    execSegLimit = BO(seg->filesize);
                }
            }
            if (std::strcmp(segName, "__LINKEDIT") == 0) {
                linkEditOff = lcOff;
                linkEditIs64 = segIs64;
            }
            if (fileoff > 0 && fileoff < minDataOffset) minDataOffset = static_cast<std::uint32_t>(fileoff);
            const std::size_t sectSize = segIs64 ? sizeof(Section64) : sizeof(Section);
            const std::size_t sectBase = segIs64 ? sizeof(SegmentCommand64) : sizeof(SegmentCommand);
            if (sectBase + static_cast<std::uint64_t>(nsects) * sectSize <= cmdsize) {
                for (std::uint32_t j{}; j < nsects; ++j) {
                    auto off = segIs64 ? BO(reinterpret_cast<Section64*>(pLC + sectBase + sectSize * j)->offset)
                                       : BO(reinterpret_cast<Section*>(pLC + sectBase + sectSize * j)->offset);
                    if (off > 0 && off < minDataOffset) minDataOffset = off;
                }
            }
        } else if (cmd == LC_CODE_SIGNATURE_VAL) {
            auto csCmd = reinterpret_cast<CodeSignatureCommand*>(pLC);
            codeLength = BO(csCmd->dataoff);
            originalDataSize = BO(csCmd->datasize);
            csCmdOff = lcOff;
        }
        pLC += cmdsize;
    }

    // 未签名的 Mach-O 没有 LC_CODE_SIGNATURE：在 load commands 尾部的 header
    // padding 中补一条，并同步递增 ncmds/sizeofcmds。
    if (csCmdOff == 0) {
        const auto usedEnd = static_cast<std::uint64_t>(headerSize) + BO(header->sizeofcmds);
        if (usedEnd > length) {
            Logger::error("mach-o load commands exceed slice size");
            return false;
        }
        const auto freeSpace = minDataOffset > usedEnd ? minDataOffset - usedEnd : 0;
        if (freeSpace < sizeof(CodeSignatureCommand)) {
            Logger::error("not enough header padding to add LC_CODE_SIGNATURE");
            return false;
        }
        // 签名起点需 16 字节对齐；补齐的字节必须真实存在，否则首次计算
        // CodeDirectory 哈希时会越界读。新增长度由 SignMachOFile 的 grown 统一
        // 计入 FatArch 的 size/offset 修正。
        if (codeLength > length) {
            data.insert(archOffset + length, codeLength - length, '\0');
            length = codeLength;
            base = reinterpret_cast<std::uint8_t*>(data.data()) + archOffset;
            header = reinterpret_cast<MachHeader*>(base);
        }
        auto cs = reinterpret_cast<CodeSignatureCommand*>(base + usedEnd);
        cs->cmd = BO(LC_CODE_SIGNATURE_VAL);
        cs->cmdsize = BO(static_cast<std::uint32_t>(sizeof(CodeSignatureCommand)));
        cs->dataoff = BO(codeLength);
        cs->datasize = 0;
        csCmdOff = static_cast<std::uint32_t>(reinterpret_cast<std::uint8_t*>(cs) - base);
        header->ncmds = BO(BO(header->ncmds) + 1);
        header->sizeofcmds = BO(BO(header->sizeofcmds) + static_cast<std::uint32_t>(sizeof(CodeSignatureCommand)));
        Logger::debug("added LC_CODE_SIGNATURE load command for unsigned mach-o");
    }

    auto crSHA256 = codeResourcesData.empty() ? std::string(32, '\0')
                                              : SHARaw(2, codeResourcesData.data(), codeResourcesData.size());

    auto blob = buildCodeSignature(cert, pkey, base, codeLength, execSegBase, execSegLimit, isExecute, bundleId, teamId,
                                   subjectCN, entitlements, infoPlistSHA256, crSHA256);
    if (blob.empty()) {
        Logger::error("failed to build CodeSignature");
        return false;
    }

    // 第一次生成的 blob 只用于估算所需空间；最终签名必须在所有 header 修改
    // 完成后重新生成（见下方说明）。
    const auto estimatedSize = static_cast<std::uint32_t>(blob.size());
    std::uint32_t signatureSize = estimatedSize;
    if (static_cast<std::int64_t>(length) - codeLength < static_cast<std::int64_t>(estimatedSize)) {
        Logger::debug("CodeSignature space insufficient, expanding file");
        if (linkEditOff == 0) {
            Logger::error("cannot find __LINKEDIT segment to expand");
            return false;
        }

        auto byteAlign = [](const std::uint32_t v, const std::uint32_t a) -> std::uint32_t { return v + (a - v % a); };
        // SHA256-only：每页只有 32 字节哈希，不再为 SHA1 备用 CD 预留空间。
        std::uint32_t newArchLength = codeLength + byteAlign((codeLength / 4096 + 1) * 32, 4096) + 32768;
        if (newArchLength <= length) newArchLength = codeLength + estimatedSize + 4096;
        std::uint32_t extraBytes = newArchLength - length;

        // 在 slice 末尾追加空间（Fat 后续 slice 由 SignMachOFile 统一平移）。
        data.insert(archOffset + length, extraBytes, '\0');
        base = reinterpret_cast<std::uint8_t*>(data.data()) + archOffset;
        length = newArchLength;

        // 用相对偏移重新定位 __LINKEDIT，扩展其文件/虚拟大小。
        auto linkEdit = base + linkEditOff;
        if (!linkEditIs64) {
            auto seg = reinterpret_cast<SegmentCommand*>(linkEdit);
            seg->vmsize = BO(byteAlign(BO(seg->vmsize) + extraBytes, 4096));
            seg->filesize = BO(BO(seg->filesize) + extraBytes);
        } else {
            auto seg = reinterpret_cast<SegmentCommand64*>(linkEdit);
            auto alignedVm = BO64(seg->vmsize) + extraBytes;
            alignedVm += (4096 - alignedVm % 4096) % 4096;
            seg->vmsize = BO64(alignedVm);
            seg->filesize = BO64(BO64(seg->filesize) + extraBytes);
        }
        signatureSize = newArchLength - codeLength;
    } else {
        // 未扩展时保留原签名区大小，但至少要覆盖本次写入的 blob，
        // 否则重签名后 datasize 可能小于实际签名数据。
        signatureSize = std::min(std::max(originalDataSize, estimatedSize), length - codeLength);
    }

    // 关键：LC_CODE_SIGNATURE 的 dataoff/datasize 位于 load commands 区，属于
    // CodeDirectory 页哈希覆盖范围 [0, codeLimit)。必须在生成最终 CD 之前写完，
    // 否则「签名后再改自身」会让 codesign --verify 报
    // "code or signature have been modified"。
    auto cs = reinterpret_cast<CodeSignatureCommand*>(base + csCmdOff);
    cs->dataoff = BO(codeLength);
    cs->datasize = BO(signatureSize);

    // 所有对 [0, codeLength) 的修改都已完成，用最终文件内容生成签名。
    blob = buildCodeSignature(cert, pkey, base, codeLength, execSegBase, execSegLimit, isExecute, bundleId, teamId,
                              subjectCN, entitlements, infoPlistSHA256, crSHA256);
    if (blob.empty()) {
        Logger::error("failed to rebuild CodeSignature after header update");
        return false;
    }
    if (blob.size() > signatureSize) {
        Logger::error("CodeSignature blob exceeds reserved signature space");
        return false;
    }

    std::memcpy(reinterpret_cast<std::uint8_t*>(data.data()) + archOffset + codeLength, blob.data(), blob.size());
    return true;
}

/**
 * @brief 向单个架构的 Mach-O 注入 dylib 加载命令。
 *
 * 执行流程：
 * 1. 检查是否已存在该 dylib 路径的加载命令，若已存在则根据 weakInject 切换类型或跳过
 * 2. 扫描 __TEXT.__text section 计算 load commands 区域的可用空间
 * 3. 在 load commands 末尾追加 LC_LOAD_DYLIB 或 LC_LOAD_WEAK_DYLIB 命令
 * 4. 更新 Mach-O 头部的 ncmds 和 sizeofcmds 字段
 *
 * @param base 当前架构在内存中的起始指针。
 * @param dylibPath 要注入的 dylib 路径（如 @executable_path/xxx.dylib）。
 * @param weakInject true 使用 LC_LOAD_WEAK_DYLIB（弱引用，找不到不崩溃），false 使用 LC_LOAD_DYLIB。
 * @return 成功返回 true，空间不足或其他错误返回 false。
 */
static bool injectDyLibSingleArch(uint8_t* base, const std::string_view dylibPath, const bool weakInject) {
    auto header = reinterpret_cast<MachHeader*>(base);
    bool is64 = header->magic == MH_MAGIC_64_VAL || header->magic == MH_CIGAM_64_VAL;
    bool bigEndian = header->magic == MH_CIGAM_VAL || header->magic == MH_CIGAM_64_VAL;
    auto BO = [bigEndian](const std::uint32_t v) -> std::uint32_t { return bigEndian ? Swap(v) : v; };
    std::uint32_t headerSize = is64 ? sizeof(MachHeader64) : sizeof(MachHeader);

    // 检查是否已存在该 dylib。
    auto pLC = base + headerSize;
    std::uint32_t freeSpace = 0;
    for (std::uint32_t i{}; i < BO(header->ncmds); ++i) {
        auto lc = reinterpret_cast<LoadCommand*>(pLC);
        auto cmd = BO(lc->cmd);
        if (cmd == LC_LOAD_DYLIB_VAL || cmd == LC_LOAD_WEAK_DYLIB_VAL) {
            auto dlc = reinterpret_cast<DylibCommand*>(pLC);
            if (auto existPath = reinterpret_cast<const char*>(pLC + BO(dlc->dylib.name.offset));
                std::strcmp(existPath, dylibPath.data()) == 0) {
                if (auto wantCmd = weakInject ? LC_LOAD_WEAK_DYLIB_VAL : LC_LOAD_DYLIB_VAL; cmd != wantCmd) {
                    dlc->cmd = BO(wantCmd);
                    Logger::debug("changed dylib load type for:", dylibPath);
                } else {
                    Logger::debug("dylib already exists:", dylibPath);
                }
                return true;
            }
        }
        // 查找 __text section 来确定可用空间。
        if (cmd == LC_SEGMENT_VAL) {
            auto seg = reinterpret_cast<SegmentCommand*>(pLC);
            if (std::strcmp(seg->segname, "__TEXT") == 0) {
                for (std::uint32_t j = 0; j < BO(seg->nsects); ++j) {
                    auto sect = reinterpret_cast<Section*>(pLC + sizeof(SegmentCommand) + sizeof(Section) * j);
                    if (std::strcmp(sect->sectname, "__text") == 0) {
                        if (BO(sect->offset) > BO(header->sizeofcmds) + headerSize)
                            freeSpace = BO(sect->offset) - BO(header->sizeofcmds) - headerSize;
                    }
                }
            }
        } else if (cmd == LC_SEGMENT_64_VAL) {
            auto seg = reinterpret_cast<SegmentCommand64*>(pLC);
            if (std::strcmp(seg->segname, "__TEXT") == 0) {
                for (std::uint32_t j = 0; j < BO(seg->nsects); ++j) {
                    auto sect = reinterpret_cast<Section64*>(pLC + sizeof(SegmentCommand64) + sizeof(Section64) * j);
                    if (std::strcmp(sect->sectname, "__text") == 0) {
                        if (BO(sect->offset) > BO(header->sizeofcmds) + headerSize)
                            freeSpace = BO(sect->offset) - BO(header->sizeofcmds) - headerSize;
                    }
                }
            }
        }
        pLC += BO(lc->cmdsize);
    }

    // 计算 dylib command 所需空间。
    auto pathLen = static_cast<std::uint32_t>(dylibPath.size());
    auto pathPadding = (8 - pathLen % 8) % 8;
    if (pathPadding == 0) pathPadding = 8;
    auto cmdSize = static_cast<std::uint32_t>(sizeof(DylibCommand)) + pathLen + pathPadding;
    if (freeSpace > 0 && freeSpace < cmdSize) {
        Logger::error("not enough free space in load commands for dylib injection");
        return false;
    }

    // 在 load commands 末尾追加新的 dylib command。
    auto dlc = reinterpret_cast<DylibCommand*>(base + headerSize + BO(header->sizeofcmds));
    dlc->cmd = BO(weakInject ? LC_LOAD_WEAK_DYLIB_VAL : LC_LOAD_DYLIB_VAL);
    dlc->cmdsize = BO(cmdSize);
    dlc->dylib.name.offset = BO(sizeof(DylibCommand));
    dlc->dylib.timestamp = BO(2);
    dlc->dylib.current_version = 0;
    dlc->dylib.compatibility_version = 0;

    auto pathDest = reinterpret_cast<std::uint8_t*>(dlc) + sizeof(DylibCommand);
    std::memcpy(pathDest, dylibPath.data(), pathLen);
    std::memset(pathDest + pathLen, 0, pathPadding);

    header->ncmds = BO(BO(header->ncmds) + 1);
    header->sizeofcmds = BO(BO(header->sizeofcmds) + cmdSize);

    return true;
}

/**
 * @brief 对 Mach-O 文件执行代码签名（支持 Fat Binary 多架构）。
 *
 * 读取指定路径的 Mach-O 文件，根据 magic 判断文件类型：
 * - Fat Binary (0xCAFEBABE / 0xBEBAFECA)：遍历每个架构逐一签名
 * - 单架构 32 位 (0xFEEDFACE / 0xCEFAEDFE)：直接签名
 * - 单架构 64 位 (0xFEEDFACF / 0xCFFAEDFE)：直接签名
 *
 * 签名完成后写回原文件。
 *
 * @param filePath 待签名的 Mach-O 文件路径。
 * @param cert 签名用的 X509 证书。
 * @param pkey 签名用的私钥。
 * @param bundleId 应用的 Bundle ID 标识符。
 * @param teamId 团队标识符。
 * @param subjectCN 签名证书的主体通用名称。
 * @param entitlements 权限配置 XML 内容。
 * @param infoPlistSHA1 Info.plist 的 SHA1 原始哈希（20 字节）。
 * @param infoPlistSHA256 Info.plist 的 SHA256 原始哈希（32 字节）。
 * @param codeResourcesData CodeResources plist 文件的原始内容（用于计算资源哈希）。
 * @return 成功返回 true，失败返回 false。
 */
bool SignMachOFile(const std::filesystem::path& filePath, X509* cert, EVP_PKEY* pkey, const std::string_view bundleId,
                   const std::string_view teamId, const std::string_view subjectCN, const std::string_view entitlements,
                   [[maybe_unused]] const std::string_view infoPlistSHA1, const std::string_view infoPlistSHA256,
                   const std::string_view codeResourcesData) {
    // 读取整个文件到内存。
    auto dataOpt = ReadFile(filePath);
    if (!dataOpt) {
        Logger::error("failed to read mach-o file:", filePath.string());
        return false;
    }
    auto& data = *dataOpt;
    auto base = reinterpret_cast<std::uint8_t*>(data.data());
    auto fileSize = static_cast<std::uint32_t>(data.size());
    auto magic = *reinterpret_cast<std::uint32_t*>(base);

    // 当调用方未提供 bundleId 时（如签名独立 dylib），使用文件名作为默认标识。
    // 这与 zsign 行为一致：basename(filePath) 作为 CodeDirectory 的 identifier。
    std::string fallbackBundleId{};
    std::string_view effectiveBundleId = bundleId;
    if (effectiveBundleId.empty()) {
        fallbackBundleId = filePath.filename().string();
        effectiveBundleId = fallbackBundleId;
    }

    bool ok{};
    if (magic == FAT_MAGIC_VAL || magic == FAT_CIGAM_VAL) {
        // 以宿主字节序读到的 magic 为 FAT_MAGIC_VAL 时字段是宿主序，
        // 否则（标准 fat 头在小端机上读作 FAT_CIGAM_VAL）字段为大端，需要 Swap。
        const bool fatNeedsSwap = magic != FAT_MAGIC_VAL;
        auto fatBO = [fatNeedsSwap](const std::uint32_t v) { return fatNeedsSwap ? Swap(v) : v; };
        auto nArch = fatBO(reinterpret_cast<FatHeader*>(base)->nfat_arch);
        for (std::uint32_t i{}; i < nArch; ++i) {
            auto arch = reinterpret_cast<FatArch*>(base + sizeof(FatHeader) + sizeof(FatArch) * i);
            auto archOffset = fatBO(arch->offset);
            auto archSize = fatBO(arch->size);
            auto sizeBefore = data.size();
            if (!signSingleArch(data, archOffset, archSize, cert, pkey, effectiveBundleId, teamId, subjectCN,
                                entitlements, infoPlistSHA256, codeResourcesData))
                return false;
            // 重新获取 base（data 可能因扩展而重新分配）。
            base = reinterpret_cast<std::uint8_t*>(data.data());
            // 某个 slice 扩展后必须同步修正 FatArch 表：当前 slice 变大，
            // 后续 slice 整体后移，否则后续架构会解析到错误位置。
            if (auto grown = static_cast<std::uint32_t>(data.size() - sizeBefore); grown > 0) {
                for (std::uint32_t j{}; j < nArch; ++j) {
                    auto cur = reinterpret_cast<FatArch*>(base + sizeof(FatHeader) + sizeof(FatArch) * j);
                    auto off = fatBO(cur->offset);
                    auto sz = fatBO(cur->size);
                    if (j == i)
                        sz += grown;
                    else if (j > i)
                        off += grown;
                    cur->offset = fatBO(off);
                    cur->size = fatBO(sz);
                }
            }
        }
        ok = true;
    } else if (magic == MH_MAGIC_VAL || magic == MH_CIGAM_VAL || magic == MH_MAGIC_64_VAL || magic == MH_CIGAM_64_VAL) {
        ok = signSingleArch(data, 0, fileSize, cert, pkey, effectiveBundleId, teamId, subjectCN, entitlements,
                            infoPlistSHA256, codeResourcesData);
    } else {
        Logger::error("invalid mach-o file magic:", std::to_string(magic));
        return false;
    }

    if (ok) {
        if (!WriteFile(filePath, data)) {
            Logger::error("failed to write signed mach-o file:", filePath.string());
            return false;
        }
    }
    return ok;
}


/**
 * @brief 向 Mach-O 文件注入动态库加载命令（支持 Fat Binary 多架构）。
 *
 * 读取指定路径的 Mach-O 文件，根据 magic 判断文件类型后，
 * 对每个架构调用 injectDyLibSingleArch() 执行实际的加载命令注入。
 * 注入完成后写回原文件。
 *
 * @param filePath 待修改的 Mach-O 文件路径。
 * @param dylibPath 要注入的 dylib 加载路径（如 @executable_path/xxx.dylib）。
 * @param weakInject true 使用 LC_LOAD_WEAK_DYLIB（弱引用），false 使用 LC_LOAD_DYLIB（强引用）。
 * @return 成功返回 true，失败返回 false。
 */
bool InjectDyLib(const std::filesystem::path& filePath, const std::string_view dylibPath, const bool weakInject) {
    auto dataOpt = ReadFile(filePath);
    if (!dataOpt) {
        Logger::error("failed to read mach-o file for dylib injection:", filePath.string());
        return false;
    }
    auto& data = *dataOpt;
    auto base = reinterpret_cast<std::uint8_t*>(data.data());
    auto magic = *reinterpret_cast<std::uint32_t*>(base);

    bool ok = false;
    if (magic == FAT_MAGIC_VAL || magic == FAT_CIGAM_VAL) {
        const bool fatNeedsSwap = magic != FAT_MAGIC_VAL;
        auto fatBO = [fatNeedsSwap](const std::uint32_t v) { return fatNeedsSwap ? Swap(v) : v; };
        auto nArch = fatBO(reinterpret_cast<FatHeader*>(base)->nfat_arch);
        for (std::uint32_t i{}; i < nArch; ++i) {
            auto arch = reinterpret_cast<FatArch*>(base + sizeof(FatHeader) + sizeof(FatArch) * i);
            if (auto archOffset = fatBO(arch->offset); !injectDyLibSingleArch(base + archOffset, dylibPath, weakInject))
                return false;
        }
        ok = true;
    } else if (magic == MH_MAGIC_VAL || magic == MH_CIGAM_VAL || magic == MH_MAGIC_64_VAL || magic == MH_CIGAM_64_VAL) {
        ok = injectDyLibSingleArch(base, dylibPath, weakInject);
    } else {
        Logger::error("invalid mach-o file for dylib injection, magic:", std::to_string(magic));
        return false;
    }

    if (ok) {
        if (!WriteFile(filePath, data)) {
            Logger::error("failed to write mach-o file after dylib injection:", filePath.string());
            return false;
        }
    }
    return ok;
}

}
