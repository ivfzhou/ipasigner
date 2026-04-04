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
 *    - CodeDirectory Slot（代码哈希目录，支持 SHA1/SHA256 双版本）
 *    - CMS Signature Slot（基于 OpenSSL CMS 的数字签名）
 * 2. 组装完整的 __LINKEDIT 段 CodeSignature SuperBlob
 * 3. 解析 Mach-O 文件格式并执行单架构签名（支持自动扩展 __LINKEDIT 空间）
 * 4. Fat Binary 多架构遍历签名
 * 5. 向 Mach-O 注入 LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB 加载命令
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
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

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 构建 Requirements Slot（CSSLOT_REQUIREMENTS）。
 *
 * 构建一个 Apple 专有的二进制需求表达式（Requirement Blob），
 * 指定签名证书的 subject.CN 必须与给定值匹配，且应用的标识符为指定 Bundle ID。
 * 当 bundleId 或 subjectCN 为空时，返回一个空的 Requirements Blob。
 *
 * 内部使用 0xfade0c00/0xfade0c01 magic 和 TLV 编码格式，
 * 嵌套表达 identifier "bundleId" and anchor apple generic and
 * (certificate leaf["subject.CN"] = "subjectCN") or certificate 1[field.1.2.840.113635.100.6.1.17]
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
static std::string slotBuildEntitlements(const std::string_view entitlements) {
    if (entitlements.empty()) return {};
    auto magic = Swap(CSMAGIC_EMBEDDED_ENTITLEMENTS);
    auto length = Swap(static_cast<std::uint32_t>(entitlements.size() + 8));
    std::string out{};
    out.append(reinterpret_cast<const char*>(&magic), 4);
    out.append(reinterpret_cast<const char*>(&length), 4);
    out.append(entitlements);
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
static std::string nodeToDer(const pugi::xml_node& node) {
    std::string out{};

    if (auto name = std::string_view(node.name()); name == PLIST_TAG_TRUE || name == PLIST_TAG_FALSE) {
        out.append(1, '\x01'); // BOOLEAN tag。
        out.append(1, '\x01'); // length 1。
        out.append(1, name == PLIST_TAG_TRUE ? '\x01' : '\x00');
    } else if (name == PLIST_TAG_INTEGER) {
        auto text = std::string_view(node.child_value());
        std::uint64_t val{};
        for (auto&& c : text) {
            if (c >= '0' && c <= '9') val = val * 10 + (c - '0');
        }
        out.append(1, '\x02'); // INTEGER tag。
        // 计算需要的字节数。
        int byteCount = 0;
        if (val == 0) {
            byteCount = 1;
        } else {
            auto tmp = val;
            while (tmp > 0) {
                ++byteCount;
                tmp >>= 8;
            }
        }
        derLength(out, byteCount);
        if (val == 0) {
            out.append(1, '\x00');
        } else {
            for (int i = byteCount - 1; i >= 0; --i) out.append(1, static_cast<char>(val >> (i * 8) & 0xff));
        }
    } else if (name == PLIST_TAG_STRING) {
        auto text = std::string(node.child_value());
        out.append(1, '\x0c'); // UTF8String tag。
        derLength(out, text.size());
        out += text;
    } else if (name == PLIST_TAG_ARRAY) {
        std::string arrContent{};
        for (auto child = node.first_child(); child; child = child.next_sibling()) arrContent += nodeToDer(child);
        out.append(1, '\x30'); // SEQUENCE tag。
        derLength(out, arrContent.size());
        out += arrContent;
    } else if (name == PLIST_TAG_DICT) {
        std::string dictContent{};
        for (auto&& it = node.begin(); it != node.end(); ++it) {
            if (std::string_view(it->name()) != PLIST_TAG_KEY) continue;
            auto keyText = std::string(it->child_value());
            auto valNode = it->next_sibling();
            if (!valNode) break;
            ++it;
            auto valDer = nodeToDer(valNode);

            // 每个键值对是一个 SEQUENCE { UTF8String(key), value }。
            std::string kvContent{};
            kvContent.append(1, '\x0c'); // UTF8String tag for key。
            derLength(kvContent, keyText.size());
            kvContent += keyText;
            kvContent += valDer;

            dictContent.append(1, '\x30'); // SEQUENCE tag。
            derLength(dictContent, kvContent.size());
            dictContent += kvContent;
        }
        out.append(1, '\x31'); // SET tag。
        derLength(out, dictContent.size());
        out += dictContent;
    }
    return out;
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

    // 解析 plist XML。
    pugi::xml_document doc{};
    if (!doc.load_string(entitlements.data())) return {};

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
 * @brief 构建 CodeDirectory Slot（CSSLOT_CODEDIRECTORY / CSSLOT_ALTERNATE_CODEDIRECTORIES）。
 *
 * 构建完整的 CodeDirectory Blob，这是 Apple 代码签名的核心数据结构。
 * 按照版本 0x20400 格式组织，包含：
 * - 头部固定字段（magic, version, codeLimit, hashType, pageSize 等）
 * - 可执行段限制与标志（execSegLimit, execSegFlags）
 * - 特殊 Slot 哈希（DER Entitlements、Entitlements、CodeResources、Requirements、Info.plist）
 * - Bundle ID 和 Team ID 标识符
 * - 代码页哈希（按 pageSize 分页，每页计算 SHA1 或 SHA256）
 *
 * @param bAlternate true 构建 SHA256 版本（Alternate），false 构建 SHA1 主版本。
 * @param codeBase 代码区起始指针（Mach-O 文件在内存中的基地址）。
 * @param codeLength 代码区长度（需签名的字节数）。
 * @param execSegLimit 可执行段的内存上限（__TEXT.vmsize）。
 * @param execSegFlags 可执行段标志位（如 CS_EXECSEG_MAIN_BINARY）。
 * @param bundleId 应用的 Bundle ID 标识符。
 * @param teamId 团队标识符（Team ID）。
 * @param infoPlistSHA Info.plist 的 SHA 哈希值（主/备版本对应长度）。
 * @param requirementsSHA Requirements Slot 的 SHA 哈希值。
 * @param codeResourcesSHA CodeResources 的 SHA 哈希值。
 * @param entitlementsSHA Entitlements Slot 的 SHA 哈希值。
 * @param derEntitlementsSHA DER Entitlements Slot 的 SHA 哈希值。
 * @param isExecuteArch 是否为主可执行文件架构（影响特殊 Slot 排列顺序）。
 * @return 序列化的 CodeDirectory Slot 二进制数据，参数无效时返回空。
 */
static std::string slotBuildCodeDirectory(const bool bAlternate, const std::uint8_t* codeBase,
                                          const std::uint32_t codeLength, const std::uint64_t execSegLimit,
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
    cd.hashSize = bAlternate ? 32 : 20;
    cd.hashType = bAlternate ? 2 : 1;
    cd.pageSize = 12;
    cd.execSegLimit = Swap(execSegLimit);
    cd.execSegFlags = Swap(execSegFlags);

    std::string emptySHA(cd.hashSize, '\0');
    std::vector<std::string> specialSlots{};
    if (isExecuteArch) {
        specialSlots.push_back(derEntitlementsSHA.empty() ? emptySHA : std::string(derEntitlementsSHA));
        specialSlots.push_back(emptySHA);
    }
    specialSlots.push_back(entitlementsSHA.empty() ? emptySHA : std::string(entitlementsSHA));
    specialSlots.push_back(emptySHA);
    specialSlots.push_back(codeResourcesSHA.empty() ? emptySHA : std::string(codeResourcesSHA));
    specialSlots.push_back(requirementsSHA.empty() ? emptySHA : std::string(requirementsSHA));
    specialSlots.push_back(infoPlistSHA.empty() ? emptySHA : std::string(infoPlistSHA));

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

/**
 * @brief 构建 CMS 签名 Slot（CSSLOT_SIGNATURESLOT）。
 *
 * 使用 OpenSSL CMS API 生成 PKCS#7 detached 签名，签名内容包括：
 * - SHA1 CodeDirectory 哈希（作为 CDHashes plist 属性，OID 1.2.840.113635.100.9.1）
 * - SHA256 CodeDirectory 哈希（作为 ASN.1 SEQUENCE 属性，OID 1.2.840.113635.100.9.2）
 * - Apple WWDR CA G3 和 Apple Root CA 作为证书链
 *
 * 最终结果包装为 CSMAGIC_BLOBWRAPPER 格式。
 *
 * @param cert 用于签名的 X509 证书。
 * @param pkey 对应的私钥。
 * @param codeDirectorySlot 主 CodeDirectory Slot 数据。
 * @param alternateCodeDirectorySlot 备用（SHA256）CodeDirectory Slot 数据。
 * @return 成功返回 CMS 签名的 BlobWrapper 数据，失败返回 std::nullopt。
 */
static std::optional<std::string> slotBuildCMSSignature(X509* cert, EVP_PKEY* pkey,
                                                        const std::string_view codeDirectorySlot,
                                                        const std::string_view alternateCodeDirectorySlot) {
    if (!cert || !pkey) return std::nullopt;

    // 计算 CodeDirectory 的 SHA1 和 SHA256。
    auto cdSHA1 = SHARaw(1, codeDirectorySlot.data(), codeDirectorySlot.size());
    auto altCdSHA256 = SHARaw(2, alternateCodeDirectorySlot.data(), alternateCodeDirectorySlot.size());

    // 构建 CDHashes plist（截断到 20 字节）。
    std::string cdHashesPlist =
        std::format(R"++(<?xml version="1.0" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>cdhashes</key>
<array><data>{}</data><data>{}</data></array>
</dict>
</plist>
)++",
                    Base64Encode(cdSHA1.substr(0, 20)), Base64Encode(altCdSHA256.substr(0, 20)));

    // 加载 Apple CA 证书链。
    auto bother1 = BIO_new_mem_buf(CERTIFICATE_APPLE_DEV_G3_CA, -1);
    auto bother2 = BIO_new_mem_buf(CERTIFICATE_APPLE_ROOT_CA, -1);
    if (!bother1 || !bother2) return std::nullopt;
    ScopeGuard bioGuard{[&] {
        BIO_free(bother1);
        BIO_free(bother2);
    }};

    auto ocert1 = PEM_read_bio_X509(bother1, nullptr, nullptr, nullptr);
    auto ocert2 = PEM_read_bio_X509(bother2, nullptr, nullptr, nullptr);
    if (!ocert1 || !ocert2) return std::nullopt;

    auto otherCerts = sk_X509_new_null();
    sk_X509_push(otherCerts, ocert1);
    sk_X509_push(otherCerts, ocert2);

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
    CMS_signed_add1_attr_by_OBJ(si, obj1, 0x04, cdHashesPlist.c_str(), static_cast<int>(cdHashesPlist.size()));

    // 添加 CDHashes SHA256 属性 (OID 1.2.840.113635.100.9.2)。
    std::string sha256Hex{};
    for (auto c : altCdSHA256) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned char>(c));
        sha256Hex += buf;
    }
    if (auto obj2 = OBJ_txt2obj("1.2.840.113635.100.9.2", 1)) {
        std::string confStr = "asn1=SEQUENCE:A\n[A]\nC=OBJECT:sha256\nB=FORMAT:HEX,OCT:" + sha256Hex + "\n";
        long errline = -1;
        auto ldapbio = BIO_new(BIO_s_mem());
        auto cnf = NCONF_new(nullptr);
        BIO_puts(ldapbio, confStr.c_str());
        NCONF_load_bio(cnf, ldapbio, &errline);
        BIO_free(ldapbio);
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
        NCONF_free(cnf);
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
 * 4. CodeDirectory Slot（SHA1 版本）
 * 5. Alternate CodeDirectory Slot（SHA256 版本）
 * 6. CMS Signature Slot（数字签名）
 *
 * 根据 Entitlements 中是否包含 get-task-allow 自动设置 execSegFlags。
 *
 * @param cert 用于签名的 X509 证书。
 * @param pkey 对应的私钥。
 * @param codeBase 代码区起始指针。
 * @param codeLength 代码区长度。
 * @param execSegLimit 可执行段内存上限。
 * @param isExecute 是否为主可执行文件（决定是否嵌入完整 Entitlements）。
 * @param bundleId Bundle ID 标识符。
 * @param teamId 团队标识符。
 * @param subjectCN 证书主体通用名称（用于 Requirements 表达式）。
 * @param entitlements 权限配置 XML 字符串。
 * @param infoPlistSHA1 Info.plist 的 SHA1 哈希。
 * @param infoPlistSHA256 Info.plist 的 SHA256 哈希。
 * @param codeResourcesSHA1 CodeResources 的 SHA1 哈希。
 * @param codeResourcesSHA256 CodeResources 的 SHA256 哈希。
 * @return 序列化的完整 SuperBlob 二进制数据。
 */
static std::string buildCodeSignature(X509* cert, EVP_PKEY* pkey, const std::uint8_t* codeBase,
                                      const std::uint32_t codeLength, const std::uint64_t execSegLimit,
                                      const bool isExecute, const std::string_view bundleId,
                                      const std::string_view teamId, const std::string_view subjectCN,
                                      const std::string_view entitlements, const std::string_view infoPlistSHA1,
                                      const std::string_view infoPlistSHA256, const std::string_view codeResourcesSHA1,
                                      const std::string_view codeResourcesSHA256) {
    std::string emptyEntitlements = R"++(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict/></plist>)++";

    auto reqSlot = slotBuildRequirements(bundleId, subjectCN);
    auto entSlot = slotBuildEntitlements(isExecute ? entitlements : std::string_view(emptyEntitlements));
    auto derEntSlot = slotBuildDerEntitlements(isExecute ? entitlements : std::string_view{});

    auto [reqSHA1, reqSHA256] =
        reqSlot.empty() ? std::pair(std::string(20, '\0'), std::string(32, '\0')) : SHASumRaw(reqSlot);
    auto [entSHA1, entSHA256] =
        entSlot.empty() ? std::pair(std::string(20, '\0'), std::string(32, '\0')) : SHASumRaw(entSlot);
    auto [derEntSHA1, derEntSHA256] =
        derEntSlot.empty() ? std::pair(std::string(20, '\0'), std::string(32, '\0')) : SHASumRaw(derEntSlot);

    std::uint64_t execSegFlags{};
    if (!entSlot.empty() && entSlot.size() > 8) {
        if (std::string_view entData(entSlot.data() + 8, entSlot.size() - 8);
            entData.find("<key>get-task-allow</key>") != std::string_view::npos)
            execSegFlags = CS_EXECSEG_MAIN_BINARY | CS_EXECSEG_ALLOW_UNSIGNED;
    }

    auto cdSlot = slotBuildCodeDirectory(false, codeBase, codeLength, execSegLimit, execSegFlags, bundleId, teamId,
                                         infoPlistSHA1, reqSHA1, codeResourcesSHA1, entSHA1, derEntSHA1, isExecute);
    auto altCdSlot =
        slotBuildCodeDirectory(true, codeBase, codeLength, execSegLimit, execSegFlags, bundleId, teamId,
                               infoPlistSHA256, reqSHA256, codeResourcesSHA256, entSHA256, derEntSHA256, isExecute);
    auto cmsSlotOpt = slotBuildCMSSignature(cert, pkey, cdSlot, altCdSlot);
    std::string cmsSlot = cmsSlotOpt ? *cmsSlotOpt : std::string{};

    // 计算 blob 数量和长度。
    std::vector<std::pair<std::uint32_t, std::string*>> blobs{};
    if (!cdSlot.empty()) blobs.push_back({CSSLOT_CODEDIRECTORY, &cdSlot});
    if (!reqSlot.empty()) blobs.push_back({CSSLOT_REQUIREMENTS, &reqSlot});
    if (!entSlot.empty()) blobs.push_back({CSSLOT_ENTITLEMENTS, &entSlot});
    if (!derEntSlot.empty()) blobs.push_back({CSSLOT_DER_ENTITLEMENTS, &derEntSlot});
    if (!altCdSlot.empty()) blobs.push_back({CSSLOT_ALTERNATE_CODEDIRECTORIES, &altCdSlot});
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
 * @param infoPlistSHA1 Info.plist SHA1 哈希。
 * @param infoPlistSHA256 Info.plist SHA256 哈希。
 * @param codeResourcesData CodeResources 文件内容（用于计算哈希）。
 * @return 成功返回 true，失败返回 false。
 */
static bool signSingleArch(std::string& data, const std::uint32_t archOffset, const std::uint32_t archLength,
                           X509* cert, EVP_PKEY* pkey, const std::string_view bundleId, const std::string_view teamId,
                           const std::string_view subjectCN, const std::string_view entitlements,
                           const std::string_view infoPlistSHA1, const std::string_view infoPlistSHA256,
                           const std::string_view codeResourcesData) {
    auto base = reinterpret_cast<std::uint8_t*>(data.data()) + archOffset;
    auto length = archLength;
    auto header = reinterpret_cast<MachHeader*>(base);
    bool is64 = header->magic == MH_MAGIC_64_VAL || header->magic == MH_CIGAM_64_VAL;
    bool bigEndian = header->magic == MH_CIGAM_VAL || header->magic == MH_CIGAM_64_VAL;
    auto BO = [bigEndian](const std::uint32_t v) -> std::uint32_t { return bigEndian ? Swap(v) : v; };
    std::uint32_t headerSize = is64 ? sizeof(MachHeader64) : sizeof(MachHeader);
    bool isExecute = BO(header->filetype) == MH_EXECUTE_VAL;

    std::uint32_t codeLength = length % 16 == 0 ? length : length + 16 - length % 16;
    std::uint8_t* signBase{};
    std::uint64_t execSegLimit{};
    std::uint8_t* linkEditSeg{};

    auto pLC = base + headerSize;
    for (std::uint32_t i{}; i < BO(header->ncmds); ++i) {
        auto lc = reinterpret_cast<LoadCommand*>(pLC);
        if (auto cmd = BO(lc->cmd); cmd == LC_SEGMENT_VAL) {
            auto seg = reinterpret_cast<SegmentCommand*>(pLC);
            if (std::strcmp(seg->segname, "__TEXT") == 0) execSegLimit = seg->vmsize;
            if (std::strcmp(seg->segname, "__LINKEDIT") == 0) linkEditSeg = pLC;
        } else if (cmd == LC_SEGMENT_64_VAL) {
            auto seg = reinterpret_cast<SegmentCommand64*>(pLC);
            if (std::strcmp(seg->segname, "__TEXT") == 0) execSegLimit = seg->vmsize;
            if (std::strcmp(seg->segname, "__LINKEDIT") == 0) linkEditSeg = pLC;
        } else if (cmd == LC_CODE_SIGNATURE_VAL) {
            auto csCmd = reinterpret_cast<CodeSignatureCommand*>(pLC);
            codeLength = BO(csCmd->dataoff);
            signBase = base + codeLength;
        }
        pLC += BO(lc->cmdsize);
    }

    if (!signBase) {
        Logger::error("no CodeSignature segment found, file is not signed");
        return false;
    }

    auto [crSHA1, crSHA256] = codeResourcesData.empty() ? std::pair(std::string(20, '\0'), std::string(32, '\0'))
                                                        : SHASumRaw(codeResourcesData);

    auto blob = buildCodeSignature(cert, pkey, base, codeLength, execSegLimit, isExecute, bundleId, teamId, subjectCN,
                                   entitlements, infoPlistSHA1, infoPlistSHA256, crSHA1, crSHA256);
    if (blob.empty()) {
        Logger::error("failed to build CodeSignature");
        return false;
    }

    // 空间不足：扩展 __LINKEDIT 并重建文件。
    if (static_cast<std::int64_t>(length) - codeLength < static_cast<std::int64_t>(blob.size())) {
        Logger::warn("CodeSignature space insufficient, expanding file");
        if (!linkEditSeg) {
            Logger::error("cannot find __LINKEDIT segment to expand");
            return false;
        }

        auto byteAlign = [](const std::uint32_t v, const std::uint32_t a) -> std::uint32_t { return v + (a - v % a); };
        std::uint32_t newArchLength = codeLength + byteAlign((codeLength / 4096 + 1) * (20 + 32), 4096) + 32768;
        if (newArchLength <= length) newArchLength = codeLength + static_cast<std::uint32_t>(blob.size()) + 4096;
        std::uint32_t extraBytes = newArchLength - length;

        // 扩展 __LINKEDIT 段。
        // 重新获取指针（base 可能因 data 重新分配失效）。
        auto lcCmd = BO(reinterpret_cast<LoadCommand*>(linkEditSeg)->cmd);
        auto linkEditOff = static_cast<std::uint32_t>(linkEditSeg - base);

        // 在文件末尾追加空间。
        auto insertPos = archOffset + length;
        data.insert(insertPos, extraBytes, '\0');
        // 重新获取 base。
        base = reinterpret_cast<std::uint8_t*>(data.data()) + archOffset;

        // 更新 __LINKEDIT 段大小。
        auto linkEdit = base + linkEditOff;
        if (lcCmd == LC_SEGMENT_VAL) {
            auto seg = reinterpret_cast<SegmentCommand*>(linkEdit);
            seg->vmsize = BO(byteAlign(BO(seg->vmsize) + extraBytes, 4096));
            seg->filesize = BO(BO(seg->filesize) + extraBytes);
        } else {
            auto seg = reinterpret_cast<SegmentCommand64*>(linkEdit);
            auto oldVm = BO(seg->vmsize);
            seg->vmsize = BO(byteAlign(oldVm + extraBytes, 4096));
            seg->filesize = BO(BO(seg->filesize) + static_cast<std::uint64_t>(extraBytes));
        }

        // 更新 LC_CODE_SIGNATURE 的 datasize。
        pLC = base + headerSize;
        for (std::uint32_t i = 0; i < BO(reinterpret_cast<MachHeader*>(base)->ncmds); ++i) {
            auto lc = reinterpret_cast<LoadCommand*>(pLC);
            if (BO(lc->cmd) == LC_CODE_SIGNATURE_VAL) {
                auto cs = reinterpret_cast<CodeSignatureCommand*>(pLC);
                cs->datasize = BO(newArchLength - codeLength);
                break;
            }
            pLC += BO(lc->cmdsize);
        }

        // 重新构建签名（因为代码区数据变了需要重新计算哈希）。
        blob = buildCodeSignature(cert, pkey, base, codeLength, execSegLimit, isExecute, bundleId, teamId, subjectCN,
                                  entitlements, infoPlistSHA1, infoPlistSHA256, crSHA1, crSHA256);
        if (blob.empty()) {
            Logger::error("failed to rebuild CodeSignature after expansion");
            return false;
        }
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
                    Logger::info("changed dylib load type for:", dylibPath);
                } else {
                    Logger::warn("dylib already exists:", dylibPath);
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
                   const std::string_view infoPlistSHA1, const std::string_view infoPlistSHA256,
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

    bool ok{};
    if (magic == FAT_MAGIC_VAL || magic == FAT_CIGAM_VAL) {
        auto fatHeader = reinterpret_cast<FatHeader*>(base);
        auto nArch = magic == FAT_MAGIC_VAL ? fatHeader->nfat_arch : Swap(fatHeader->nfat_arch);
        for (std::uint32_t i{}; i < nArch; ++i) {
            auto arch = reinterpret_cast<FatArch*>(base + sizeof(FatHeader) + sizeof(FatArch) * i);
            auto archOffset = magic == FAT_MAGIC_VAL ? arch->offset : Swap(arch->offset);
            if (auto archSize = magic == FAT_MAGIC_VAL ? arch->size : Swap(arch->size);
                !signSingleArch(data, archOffset, archSize, cert, pkey, bundleId, teamId, subjectCN, entitlements,
                                infoPlistSHA1, infoPlistSHA256, codeResourcesData))
                return false;
            // 重新获取 base（data 可能因扩展而重新分配）。
            base = reinterpret_cast<std::uint8_t*>(data.data());
        }
        ok = true;
    } else if (magic == MH_MAGIC_VAL || magic == MH_CIGAM_VAL || magic == MH_MAGIC_64_VAL || magic == MH_CIGAM_64_VAL) {
        ok = signSingleArch(data, 0, fileSize, cert, pkey, bundleId, teamId, subjectCN, entitlements, infoPlistSHA1,
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
        auto fatHeader = reinterpret_cast<FatHeader*>(base);
        auto nArch = magic == FAT_MAGIC_VAL ? fatHeader->nfat_arch : Swap(fatHeader->nfat_arch);
        for (std::uint32_t i{}; i < nArch; ++i) {
            auto arch = reinterpret_cast<FatArch*>(base + sizeof(FatHeader) + sizeof(FatArch) * i);
            if (auto archOffset = magic == FAT_MAGIC_VAL ? arch->offset : Swap(arch->offset);
                !injectDyLibSingleArch(base + archOffset, dylibPath, weakInject))
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
