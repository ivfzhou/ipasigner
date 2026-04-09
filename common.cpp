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
 * @file common.cpp
 * @brief 通用工具函数实现。
 *
 * 实现 common.hpp 中声明的各类通用工具函数，包括字节序交换、
 * 文件读写、目录查找、字符串处理、错误信息获取等功能。
 */

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <ios>
#include <optional>
#include <queue>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <zip.h>

#include "Logger.tpp"
#include "ScopeGuard.hpp"
#include "common.hpp"

namespace gitee::com::ivfzhou::ipasigner {

// 交换 16 位无符号整数的字节序（大端 <-> 小端），即交换高低两个字节的位置。
std::uint16_t Swap(const std::uint16_t value) { return (value >> 8 & 0x00ff) | (value << 8 & 0xff00); }

// 交换 32 位无符号整数的字节序（大端 <-> 小端）。
// 第一步：交换每对相邻字节（奇偶字节互换）；第二步：交换前后两个半字（16 位）。
std::uint32_t Swap(std::uint32_t value) {
    value = (value >> 8 & 0x00ff00ff) | (value << 8 & 0xff00ff00);
    value = (value >> 16 & 0x0000ffff) | (value << 16 & 0xffff0000);
    return value;
}

// 交换 64 位无符号整数的字节序（大端 <-> 小端）。
// 第一步：交换前后两个 32 位半部分；第二步：在每个 32 位内交换前后两个 16 位；第三步：在每个 16 位内交换前后两个字节。
std::uint64_t Swap(std::uint64_t value) {
    value = (value & 0x00000000ffffffffULL) << 32 | (value & 0xffffffff00000000ULL) >> 32;
    value = (value & 0x0000ffff0000ffffULL) << 16 | (value & 0xffff0000ffff0000ULL) >> 16;
    value = (value & 0x00ff00ff00ff00ffULL) << 8 | (value & 0xff00ff00ff00ff00ULL) >> 8;
    return value;
}

// 交换 32 位无符号整数的字节序（大端 <-> 小端），功能与 Swap(uint32_t) 相同。
uint32_t SwapInt32(uint32_t value) {
    value = (value >> 8 & 0x00ff00ff) | (value << 8 & 0xff00ff00);
    value = (value >> 16 & 0x0000ffff) | (value << 16 & 0xffff0000);
    return value;
}

/**
 * @brief 读取文件全部内容到字符串。
 *
 * 以二进制模式打开文件，先定位到文件末尾获取文件大小，
 * 然后一次性读取全部内容。
 *
 * @param filePath 文件路径。
 * @return 成功返回文件内容字符串，失败返回 std::nullopt。
 */
std::optional<std::string> ReadFile(const std::filesystem::path& filePath) {
    std::ifstream file{};
    file.exceptions(std::ios::failbit | std::ios::badbit);
    try {
        file.open(filePath, std::ios::binary | std::ios::ate);
        ScopeGuard fileDeleter{[&file] { file.close(); }};
        auto size = file.tellg();
        file.seekg(0);
        std::string content{};
        content.resize(size);
        file.read(content.data(), size);
        return std::move(content);
    } catch (const std::ios_base::failure& e) {
        Logger::error("failed to read file:", e.what(), "code:", e.code().message());
        return std::nullopt;
    }
}

/**
 * @brief 将数据写入文件。
 *
 * 若父目录不存在则自动创建。以二进制模式写入。
 *
 * @param filePath 目标文件路径。
 * @param data 待写入的数据。
 * @return 成功返回 true，失败返回 false。
 */
bool WriteFile(const std::filesystem::path& filePath, const std::string_view data) {
    // 确保父目录存在。
    if (auto parentDir = filePath.parent_path(); !parentDir.empty() && !std::filesystem::exists(parentDir))
        std::filesystem::create_directories(parentDir);

    std::ofstream file{};
    file.exceptions(std::ios::failbit | std::ios::badbit);
    try {
        file.open(filePath, std::ios::binary);
        ScopeGuard fileDeleter{[&file] { file.close(); }};
        file.write(data.data(), static_cast<std::streamsize>(data.size()));
        return true;
    } catch (const std::ios_base::failure& e) {
        Logger::error("failed to write file:", e.what(), "code:", e.code().message());
        return false;
    }
}

/**
 * @brief 广度优先遍历查找 IPA 解压目录中最外层的 .app 文件夹。
 *
 * IPA 解压后的目录结构通常为：ipaDir/Payload/XXX.app/。
 * 使用 BFS 确保找到的是最外层的 .app 目录。
 *
 * @param ipaDir IPA 解压后的根目录。
 * @return 成功返回 .app 目录的绝对路径，未找到返回 std::nullopt。
 */
std::optional<std::filesystem::path> FindIPAAppFolder(const std::filesystem::path& ipaDir) {
    if (!std::filesystem::exists(ipaDir) || !std::filesystem::is_directory(ipaDir)) {
        Logger::error("ipa directory does not exist or is not a directory:", ipaDir);
        return std::nullopt;
    }

    // 广度优先遍历，确保找到的是最外层的 .app 文件夹。
    std::queue<std::filesystem::path> dirs{};
    dirs.push(ipaDir);

    while (!dirs.empty()) {
        auto current = dirs.front();
        dirs.pop();

        for (auto&& entry : std::filesystem::directory_iterator(current)) {
            if (!entry.is_directory()) continue;

            if (auto name = entry.path().filename().string();
                name.size() >= std::strlen(FILE_NAME_SUFFIX_APP) && name.ends_with(FILE_NAME_SUFFIX_APP)) {
                return entry.path();
            }

            // 非 .app 文件夹加入队列继续搜索。
            dirs.push(entry.path());
        }
    }

    return std::nullopt;
}

/**
 * @brief 递归查找 .app 目录下的所有插件目录（.app 或 .appex）。
 * @param appDir .app 目录路径。
 * @return 成功返回插件目录路径列表，目录不存在返回 std::nullopt。
 */
std::optional<std::vector<std::filesystem::path>> FindIPAPluginFolders(const std::filesystem::path& appDir) {
    // 文件夹需存在。
    if (!std::filesystem::exists(appDir) || !std::filesystem::is_directory(appDir)) {
        Logger::error("app directory does not exist or is not a directory:", appDir.string());
        return std::nullopt;
    }

    // 递归遍历文件夹。
    std::vector<std::filesystem::path> result{};
    for (auto&& entry : std::filesystem::recursive_directory_iterator(appDir)) {
        if (!entry.is_directory()) continue;

        auto&& filePath = entry.path();
        if (auto filePathStr = filePath.string();
            filePathStr.ends_with(FILE_NAME_SUFFIX_APP) || filePathStr.ends_with(FILE_NAME_SUFFIX_APPEX)) {
            result.push_back(filePath);
        }
    }

    return result;
}

/**
 * @brief 获取 OpenSSL 错误栈中的错误信息。
 *
 * 使用 BIO 内存缓冲区捕获 ERR_print_errors 的输出，
 * 转换为 std::string 返回。
 *
 * @return 错误信息字符串，无错误时返回空字符串。
 */
std::string GetOpensslErrors() {
    auto bio = BIO_new(BIO_s_mem());
    if (!bio) {
        Logger::error("BIO_new failed, cannot get openssl errors");
        return {};
    }
    ScopeGuard bioDeleter{[&bio] { BIO_free(bio); }};
    ERR_print_errors(bio);
    char* buf{};
    auto len = BIO_get_mem_data(bio, &buf);
    if (len <= 0) return {};
    std::string errMsg(buf, len);
    return errMsg;
}

/**
 * @brief 获取 libzip 错误码对应的错误信息字符串。
 * @param err libzip 错误码。
 * @return 错误描述字符串。
 */
std::string GetZipErrors(const int err) {
    zip_error_t zipError{};
    zip_error_init_with_code(&zipError, err);
    std::string result(zip_error_strerror(&zipError));
    zip_error_fini(&zipError);
    return result;
}

/**
 * @brief 去除字符串首尾的空白字符（空格、制表符、换行符等）。
 * @param value 待处理的字符串。
 * @return 去除首尾空白后的新字符串，全为空白则返回空字符串。
 */
std::string StringTrimBlank(const std::string_view value) {
    auto isSpace = [](const char c) { return std::isspace(c); };

    auto first = std::ranges::find_if_not(value, isSpace);
    if (first == value.end()) return {};

    auto last = std::find_if_not(value.rbegin(), value.rend(), isSpace).base();
    if (first >= last) return {};

    return {first, last};
}

/**
 * @brief 将字符串中所有出现的子串 from 替换为 to。
 * @param str 待处理的字符串（原地修改）。
 * @param from 要查找的子串。
 * @param to 替换为的字符串。
 */
void StringReplaceAll(std::string& str, const std::string_view from, const std::string_view to) {
    if (from.empty()) return;

    std::size_t pos{};
    while ((pos = str.find(from, pos)) != std::string::npos) {
        str.replace(pos, from.size(), to);
        pos += to.size();
    }
}

/**
 * @brief 忽略大小写比较两个字符串是否相等。
 * @param a 第一个字符串。
 * @param b 第二个字符串。
 * @return 相等返回 true，否则返回 false。
 */
bool StringEqualIgnoreCase(const std::string_view a, const std::string_view b) {
    return std::ranges::equal(a, b, [](const char c1, const char c2) { return std::tolower(c1) == std::tolower(c2); });
}

/**
 * @brief 为 XML 片段包装 <plist> 根标签。
 *
 * 用于将从描述文件中提取的 Entitlements 等 XML 片段包装为完整的 plist 文档，
 * 以便使用 pugixml 进行解析。
 *
 * @param s XML 片段字符串。
 * @return 包装后的字符串："<plist>" + s + "</plist>"。
 */
std::string WrapperPListXMLTag(const std::string_view s) {
    std::string result("<plist>");
    result.append(s.data(), s.size());
    result.append("</plist>");
    return result;
}

/**
 * @brief 去除 XML 片段的 <plist> 根标签。
 *
 * WrapperPListXMLTag 的逆操作，将包装后的 plist 文档还原为纯 XML 片段。
 *
 * @param s 包含 <plist> 标签的字符串。
 * @return 去除标签后的 XML 片段，若不包含标签则原样返回。
 */
std::string UnwrapPListXMLTag(const std::string_view s) {
    if (auto nonBlankStr = StringTrimBlank(s); nonBlankStr.starts_with("<plist>") && nonBlankStr.ends_with("</plist>"))
        return std::string(nonBlankStr.substr(7, nonBlankStr.size() - 15));
    return std::string(s);
}

/**
 * @brief 创建目录并设置权限。
 *
 * 若目录已存在则打印警告日志并返回成功。
 * 支持多层目录创建（create_directories）。
 *
 * @param dirPath 目录路径。
 * @param perm 目录权限。
 * @return 成功返回 true，失败返回 false。
 */
bool MakeDir(const std::filesystem::path& dirPath, const std::filesystem::perms perm) {
    if (std::filesystem::exists(dirPath)) {
        Logger::warn("directory already exists:", dirPath.string());
        return true;
    }

    std::error_code ec{};
    if (!std::filesystem::create_directories(dirPath, ec)) {
        Logger::error("failed to create directory:", dirPath.string(), ec.message());
        return false;
    }

    std::filesystem::permissions(dirPath, perm, ec);
    if (ec) {
        Logger::error("failed to set permissions on directory:", dirPath.string(), ec.message());
        return false;
    }

    return true;
}

/**
 * @brief 校验 Bundle ID 格式是否合法。
 *
 * 合法的 Bundle ID 仅包含字母、数字、连字符和点号。
 *
 * @param bundle 待校验的 Bundle ID 字符串。
 * @return 格式合法返回 true，否则返回 false。
 */
bool IsInvalidBundleValue(std::string_view bundle) {
    static std::regex re(R"(^[A-Za-z0-9\-\.]+$)");
    return std::regex_match(bundle.data(), re);
}

/**
 * @brief 检测 plist 数据的格式。
 *
 * 通过文件头魔数和内容特征判断 plist 格式：
 * - Binary Plist 以 "bplist" 开头
 * - XML Plist 以 XML 声明、DOCTYPE 或 <plist 标签开头
 *
 * @param data plist 文件的原始二进制数据。
 * @return 检测到的格式类型。
 */
PListFormat DetectPListFormat(const std::string_view data) {
    if (data.size() >= 6 && data.substr(0, 6) == "bplist") return PListFormat::Binary;

    auto trimmed = StringTrimBlank(data);
    if (trimmed.starts_with("<?xml") || trimmed.starts_with("<!DOCTYPE") || trimmed.starts_with("<plist"))
        return PListFormat::XML;

    return PListFormat::Unknown;
}

/**
 * @brief 从 Binary Plist 数据中按大端序读取指定字节数的无符号整数。
 * @param data 数据指针。
 * @param offset 起始偏移。
 * @param nbytes 字节数（1~8）。
 * @return 读取的无符号整数值。
 */
static std::uint64_t bplistReadUInt(const std::uint8_t* data, std::uint64_t offset, std::uint8_t nbytes) {
    std::uint64_t val{};
    for (std::uint8_t i{}; i < nbytes; ++i) val = (val << 8) | data[offset + i];
    return val;
}

/**
 * @brief 对字符串中的 XML 特殊字符进行转义。
 * @param s 原始字符串。
 * @return 转义后的字符串（& -> &amp; < -> &lt; > -> &gt;）。
 */
static std::string xmlEscape(const std::string_view s) {
    std::string out{};
    out.reserve(s.size());
    for (auto c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            default: out += c; break;
        }
    }
    return out;
}

/**
 * @brief 递归将 Binary Plist 中的单个对象转换为 XML 字符串。
 *
 * 根据对象类型标记（高 4 bit）分发处理：
 * - 0x0: null/bool/fill
 * - 0x1: integer
 * - 0x2: real
 * - 0x3: date
 * - 0x4: binary data
 * - 0x5: ASCII string
 * - 0x6: Unicode string
 * - 0x8: UID（以 dict 形式输出）
 * - 0xA: array
 * - 0xD: dict
 *
 * @param data 整个 bplist 文件的原始字节。
 * @param dataSize 文件总字节数。
 * @param offsetTable 对象偏移表。
 * @param objectCount 对象总数。
 * @param objectRefSize 对象引用的字节宽度。
 * @param objIndex 当前要转换的对象索引。
 * @param out 输出的 XML 字符串（追加模式）。
 * @param depth 当前缩进深度。
 * @return 成功返回 true，数据异常返回 false。
 */
static bool bplistObjectToXML(const std::uint8_t* data, std::uint64_t dataSize,
                              const std::vector<std::uint64_t>& offsetTable, std::uint64_t objectCount,
                              std::uint8_t objectRefSize, std::uint64_t objIndex, std::string& out, int depth) {
    if (objIndex >= objectCount) return false;

    auto offset = offsetTable[objIndex];
    if (offset >= dataSize) return false;

    auto marker = data[offset];
    auto objectType = static_cast<std::uint8_t>(marker >> 4);
    auto objectInfo = static_cast<std::uint8_t>(marker & 0x0F);

    std::string indent(depth, '\t');

    // 读取扩展大小：当 objectInfo == 0x0F 时，紧随其后有一个 int 对象表示实际大小。
    // 注意：调用时 pos 已指向 marker 后一字节（即 size 编码的起始位置）。
    auto readExtendedSize = [&](std::uint64_t& pos) -> std::uint64_t {
        if (objectInfo != 0x0F) return objectInfo;
        if (pos >= dataSize) return 0;
        auto sizeMarker = data[pos];
        auto sizeType = static_cast<std::uint8_t>(sizeMarker >> 4);
        auto sizePow = static_cast<std::uint8_t>(sizeMarker & 0x0F);
        if (sizeType != 0x01) return 0;
        std::uint8_t sizeBytes = 1u << sizePow;
        pos++;
        if (pos + sizeBytes > dataSize) return 0;
        auto val = bplistReadUInt(data, pos, sizeBytes);
        pos += sizeBytes;
        return val;
    };

    switch (objectType) {
        case 0x0: {
            // null (0x00), false (0x08), true (0x09)。
            if (objectInfo == 0x08) {
                out += indent + "<false/>\n";
            } else if (objectInfo == 0x09) {
                out += indent + "<true/>\n";
            }
            // 0x00 (null) and 0x0F (fill) are skipped。
            break;
        }
        case 0x1: {
            // Integer：2^objectInfo 字节的大端整数。
            std::uint8_t byteCount = 1u << objectInfo;
            if (offset + 1 + byteCount > dataSize) return false;
            auto val = bplistReadUInt(data, offset + 1, byteCount);
            out += indent + "<integer>" + std::to_string(val) + "</integer>\n";
            break;
        }
        case 0x2: {
            // Real：4 字节 float 或 8 字节 double。
            std::uint8_t byteCount = 1u << objectInfo;
            if (offset + 1 + byteCount > dataSize) return false;
            double val{};
            if (byteCount == 4) {
                std::uint32_t bits = static_cast<std::uint32_t>(bplistReadUInt(data, offset + 1, 4));
                float f{};
                std::memcpy(&f, &bits, 4);
                val = f;
            } else if (byteCount == 8) {
                std::uint64_t bits = bplistReadUInt(data, offset + 1, 8);
                std::memcpy(&val, &bits, 8);
            }
            out += indent + "<real>" + std::to_string(val) + "</real>\n";
            break;
        }
        case 0x3: {
            // Date：8 字节 double（Core Data 时间戳，基于 2001-01-01）。
            if (offset + 9 > dataSize) return false;
            std::uint64_t bits = bplistReadUInt(data, offset + 1, 8);
            double timestamp{};
            std::memcpy(&timestamp, &bits, 8);
            out += indent + "<date>2001-01-01T00:00:00Z</date>\n";
            break;
        }
        case 0x4: {
            // Binary data -> Base64。
            auto pos = offset + 1;
            auto count = readExtendedSize(pos);
            if (pos + count > dataSize) return false;
            // 简单 Base64 编码。
            static constexpr char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string b64{};
            for (std::uint64_t i{}; i < count; i += 3) {
                auto remaining = count - i;
                auto b0 = data[pos + i];
                auto b1 = remaining > 1 ? data[pos + i + 1] : 0;
                auto b2 = remaining > 2 ? data[pos + i + 2] : 0;
                b64 += b64chars[b0 >> 2];
                b64 += b64chars[((b0 & 0x03) << 4) | (b1 >> 4)];
                b64 += remaining > 1 ? b64chars[((b1 & 0x0F) << 2) | (b2 >> 6)] : '=';
                b64 += remaining > 2 ? b64chars[b2 & 0x3F] : '=';
            }
            out += indent + "<data>" + b64 + "</data>\n";
            break;
        }
        case 0x5: {
            // ASCII string。
            auto pos = offset + 1;
            auto count = readExtendedSize(pos);
            if (pos + count > dataSize) return false;
            std::string str(reinterpret_cast<const char*>(data + pos), count);
            out += indent + "<string>" + xmlEscape(str) + "</string>\n";
            break;
        }
        case 0x6: {
            // Unicode (UTF-16BE) string。
            auto pos = offset + 1;
            auto count = readExtendedSize(pos);
            if (pos + count * 2 > dataSize) return false;
            // 简单 UTF-16BE -> ASCII/UTF-8 转换。
            std::string str{};
            for (std::uint64_t i{}; i < count; ++i) {
                auto ch = static_cast<std::uint16_t>(bplistReadUInt(data, pos + i * 2, 2));
                if (ch < 0x80) {
                    str += static_cast<char>(ch);
                } else if (ch < 0x800) {
                    str += static_cast<char>(0xC0 | (ch >> 6));
                    str += static_cast<char>(0x80 | (ch & 0x3F));
                } else {
                    str += static_cast<char>(0xE0 | (ch >> 12));
                    str += static_cast<char>(0x80 | ((ch >> 6) & 0x3F));
                    str += static_cast<char>(0x80 | (ch & 0x3F));
                }
            }
            out += indent + "<string>" + xmlEscape(str) + "</string>\n";
            break;
        }
        case 0x8: {
            // UID：以 dict{CF$UID: integer} 形式输出。
            std::uint8_t byteCount = objectInfo + 1;
            if (offset + 1 + byteCount > dataSize) return false;
            auto val = bplistReadUInt(data, offset + 1, byteCount);
            out += indent + "<dict>\n";
            out += indent + "\t<key>CF$UID</key>\n";
            out += indent + "\t<integer>" + std::to_string(val) + "</integer>\n";
            out += indent + "</dict>\n";
            break;
        }
        case 0xA: {
            // Array。
            auto pos = offset + 1;
            auto count = readExtendedSize(pos);
            if (pos + count * objectRefSize > dataSize) return false;
            out += indent + "<array>\n";
            for (std::uint64_t i{}; i < count; ++i) {
                auto childIdx = bplistReadUInt(data, pos + i * objectRefSize, objectRefSize);
                if (!bplistObjectToXML(data, dataSize, offsetTable, objectCount, objectRefSize, childIdx, out,
                                       depth + 1))
                    return false;
            }
            out += indent + "</array>\n";
            break;
        }
        case 0xD: {
            // Dict。
            auto pos = offset + 1;
            auto count = readExtendedSize(pos);
            auto keysStart = pos;
            auto valsStart = pos + count * objectRefSize;
            if (valsStart + count * objectRefSize > dataSize) return false;
            out += indent + "<dict>\n";
            for (std::uint64_t i{}; i < count; ++i) {
                auto keyIdx = bplistReadUInt(data, keysStart + i * objectRefSize, objectRefSize);
                auto valIdx = bplistReadUInt(data, valsStart + i * objectRefSize, objectRefSize);
                // Key 必须是字符串类型，直接内联输出。
                if (keyIdx >= objectCount) return false;
                auto keyOffset = offsetTable[keyIdx];
                if (keyOffset >= dataSize) return false;
                auto keyMarker = data[keyOffset];
                auto keyType = static_cast<std::uint8_t>(keyMarker >> 4);
                auto keyInfo = static_cast<std::uint8_t>(keyMarker & 0x0F);
                std::string keyStr{};
                if (keyType == 0x5) {
                    auto keyPos = keyOffset + 1;
                    auto keyCount = static_cast<std::uint64_t>(keyInfo);
                    if (keyInfo == 0x0F) {
                        if (keyPos < dataSize) {
                            auto sm = data[keyPos];
                            auto sp = static_cast<std::uint8_t>(sm & 0x0F);
                            std::uint8_t sb = 1u << sp;
                            keyPos++;
                            keyCount = bplistReadUInt(data, keyPos, sb);
                            keyPos += sb;
                        }
                    }
                    if (keyPos + keyCount <= dataSize)
                        keyStr = std::string(reinterpret_cast<const char*>(data + keyPos), keyCount);
                } else if (keyType == 0x6) {
                    auto keyPos = keyOffset + 1;
                    auto keyCount = static_cast<std::uint64_t>(keyInfo);
                    if (keyInfo == 0x0F) {
                        if (keyPos < dataSize) {
                            auto sm = data[keyPos];
                            auto sp = static_cast<std::uint8_t>(sm & 0x0F);
                            std::uint8_t sb = 1u << sp;
                            keyPos++;
                            keyCount = bplistReadUInt(data, keyPos, sb);
                            keyPos += sb;
                        }
                    }
                    if (keyPos + keyCount * 2 <= dataSize) {
                        for (std::uint64_t j{}; j < keyCount; ++j) {
                            auto ch = static_cast<std::uint16_t>(bplistReadUInt(data, keyPos + j * 2, 2));
                            if (ch < 0x80) {
                                keyStr += static_cast<char>(ch);
                            } else if (ch < 0x800) {
                                keyStr += static_cast<char>(0xC0 | (ch >> 6));
                                keyStr += static_cast<char>(0x80 | (ch & 0x3F));
                            } else {
                                keyStr += static_cast<char>(0xE0 | (ch >> 12));
                                keyStr += static_cast<char>(0x80 | ((ch >> 6) & 0x3F));
                                keyStr += static_cast<char>(0x80 | (ch & 0x3F));
                            }
                        }
                    }
                } else {
                    return false;
                }
                out += indent + "\t<key>" + xmlEscape(keyStr) + "</key>\n";
                if (!bplistObjectToXML(data, dataSize, offsetTable, objectCount, objectRefSize, valIdx, out,
                                       depth + 1))
                    return false;
            }
            out += indent + "</dict>\n";
            break;
        }
        default: {
            Logger::warn("unsupported bplist object type:", std::to_string(objectType));
            break;
        }
    }

    return true;
}

/**
 * @brief 将 Binary Plist 数据转换为 XML 格式的 plist 字符串。
 *
 * Apple Binary Plist 格式结构：
 * - Header: "bplist00" (8 bytes)
 * - Object Table: 各种序列化对象
 * - Offset Table: 每个对象的文件偏移
 * - Trailer: 32 bytes，包含元数据
 *
 * @param data Binary Plist 的原始二进制数据。
 * @return 成功返回 XML 格式 plist 字符串，失败返回 std::nullopt。
 */
std::optional<std::string> BPListToXML(const std::string_view data) {
    if (data.size() < 40) {
        Logger::error("bplist data too small:", data.size());
        return std::nullopt;
    }

    // 验证魔数。
    if (data.substr(0, 6) != "bplist") {
        Logger::error("invalid bplist magic");
        return std::nullopt;
    }

    auto bytes = reinterpret_cast<const std::uint8_t*>(data.data());
    auto dataSize = static_cast<std::uint64_t>(data.size());

    // 读取 Trailer（最后 32 字节）。
    // Trailer 布局: [6 unused][1 sortVersion][1 offsetIntSize][1 objectRefSize]
    //               [4 unused][4 numObjects][4 unused][4 topObject][4 unused][4 offsetTableOffset]
    // 实际按 Apple 规范是：
    //   offset -32: 5 unused, 1 sortVersion
    //   offset -26: 1 offsetIntSize
    //   offset -25: 1 objectRefSize
    //   offset -24: 8 numObjects
    //   offset -16: 8 topObject
    //   offset -8:  8 offsetTableOffset
    auto trailerStart = dataSize - 32;
    auto offsetIntSize = bytes[trailerStart + 6];
    auto objectRefSize = bytes[trailerStart + 7];
    auto numObjects = bplistReadUInt(bytes, trailerStart + 8, 8);
    auto topObject = bplistReadUInt(bytes, trailerStart + 16, 8);
    auto offsetTableOffset = bplistReadUInt(bytes, trailerStart + 24, 8);

    if (offsetIntSize == 0 || objectRefSize == 0 || numObjects == 0) {
        Logger::error("invalid bplist trailer");
        return std::nullopt;
    }
    if (offsetTableOffset + numObjects * offsetIntSize > dataSize - 32) {
        Logger::error("bplist offset table out of bounds");
        return std::nullopt;
    }

    // 读取 Offset Table。
    std::vector<std::uint64_t> offsetTable{};
    offsetTable.reserve(numObjects);
    for (std::uint64_t i{}; i < numObjects; ++i)
        offsetTable.push_back(bplistReadUInt(bytes, offsetTableOffset + i * offsetIntSize, offsetIntSize));

    // 构建 XML 输出。
    std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                      "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                      "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                      "<plist version=\"1.0\">\n";

    if (!bplistObjectToXML(bytes, dataSize, offsetTable, numObjects, objectRefSize, topObject, xml, 0)) {
        Logger::error("failed to convert bplist object to XML");
        return std::nullopt;
    }

    xml += "</plist>\n";
    return xml;
}

/**
 * @brief 读取 plist 文件并确保返回 XML 格式。
 *
 * 先以二进制模式读取文件内容，检测格式后：
 * - 若为 XML 格式则直接返回
 * - 若为 Binary Plist 格式则自动转换为 XML 后返回
 * - 若格式未知则尝试作为 XML 返回（可能后续 pugixml 解析失败）
 *
 * @param filePath plist 文件路径。
 * @return 成功返回 XML 格式 plist 字符串，失败返回 std::nullopt。
 */
std::optional<std::string> ReadPListAsXML(const std::filesystem::path& filePath) {
    auto dataOpt = ReadFile(filePath);
    if (!dataOpt) return std::nullopt;

    auto format = DetectPListFormat(*dataOpt);
    switch (format) {
        case PListFormat::XML:
            return dataOpt;
        case PListFormat::Binary: {
            Logger::info("detected binary plist, converting to XML:", filePath.string());
            return BPListToXML(*dataOpt);
        }
        case PListFormat::Unknown:
        default:
            Logger::warn("unknown plist format, treating as XML:", filePath.string());
            return dataOpt;
    }
}

}
