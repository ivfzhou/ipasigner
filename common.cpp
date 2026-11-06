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
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <ios>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <pugixml.hpp>
#include <zip.h>

#include "Logger.tpp"
#include "ScopeGuard.hpp"
#include "common.hpp"
#include "constants.hpp"
#include "macho.hpp"

namespace com::gitee::ivfzhou::ipasigner {

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
        // 仅记录调试日志，由调用方根据上下文（必需文件 vs 可选文件）决定是否输出错误。
        Logger::debug("failed to read file:", e.what(), "code:", e.code().message());
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
        Logger::debug("directory already exists:", dirPath.string());
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
 * @brief 探测二进制文件的容器格式。
 *
 * 实现思路对标 keystore-cli/macho.DetectBinaryFormat：
 *   1. 读取头部 8 字节；
 *   2. 若以 "!<arch>\n" 开头 -> StaticArchive；
 *   3. 若是 0xCAFEBABE/0xBEBAFECA -> Fat 容器，再检查 nfat_arch 个 slice
 *      的首部，确定是 Fat Mach-O 还是 Fat Archive；
 *   4. 否则若是 Mach-O 4 个魔数之一 -> MachO，否则 Unknown。
 */
BinaryFormat DetectBinaryFormat(const std::filesystem::path& filePath) {
    constexpr const char archiveMagic[] = "!<arch>\n"; // 共 8 字节，不含末尾 NUL。
    constexpr std::size_t archiveMagicLen = sizeof(archiveMagic) - 1;

    auto isThinMachO = [](std::uint32_t magicLE) -> bool {
        return magicLE == MH_MAGIC_VAL || magicLE == MH_CIGAM_VAL || magicLE == MH_MAGIC_64_VAL ||
            magicLE == MH_CIGAM_64_VAL;
    };

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return BinaryFormat::Unknown;

    char header[8]{};
    file.read(header, sizeof(header));
    auto headerSize = static_cast<std::size_t>(file.gcount());
    if (headerSize == 0) return BinaryFormat::Unknown;

    if (headerSize >= archiveMagicLen && std::memcmp(header, archiveMagic, archiveMagicLen) == 0)
        return BinaryFormat::StaticArchive;

    if (headerSize < 4) return BinaryFormat::Unknown;

    auto readU32LE = [](const char* p) {
        return static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[0])) |
            static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[1])) << 8 |
            static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[2])) << 16 |
            static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[3])) << 24;
    };
    auto magicLE = readU32LE(header);

    // Mach-O 文件的 magic 在文件中以小端存放（thin），或以大端 0xCAFEBABE 存放（fat）。
    // 我们以小端方式读出 32-bit magic：
    //   - 文件字节 CA FE BA BE（标准磁盘上的 fat，大端写入） -> magicLE = 0xBEBAFECA (FAT_CIGAM_VAL)
    //   - 文件字节 BE BA FE CA（小端写入的 fat，少见）       -> magicLE = 0xCAFEBABE (FAT_MAGIC_VAL)
    // 因此：当 magicLE == FAT_CIGAM_VAL 时，文件中是大端格式，nfat_arch 需要 swap；
    //      当 magicLE == FAT_MAGIC_VAL 时，文件中是小端格式，nfat_arch 直接 LE 即可。
    if (magicLE == FAT_MAGIC_VAL || magicLE == FAT_CIGAM_VAL) {
        bool fileIsBigEndian = magicLE == FAT_CIGAM_VAL;
        if (headerSize < 8) return BinaryFormat::Unknown;
        std::uint32_t nfat = readU32LE(header + 4);
        if (fileIsBigEndian) nfat = Swap(nfat);
        if (nfat == 0 || nfat > 1024) return BinaryFormat::Unknown;

        std::vector<char> table(static_cast<std::size_t>(nfat) * 20);
        file.seekg(8, std::ios::beg);
        file.read(table.data(), static_cast<std::streamsize>(table.size()));
        auto tableRead = static_cast<std::size_t>(file.gcount());

        bool foundMachO{};
        for (std::uint32_t i = 0; i < nfat; ++i) {
            std::size_t base = static_cast<std::size_t>(i) * 20;
            if (base + 20 > tableRead) break;
            std::uint32_t offset = readU32LE(&table[base + 8]);
            if (fileIsBigEndian) offset = Swap(offset);

            char sliceHeader[8]{};
            file.seekg(offset, std::ios::beg);
            file.read(sliceHeader, sizeof(sliceHeader));
            auto sliceRead = static_cast<std::size_t>(file.gcount());
            if (sliceRead >= archiveMagicLen && std::memcmp(sliceHeader, archiveMagic, archiveMagicLen) == 0)
                return BinaryFormat::FatStaticArchive;
            if (sliceRead >= 4 && isThinMachO(readU32LE(sliceHeader))) {
                foundMachO = true;
                continue;
            }
            return BinaryFormat::Unknown;
        }
        return foundMachO ? BinaryFormat::FatMachO : BinaryFormat::Unknown;
    }

    if (isThinMachO(magicLE)) return BinaryFormat::MachO;
    return BinaryFormat::Unknown;
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
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        default:
            out += c;
            break;
        }
    }
    return out;
}

/// UTF-16BE 单元序列转 UTF-8，正确合并高低代理项。
/// 旧实现把代理项各自编成 3 字节（CESU-8），既不是合法 UTF-8，也会让 pugixml
/// 解析 XML 中间表示时失败，emoji / 部分 CJK 扩展字符因此丢失。
static std::string utf16beToUtf8(const std::uint8_t* data, const std::uint64_t pos, const std::uint64_t count) {
    std::string out{};
    out.reserve(count);
    for (std::uint64_t i{}; i < count; ++i) {
        auto unit = static_cast<std::uint16_t>(bplistReadUInt(data, pos + i * 2, 2));
        std::uint32_t cp = unit;
        if (unit >= 0xD800 && unit <= 0xDBFF && i + 1 < count) {
            auto low = static_cast<std::uint16_t>(bplistReadUInt(data, pos + (i + 1) * 2, 2));
            if (low >= 0xDC00 && low <= 0xDFFF) {
                cp = 0x10000u + ((static_cast<std::uint32_t>(unit) - 0xD800u) << 10) +
                    (static_cast<std::uint32_t>(low) - 0xDC00u);
                ++i;
            } else {
                cp = 0xFFFDu; // 孤立高代理项：XML 无法表达，退化为替换字符。
            }
        } else if (unit >= 0xD800 && unit <= 0xDFFF) {
            cp = 0xFFFDu;
        }
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0u | (cp >> 6));
            out += static_cast<char>(0x80u | (cp & 0x3Fu));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0u | (cp >> 12));
            out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
            out += static_cast<char>(0x80u | (cp & 0x3Fu));
        } else {
            out += static_cast<char>(0xF0u | (cp >> 18));
            out += static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu));
            out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
            out += static_cast<char>(0x80u | (cp & 0x3Fu));
        }
    }
    return out;
}

/// 读取 bplist 字符串对象（ASCII 0x5 / UTF-16BE 0x6，含 0x0F 扩展长度），
/// 统一返回 UTF-8，供字符串值与 dict key 共用。
static std::optional<std::string> bplistStringToUtf8(const std::uint8_t* data, const std::uint64_t dataSize,
                                                     const std::uint64_t offset) {
    if (offset >= dataSize) return std::nullopt;
    const auto marker = data[offset];
    const auto type = static_cast<std::uint8_t>(marker >> 4);
    const auto info = static_cast<std::uint8_t>(marker & 0x0F);
    auto pos = offset + 1;
    std::uint64_t count = info;
    if (info == 0x0F) {
        if (pos >= dataSize) return std::nullopt;
        const auto sizeMarker = data[pos++];
        if ((sizeMarker >> 4) != 0x01) return std::nullopt;
        const auto nbytes = static_cast<std::uint8_t>(1u << (sizeMarker & 0x0F));
        if (nbytes > 8 || pos + nbytes > dataSize) return std::nullopt;
        count = bplistReadUInt(data, pos, nbytes);
        pos += nbytes;
    }
    if (type == 0x5) {
        if (count > dataSize - pos) return std::nullopt;
        return std::string(reinterpret_cast<const char*>(data + pos), static_cast<std::size_t>(count));
    }
    if (type == 0x6) {
        if (count > (dataSize - pos) / 2) return std::nullopt;
        return utf16beToUtf8(data, pos, count);
    }
    return std::nullopt;
}

/// Apple bplist <date> 的纪元：2001-01-01T00:00:00Z 对应的 Unix 秒数。
constexpr std::int64_t APPLE_EPOCH_UNIX_SECONDS = 978307200;

/// 公历日期 -> 自 1970-01-01 的天数（Howard Hinnant civil calendar 算法）。
static std::int64_t daysFromCivil(std::int64_t y, const unsigned m, const unsigned d) {
    y -= m <= 2 ? 1 : 0;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

/// 自 1970-01-01 的天数 -> 公历日期。
static void civilFromDays(std::int64_t z, std::int64_t& y, unsigned& m, unsigned& d) {
    z += 719468;
    const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const auto doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t yy = static_cast<std::int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y = yy + (m <= 2 ? 1 : 0);
}

/// bplist date（自 2001-01-01 起的秒数，double）-> ISO8601 字符串。
static std::string bplistDateToISO8601(const double appleSeconds) {
    const double unixSeconds = static_cast<double>(APPLE_EPOCH_UNIX_SECONDS) + appleSeconds;
    auto total = static_cast<std::int64_t>(std::floor(unixSeconds));
    const double frac = unixSeconds - static_cast<double>(total);
    std::int64_t days = total / 86400;
    std::int64_t sod = total % 86400;
    if (sod < 0) {
        sod += 86400;
        --days;
    }
    std::int64_t y{};
    unsigned m{}, d{};
    civilFromDays(days, y, m, d);
    std::string out =
        std::format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}", y, m, d, sod / 3600, sod % 3600 / 60, sod % 60);
    if (frac > 1e-6) {
        auto fracStr = std::format("{:.6f}", frac); // "0.500000"
        fracStr.erase(0, 1); // ".500000"
        while (fracStr.size() > 2 && fracStr.back() == '0') fracStr.pop_back();
        out += fracStr;
    }
    out += 'Z';
    return out;
}

/// ISO8601 字符串 -> bplist date 秒数。解析 "YYYY-MM-DDTHH:MM:SS[.f]Z"。
static std::optional<double> iso8601ToBplistDate(const std::string_view in) {
    auto s = StringTrimBlank(in);
    if (s.size() < 19) return std::nullopt;
    auto digits = [&](const std::size_t pos, const std::size_t len) -> std::optional<std::int64_t> {
        if (pos + len > s.size()) return std::nullopt;
        std::int64_t v{};
        for (std::size_t i{}; i < len; ++i) {
            if (s[pos + i] < '0' || s[pos + i] > '9') return std::nullopt;
            v = v * 10 + (s[pos + i] - '0');
        }
        return v;
    };
    auto y = digits(0, 4);
    auto mo = digits(5, 2);
    auto d = digits(8, 2);
    auto h = digits(11, 2);
    auto mi = digits(14, 2);
    auto se = digits(17, 2);
    if (!y || !mo || !d || !h || !mi || !se) return std::nullopt;

    double frac{};
    std::size_t p = 19;
    if (p < s.size() && s[p] == '.') {
        ++p;
        double scale = 0.1;
        while (p < s.size() && s[p] >= '0' && s[p] <= '9') {
            frac += (s[p] - '0') * scale;
            scale *= 0.1;
            ++p;
        }
    }
    const auto days = daysFromCivil(*y, static_cast<unsigned>(*mo), static_cast<unsigned>(*d));
    const auto unixSeconds = days * 86400 + *h * 3600 + *mi * 60 + *se;
    return static_cast<double>(unixSeconds - APPLE_EPOCH_UNIX_SECONDS) + frac;
}

namespace {
/// 保留 bplist 全类型的对象树，完整定义见本文件末尾的 bplist 原生编辑层。
struct BPListNode;

/// 记录 plist 的原始字节、格式与由之生成的 XML：上层未修改 XML 时字节级透传；
/// 修改后按原格式写回（XML）或在原生对象树上打补丁（bplist）。
struct PListSourceBytes {
    std::string original{};
    std::string xml{};
    PListFormat format{PListFormat::Unknown};
    std::shared_ptr<BPListNode> tree{}; ///< 仅 Binary 格式有效。
};
std::mutex g_plistSourceMutex{};
std::map<std::filesystem::path, PListSourceBytes> g_plistSources{};

std::filesystem::path plistCacheKey(const std::filesystem::path& p) {
    std::error_code ec{};
    auto abs = std::filesystem::absolute(p, ec);
    if (ec) abs = p;
    return abs.lexically_normal();
}
} // namespace

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
        } else {
            // null/fill 在 XML plist 里没有对应类型。旧实现直接跳过会破坏
            // array/dict 的 key/value 配对，产生非法 XML；补占位值保持结构完整。
            Logger::warn("bplist null/fill object degraded to <false/> in XML");
            out += indent + "<false/>\n";
        }
        break;
    }
    case 0x1: {
        // Integer：2^objectInfo 字节的大端补码（负数按符号扩展）。
        const std::uint8_t byteCount = 1u << objectInfo;
        if (byteCount > 8 || offset + 1 + byteCount > dataSize) return false;
        auto val = bplistReadUInt(data, offset + 1, byteCount);
        if (byteCount < 8 && (val >> (byteCount * 8 - 1) & 1u) != 0)
            val |= ~((static_cast<std::uint64_t>(1) << (byteCount * 8)) - 1);
        out += indent + "<integer>" + std::to_string(static_cast<std::int64_t>(val)) + "</integer>\n";
        break;
    }
    case 0x2: {
        // Real：4 字节 float 或 8 字节 double。std::to_string 只有 6 位小数，
        // 双精度值会被截断；改用 17 位有效数字保证往返可复原。
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
        out += indent + "<real>" + std::format("{:.17g}", val) + "</real>\n";
        break;
    }
    case 0x3: {
        // Date：8 字节 double（自 2001-01-01 起的秒数），保留真实时间戳。
        if (offset + 9 > dataSize) return false;
        std::uint64_t bits = bplistReadUInt(data, offset + 1, 8);
        double timestamp{};
        std::memcpy(&timestamp, &bits, 8);
        out += indent + "<date>" + bplistDateToISO8601(timestamp) + "</date>\n";
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
        // Unicode (UTF-16BE) string：合并代理对后输出标准 4 字节 UTF-8。
        auto pos = offset + 1;
        auto count = readExtendedSize(pos);
        if (pos + count * 2 > dataSize) return false;
        out += indent + "<string>" + xmlEscape(utf16beToUtf8(data, pos, count)) + "</string>\n";
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
            if (!bplistObjectToXML(data, dataSize, offsetTable, objectCount, objectRefSize, childIdx, out, depth + 1))
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
            // dict 键同样要走完整的 UTF-16BE / 扩展长度解析，否则含代理对的
            // 键会被拆成非法 CESU-8，后续 pugixml 解析失败。
            auto keyType = static_cast<std::uint8_t>(data[keyOffset] >> 4);
            if (keyType != 0x5 && keyType != 0x6) return false;
            auto keyStr = bplistStringToUtf8(data, dataSize, keyOffset);
            if (!keyStr) return false;
            out += indent + "\t<key>" + xmlEscape(*keyStr) + "</key>\n";
            if (!bplistObjectToXML(data, dataSize, offsetTable, objectCount, objectRefSize, valIdx, out, depth + 1))
                return false;
        }
        out += indent + "</dict>\n";
        break;
    }
    default: {
        // 未知类型（set/ordered set 等）不能静默跳过，否则 dict/array 的
        // key/value 配对错位，输出非法 XML。补占位值保持结构完整。
        Logger::warn("unsupported bplist object type:", std::to_string(objectType));
        out += indent + "<data></data>\n";
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

// ===== XML -> Binary Plist 转换实现 =====

namespace {

/// Binary Plist 序列化过程中使用的对象类型。
enum class BPObjectType {
    False,
    True,
    Integer,
    String,
    Data,
    Array,
    Dict,
    Real,
    Date,
    UID,
};

/// 构建 Binary Plist 时使用的对象描述。
struct BPObject {
    BPObjectType type{};
    std::string strValue{}; ///< String/Data 的内容。
    std::uint64_t intValue{}; ///< Integer 的内容。
    double realValue{}; ///< Real 的内容。
    std::vector<std::uint64_t> children{}; ///< Array 的子对象索引。
    std::vector<std::uint64_t> dictKeys{}; ///< Dict 的键对象索引。
    std::vector<std::uint64_t> dictValues{}; ///< Dict 的值对象索引。
};

/// 判断一个字符串是否为纯 ASCII（所有字符都在 0~0x7F 范围内）。
static bool isAsciiOnly(const std::string& s) {
    for (auto c : s)
        if (static_cast<unsigned char>(c) > 0x7F) return false;
    return true;
}

/// 解析 XML plist <integer> 的十进制文本；负数按 bplist 的 8 字节补码存储。
static std::uint64_t parsePlistInteger(const std::string_view text) {
    std::uint64_t val{};
    bool negative{};
    auto p = text.data();
    const auto end = p + text.size();
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
    if (p < end && (*p == '-' || *p == '+')) {
        negative = *p == '-';
        ++p;
    }
    for (; p < end; ++p) {
        if (*p < '0' || *p > '9') break;
        val = val * 10 + (*p - '0');
    }
    return negative ? static_cast<std::uint64_t>(-static_cast<std::int64_t>(val)) : val;
}

/// 以大端序追加指定字节数的无符号整数到输出缓冲区。
static void appendBE(std::string& out, std::uint64_t val, int nbytes) {
    for (int i = nbytes - 1; i >= 0; --i) out.push_back(static_cast<char>(val >> (i * 8) & 0xFF));
}

/// 写入 Binary Plist 的对象长度字段（小长度内联、大长度使用 integer marker）。
static void writeLength(std::string& out, std::uint64_t len, std::uint8_t marker) {
    if (len < 15) {
        out.push_back(static_cast<char>(marker | len));
    } else {
        out.push_back(static_cast<char>(marker | 0xF));
        // int marker 0x10 | log2(bytes)。
        int nbytes = 1;
        auto tmp = len;
        while (tmp > 0xFF) {
            nbytes *= 2;
            tmp >>= 8;
        }
        if (nbytes > 8) nbytes = 8;
        int sp = 0;
        {
            auto n = nbytes;
            while (n > 1) {
                n >>= 1;
                ++sp;
            }
        }
        out.push_back(static_cast<char>(0x10 | sp));
        appendBE(out, len, nbytes);
    }
}

/// 计算某数值需要的最小字节宽度（2 的幂次对齐）。
static int calcIntBytes(std::uint64_t val) {
    if (val <= 0xFF) return 1;
    if (val <= 0xFFFF) return 2;
    if (val <= 0xFFFFFFFFULL) return 4;
    return 8;
}

/// 递归将 pugixml 节点转换为 BPObject 并加入 objects 列表，返回其索引。
static std::uint64_t xmlNodeToBPObject(const pugi::xml_node& valueNode, std::vector<BPObject>& objects) {
    std::string_view name(valueNode.name());
    BPObject obj{};
    if (name == "true") {
        obj.type = BPObjectType::True;
    } else if (name == "false") {
        obj.type = BPObjectType::False;
    } else if (name == "integer") {
        obj.type = BPObjectType::Integer;
        obj.intValue = parsePlistInteger(valueNode.child_value());
    } else if (name == "string") {
        obj.type = BPObjectType::String;
        obj.strValue = valueNode.child_value();
    } else if (name == "data") {
        obj.type = BPObjectType::Data;
        // 将 base64 字符串解码为二进制数据。
        std::string base64(valueNode.child_value());
        // 去除所有空白字符。
        std::string cleaned{};
        cleaned.reserve(base64.size());
        for (auto c : base64)
            if (c != '\n' && c != '\r' && c != ' ' && c != '\t') cleaned.push_back(c);
        // 简单 base64 解码。
        auto b64val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        };
        std::string decoded{};
        std::uint32_t buf{};
        int bits = 0;
        for (auto c : cleaned) {
            if (c == '=') break;
            int v = b64val(c);
            if (v < 0) continue;
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                decoded.push_back(static_cast<char>(buf >> bits & 0xFF));
            }
        }
        obj.strValue = std::move(decoded);
    } else if (name == "real") {
        obj.type = BPObjectType::Real;
        obj.realValue = std::strtod(valueNode.child_value(), nullptr);
    } else if (name == "array") {
        obj.type = BPObjectType::Array;
        std::vector<std::uint64_t> children{};
        for (auto child = valueNode.first_child(); child; child = child.next_sibling()) {
            if (child.type() != pugi::node_element) continue;
            obj.children.push_back(0); // 占位。
        }
        // 先占位插入父节点，再递归子节点。
        auto selfIdx = objects.size();
        objects.push_back(std::move(obj));
        std::size_t ci = 0;
        for (auto child = valueNode.first_child(); child; child = child.next_sibling()) {
            if (child.type() != pugi::node_element) continue;
            auto childIdx = xmlNodeToBPObject(child, objects);
            objects[selfIdx].children[ci++] = childIdx;
        }
        return selfIdx;
    } else if (name == "dict") {
        // NSKeyedArchiver 的 UID 在 XML plist 里表示为 dict{CF$UID: integer}。
        // 写回 bplist 时必须还原成 0x8 UID 对象，否则类型被永久降级为字典。
        std::size_t elementCount = 0;
        std::string uidKey{};
        pugi::xml_node uidValue{};
        for (auto c = valueNode.first_child(); c; c = c.next_sibling()) {
            if (c.type() != pugi::node_element) continue;
            ++elementCount;
            if (elementCount == 1)
                uidKey = c.child_value();
            else if (elementCount == 2)
                uidValue = c;
        }
        if (elementCount == 2 && uidKey == "CF$UID" && std::string_view(uidValue.name()) == "integer") {
            obj.type = BPObjectType::UID;
            obj.intValue = parsePlistInteger(uidValue.child_value());
            auto idx = objects.size();
            objects.push_back(std::move(obj));
            return idx;
        }
        obj.type = BPObjectType::Dict;
        auto selfIdx = objects.size();
        objects.push_back(std::move(obj));
        // 先收集所有 key-value 对。
        std::vector<std::string> keys{};
        std::vector<pugi::xml_node> values{};
        for (auto it = valueNode.begin(); it != valueNode.end(); ++it) {
            if (std::string_view(it->name()) != "key") continue;
            std::string keyText(it->child_value());
            auto valNode = it->next_sibling();
            while (valNode && valNode.type() != pugi::node_element) valNode = valNode.next_sibling();
            if (!valNode) break;
            keys.push_back(std::move(keyText));
            values.push_back(valNode);
            // 跳过 value 节点，避免将其误作为 key 再次处理。
            it = valNode;
        }
        for (std::size_t i = 0; i < keys.size(); ++i) {
            BPObject keyObj{};
            keyObj.type = BPObjectType::String;
            keyObj.strValue = keys[i];
            auto keyIdx = objects.size();
            objects.push_back(std::move(keyObj));
            objects[selfIdx].dictKeys.push_back(keyIdx);
        }
        for (std::size_t i = 0; i < values.size(); ++i) {
            auto valIdx = xmlNodeToBPObject(values[i], objects);
            objects[selfIdx].dictValues.push_back(valIdx);
        }
        return selfIdx;
    } else if (name == "date") {
        // 还原为真正的 bplist date 对象（0x33 + 8 字节双精度时间戳）。
        obj.type = BPObjectType::Date;
        obj.realValue = iso8601ToBplistDate(valueNode.child_value()).value_or(0.0);
    } else {
        // 未知类型：默认当空字符串处理。
        obj.type = BPObjectType::String;
    }

    auto idx = objects.size();
    objects.push_back(std::move(obj));
    return idx;
}

/// 将单个 BPObject 序列化并写入 out，返回其起始偏移量。
static std::uint64_t writeBPObject(std::string& out, const BPObject& obj, int objectRefSize) {
    auto startOff = out.size();
    switch (obj.type) {
    case BPObjectType::False:
        out.push_back('\x08');
        break;
    case BPObjectType::True:
        out.push_back('\x09');
        break;
    case BPObjectType::Integer: {
        auto val = obj.intValue;
        int nbytes = calcIntBytes(val);
        // sp = log2(nbytes)。
        int sp = 0;
        auto n = nbytes;
        while (n > 1) {
            n >>= 1;
            ++sp;
        }
        out.push_back(static_cast<char>(0x10 | sp));
        appendBE(out, val, nbytes);
        break;
    }
    case BPObjectType::Real: {
        out.push_back('\x23'); // 0x23 = real, 8 bytes。
        std::uint64_t bits{};
        std::memcpy(&bits, &obj.realValue, 8);
        appendBE(out, bits, 8);
        break;
    }
    case BPObjectType::Date: {
        out.push_back('\x33'); // 0x33 = date, 8-byte big-endian double。
        std::uint64_t bits{};
        std::memcpy(&bits, &obj.realValue, 8);
        appendBE(out, bits, 8);
        break;
    }
    case BPObjectType::UID: {
        // 0x8N：低 4 位为字节数 - 1，读方向按 objectInfo + 1 还原。
        const int nbytes = calcIntBytes(obj.intValue);
        out.push_back(static_cast<char>(0x80u | (nbytes - 1)));
        appendBE(out, obj.intValue, nbytes);
        break;
    }
    case BPObjectType::String: {
        if (isAsciiOnly(obj.strValue)) {
            writeLength(out, obj.strValue.size(), 0x50);
            out.append(obj.strValue);
        } else {
            // UTF-16BE 编码。
            std::vector<std::uint16_t> units{};
            auto p = reinterpret_cast<const unsigned char*>(obj.strValue.data());
            auto end = p + obj.strValue.size();
            while (p < end) {
                std::uint32_t cp{};
                if (*p < 0x80) {
                    cp = *p++;
                } else if ((*p & 0xE0) == 0xC0 && p + 1 < end) {
                    cp = (*p++ & 0x1F) << 6;
                    cp |= *p++ & 0x3F;
                } else if ((*p & 0xF0) == 0xE0 && p + 2 < end) {
                    cp = (*p++ & 0x0F) << 12;
                    cp |= (*p++ & 0x3F) << 6;
                    cp |= *p++ & 0x3F;
                } else if ((*p & 0xF8) == 0xF0 && p + 3 < end) {
                    cp = (*p++ & 0x07) << 18;
                    cp |= (*p++ & 0x3F) << 12;
                    cp |= (*p++ & 0x3F) << 6;
                    cp |= *p++ & 0x3F;
                } else {
                    ++p;
                    cp = 0xFFFD;
                }
                if (cp <= 0xFFFF) {
                    units.push_back(static_cast<std::uint16_t>(cp));
                } else {
                    cp -= 0x10000;
                    units.push_back(static_cast<std::uint16_t>(0xD800 | (cp >> 10)));
                    units.push_back(static_cast<std::uint16_t>(0xDC00 | (cp & 0x3FF)));
                }
            }
            writeLength(out, units.size(), 0x60);
            for (auto u : units) appendBE(out, u, 2);
        }
        break;
    }
    case BPObjectType::Data: {
        writeLength(out, obj.strValue.size(), 0x40);
        out.append(obj.strValue);
        break;
    }
    case BPObjectType::Array: {
        writeLength(out, obj.children.size(), 0xA0);
        for (auto idx : obj.children) appendBE(out, idx, objectRefSize);
        break;
    }
    case BPObjectType::Dict: {
        writeLength(out, obj.dictKeys.size(), 0xD0);
        for (auto idx : obj.dictKeys) appendBE(out, idx, objectRefSize);
        for (auto idx : obj.dictValues) appendBE(out, idx, objectRefSize);
        break;
    }
    }
    return startOff;
}

}

/**
 * @brief 将 XML 格式的 plist 字符串转换为 Binary Plist（bplist00）二进制数据。
 */
std::optional<std::string> XMLToBPList(const std::string_view xml) {
    pugi::xml_document doc{};
    auto result = doc.load_buffer(xml.data(), xml.size());
    if (!result) {
        Logger::error("failed to parse XML plist:", result.description());
        return std::nullopt;
    }

    auto plistNode = doc.child(PLIST_TAG_ROOT);
    if (!plistNode) {
        Logger::error("no <plist> root found in XML");
        return std::nullopt;
    }
    // 找到第一个元素子节点，作为根对象。
    pugi::xml_node rootElement{};
    for (auto child = plistNode.first_child(); child; child = child.next_sibling()) {
        if (child.type() == pugi::node_element) {
            rootElement = child;
            break;
        }
    }
    if (!rootElement) {
        Logger::error("no root element under <plist>");
        return std::nullopt;
    }

    std::vector<BPObject> objects{};
    objects.reserve(256);
    auto rootIdx = xmlNodeToBPObject(rootElement, objects);
    auto numObjects = objects.size();

    // 计算 objectRefSize：根据对象总数决定 dict/array 中每个引用占的字节数。
    int objectRefSize = 1;
    if (numObjects > 0xFF) objectRefSize = 2;
    if (numObjects > 0xFFFF) objectRefSize = 4;
    if (numObjects > 0xFFFFFFFFULL) objectRefSize = 8;

    // 序列化对象区。
    std::string out{};
    out.reserve(numObjects * 32 + 256);
    out.append("bplist00", 8);

    std::vector<std::uint64_t> offsets{};
    offsets.reserve(numObjects);
    for (auto&& obj : objects) {
        auto off = writeBPObject(out, obj, objectRefSize);
        offsets.push_back(off);
    }

    // 写入 Offset Table。
    std::uint64_t maxOffset = out.size();
    int offsetIntSize = 1;
    if (maxOffset > 0xFF) offsetIntSize = 2;
    if (maxOffset > 0xFFFF) offsetIntSize = 4;
    if (maxOffset > 0xFFFFFFFFULL) offsetIntSize = 8;

    std::uint64_t offsetTableOffset = out.size();
    for (auto off : offsets) appendBE(out, off, offsetIntSize);

    // 写入 Trailer（32 字节）。
    out.append(6, '\0'); // 6 个保留字节（0x00）。
    out.push_back(static_cast<char>(offsetIntSize));
    out.push_back(static_cast<char>(objectRefSize));
    appendBE(out, numObjects, 8);
    appendBE(out, rootIdx, 8);
    appendBE(out, offsetTableOffset, 8);

    return out;
}

// ===== bplist 原生对象树编辑层 =====
//
// 修改 bplist 时不再走「bplist -> XML -> bplist」重建（XML plist 的 DTD 无法
// 表达 set / ordered set / UID / null / 16 字节整数），而是：
//   1) 把原始 bplist 解析成保留全类型的 BPListNode 树；
//   2) 由该树生成 XML 供上层读取/修改（无法表达的类型降级成固定占位节点）；
//   3) 写回时把新 XML 解析成树，与原生树做结构对齐合并：未变化的分支沿用
//      原生节点（类型与字节原样保留），只有真正被改动的分支采用新节点；
//   4) 从合并后的原生树重新序列化 bplist。
namespace {

enum class BPType : std::uint8_t {
    Null,
    Bool,
    Int,
    Int128,
    Real,
    Date,
    Data,
    String,
    UID,
    Array,
    OrderedSet,
    Set,
    Dict,
};

struct BPListNode {
    BPType type{BPType::Null};
    bool boolValue{};
    std::uint64_t intValue{}; ///< Int / UID
    std::string int128Bytes{}; ///< Int128：16 字节大端原值
    double realValue{}; ///< Real / Date
    std::string strValue{}; ///< String(UTF-8) / Data(原始字节)
    std::vector<BPListNode> items{}; ///< Array / Set / OrderedSet
    std::vector<std::pair<std::string, BPListNode>> dict{}; ///< Dict（保持原始顺序）

    static BPListNode ofBool(const bool v) {
        BPListNode n;
        n.type = BPType::Bool;
        n.boolValue = v;
        return n;
    }
    static BPListNode ofInt(const std::uint64_t v) {
        BPListNode n;
        n.type = BPType::Int;
        n.intValue = v;
        return n;
    }
    static BPListNode ofString(std::string v) {
        BPListNode n;
        n.type = BPType::String;
        n.strValue = std::move(v);
        return n;
    }
    static BPListNode ofData(std::string v) {
        BPListNode n;
        n.type = BPType::Data;
        n.strValue = std::move(v);
        return n;
    }
};

static std::string bpBase64Encode(const std::string_view bytes) {
    static constexpr char kChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out{};
    out.reserve((bytes.size() + 2) / 3 * 4);
    for (std::size_t i{}; i < bytes.size(); i += 3) {
        const auto b0 = static_cast<std::uint8_t>(bytes[i]);
        const auto b1 = i + 1 < bytes.size() ? static_cast<std::uint8_t>(bytes[i + 1]) : 0;
        const auto b2 = i + 2 < bytes.size() ? static_cast<std::uint8_t>(bytes[i + 2]) : 0;
        out += kChars[b0 >> 2];
        out += kChars[((b0 & 0x03) << 4) | (b1 >> 4)];
        out += i + 1 < bytes.size() ? kChars[((b1 & 0x0F) << 2) | (b2 >> 6)] : '=';
        out += i + 2 < bytes.size() ? kChars[b2 & 0x3F] : '=';
    }
    return out;
}

static std::string bpBase64Decode(const std::string_view text) {
    auto val = [](const char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::string out{};
    std::uint32_t buf{};
    int bits{};
    for (auto c : text) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        if (c == '=') break;
        const int v = val(c);
        if (v < 0) continue;
        buf = (buf << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>(buf >> bits & 0xFF));
        }
    }
    return out;
}

/// 读取 bplist 对象的长度字段（内联小长度，或 0x0F 后跟一个 integer 对象）。
struct BPLength {
    std::uint64_t count{};
    std::uint64_t pos{};
};
static bool bpReadLength(const std::uint8_t* d, const std::uint64_t size, const std::uint64_t off,
                         const std::uint8_t info, BPLength& out) {
    out.pos = off + 1;
    if (info != 0x0F) {
        out.count = info;
        return true;
    }
    if (out.pos >= size) return false;
    const auto marker = d[out.pos++];
    if ((marker >> 4) != 0x01) return false;
    const auto nbytes = static_cast<std::uint8_t>(1u << (marker & 0x0F));
    if (nbytes > 8 || out.pos + nbytes > size) return false;
    out.count = bplistReadUInt(d, out.pos, nbytes);
    out.pos += nbytes;
    return true;
}

static bool bpParseObject(const std::uint8_t* d, const std::uint64_t size, const std::vector<std::uint64_t>& table,
                          const std::uint8_t refSize, const std::uint64_t idx, BPListNode& out, const int depth,
                          std::vector<std::uint8_t>& active) {
    if (idx >= table.size() || depth > 64 || active[idx]) return false;
    active[idx] = 1;
    ScopeGuard leave{[&] { active[idx] = 0; }};
    const auto off = table[idx];
    if (off >= size) return false;
    const auto marker = d[off];
    const auto type = static_cast<std::uint8_t>(marker >> 4);
    const auto info = static_cast<std::uint8_t>(marker & 0x0F);

    switch (type) {
    case 0x0:
        out = info == 0x08 ? BPListNode::ofBool(false)
            : info == 0x09 ? BPListNode::ofBool(true)
                           : BPListNode{}; // null / fill
        return true;
    case 0x1: {
        const auto n = 1u << info;
        if (n > 16 || off + 1 + n > size) return false;
        if (n == 16) {
            out = BPListNode{};
            out.type = BPType::Int128;
            out.int128Bytes.assign(reinterpret_cast<const char*>(d + off + 1), 16);
        } else {
            out = BPListNode::ofInt(bplistReadUInt(d, off + 1, static_cast<std::uint8_t>(n)));
        }
        return true;
    }
    case 0x2: {
        const auto n = 1u << info;
        if ((n != 4 && n != 8) || off + 1 + n > size) return false;
        double v{};
        if (n == 4) {
            auto bits = static_cast<std::uint32_t>(bplistReadUInt(d, off + 1, 4));
            float f{};
            std::memcpy(&f, &bits, 4);
            v = f;
        } else {
            auto bits = bplistReadUInt(d, off + 1, 8);
            std::memcpy(&v, &bits, 8);
        }
        out = BPListNode{};
        out.type = BPType::Real;
        out.realValue = v;
        return true;
    }
    case 0x3: {
        if (off + 9 > size) return false;
        const auto bits = bplistReadUInt(d, off + 1, 8);
        double v{};
        std::memcpy(&v, &bits, 8);
        out = BPListNode{};
        out.type = BPType::Date;
        out.realValue = v;
        return true;
    }
    case 0x4:
    case 0x5:
    case 0x6:
    case 0x7: {
        BPLength len{};
        if (!bpReadLength(d, size, off, info, len) || len.count > size - len.pos) return false;
        if (type == 0x4) {
            out = BPListNode::ofData(std::string(reinterpret_cast<const char*>(d + len.pos), len.count));
        } else if (type == 0x7) {
            out = BPListNode::ofString(std::string(reinterpret_cast<const char*>(d + len.pos), len.count));
        } else {
            auto s = bplistStringToUtf8(d, size, off);
            if (!s) return false;
            out = BPListNode::ofString(std::move(*s));
        }
        return true;
    }
    case 0x8: {
        const auto n = static_cast<std::uint8_t>(info + 1);
        if (n > 8 || off + 1 + n > size) return false;
        out = BPListNode{};
        out.type = BPType::UID;
        out.intValue = bplistReadUInt(d, off + 1, n);
        return true;
    }
    case 0xA:
    case 0xB:
    case 0xC: {
        BPLength len{};
        if (!bpReadLength(d, size, off, info, len) || len.count > (size - len.pos) / refSize) return false;
        out = BPListNode{};
        out.type = type == 0xA ? BPType::Array : (type == 0xB ? BPType::OrderedSet : BPType::Set);
        out.items.reserve(static_cast<std::size_t>(len.count));
        for (std::uint64_t i{}; i < len.count; ++i) {
            const auto child = bplistReadUInt(d, len.pos + i * refSize, refSize);
            BPListNode node{};
            if (!bpParseObject(d, size, table, refSize, child, node, depth + 1, active)) return false;
            out.items.push_back(std::move(node));
        }
        return true;
    }
    case 0xD: {
        BPLength len{};
        if (!bpReadLength(d, size, off, info, len) || len.count > (size - len.pos) / (2 * refSize)) return false;
        out = BPListNode{};
        out.type = BPType::Dict;
        for (std::uint64_t i{}; i < len.count; ++i) {
            const auto keyIdx = bplistReadUInt(d, len.pos + i * refSize, refSize);
            const auto valIdx = bplistReadUInt(d, len.pos + (len.count + i) * refSize, refSize);
            if (keyIdx >= table.size()) return false;
            auto key = bplistStringToUtf8(d, size, table[keyIdx]);
            if (!key) return false;
            BPListNode value{};
            if (!bpParseObject(d, size, table, refSize, valIdx, value, depth + 1, active)) return false;
            out.dict.emplace_back(std::move(*key), std::move(value));
        }
        return true;
    }
    default:
        return false;
    }
}

/// 解析完整 bplist 为保留全类型的对象树；失败时返回 nullopt（上层回退旧实现）。
static std::optional<BPListNode> bpParse(const std::string_view bytes) {
    const auto size = bytes.size();
    if (size < 40 || bytes.substr(0, 6) != "bplist") return std::nullopt;
    const auto* d = reinterpret_cast<const std::uint8_t*>(bytes.data());
    const auto t = size - 32;
    const auto offsetIntSize = d[t + 6];
    const auto refSize = d[t + 7];
    if (offsetIntSize == 0 || offsetIntSize > 8 || refSize == 0 || refSize > 8) return std::nullopt;
    const auto numObjects = bplistReadUInt(d, t + 8, 8);
    const auto topObject = bplistReadUInt(d, t + 16, 8);
    const auto tableOff = bplistReadUInt(d, t + 24, 8);
    if (numObjects == 0 || tableOff > t || numObjects > (t - tableOff) / offsetIntSize) return std::nullopt;

    std::vector<std::uint64_t> table{};
    table.reserve(static_cast<std::size_t>(numObjects));
    for (std::uint64_t i{}; i < numObjects; ++i)
        table.push_back(bplistReadUInt(d, tableOff + i * offsetIntSize, offsetIntSize));
    std::vector<std::uint8_t> active(static_cast<std::size_t>(numObjects), 0);
    BPListNode root{};
    if (!bpParseObject(d, size, table, refSize, topObject, root, 0, active)) return std::nullopt;
    return root;
}

/// 展平成对象表；容器内容转为对象引用，节点本身只保留标量。
struct BPFlat {
    BPListNode node{};
    std::vector<std::uint64_t> refs{};
};
static bool bpFlatten(const BPListNode& n, std::vector<BPFlat>& out, const int depth = 0) {
    if (depth > 64 || out.size() > 5000000) return false;
    const auto self = out.size();
    BPFlat f{};
    f.node = n;
    f.node.items.clear();
    f.node.dict.clear();
    out.push_back(std::move(f));
    if (n.type == BPType::Array || n.type == BPType::Set || n.type == BPType::OrderedSet) {
        for (const auto& c : n.items) {
            const auto idx = out.size();
            if (!bpFlatten(c, out, depth + 1)) return false;
            out[self].refs.push_back(idx);
        }
    } else if (n.type == BPType::Dict) {
        // bplist dict 布局：先全部 key 引用，再全部 value 引用。
        std::vector<std::uint64_t> keys{};
        std::vector<std::uint64_t> vals{};
        for (const auto& [k, v] : n.dict) {
            const auto keyIdx = out.size();
            if (!bpFlatten(BPListNode::ofString(k), out, depth + 1)) return false;
            keys.push_back(keyIdx);
            const auto valIdx = out.size();
            if (!bpFlatten(v, out, depth + 1)) return false;
            vals.push_back(valIdx);
        }
        out[self].refs = std::move(keys);
        out[self].refs.insert(out[self].refs.end(), vals.begin(), vals.end());
    }
    return true;
}

/// UTF-8 -> UTF-16BE 单元（含代理对）。
static std::vector<std::uint16_t> bpUtf8ToUtf16(const std::string& s) {
    std::vector<std::uint16_t> units{};
    auto p = reinterpret_cast<const unsigned char*>(s.data());
    const auto end = p + s.size();
    while (p < end) {
        std::uint32_t cp{};
        if (*p < 0x80) {
            cp = *p++;
        } else if ((*p & 0xE0) == 0xC0 && p + 1 < end) {
            cp = (*p++ & 0x1F) << 6;
            cp |= *p++ & 0x3F;
        } else if ((*p & 0xF0) == 0xE0 && p + 2 < end) {
            cp = (*p++ & 0x0F) << 12;
            cp |= (*p++ & 0x3F) << 6;
            cp |= *p++ & 0x3F;
        } else if ((*p & 0xF8) == 0xF0 && p + 3 < end) {
            cp = (*p++ & 0x07) << 18;
            cp |= (*p++ & 0x3F) << 12;
            cp |= (*p++ & 0x3F) << 6;
            cp |= *p++ & 0x3F;
        } else {
            ++p;
            cp = 0xFFFD;
        }
        if (cp <= 0xFFFF) {
            units.push_back(static_cast<std::uint16_t>(cp));
        } else {
            cp -= 0x10000;
            units.push_back(static_cast<std::uint16_t>(0xD800 | (cp >> 10)));
            units.push_back(static_cast<std::uint16_t>(0xDC00 | (cp & 0x3FF)));
        }
    }
    return units;
}

static void bpWriteObject(std::string& out, const BPFlat& f, const int refSize) {
    const auto& n = f.node;
    switch (n.type) {
    case BPType::Null:
        out.push_back('\x00');
        break;
    case BPType::Bool:
        out.push_back(n.boolValue ? '\x09' : '\x08');
        break;
    case BPType::Int: {
        const int nb = calcIntBytes(n.intValue);
        int sp = 0;
        for (int t = nb; t > 1; t >>= 1) ++sp;
        out.push_back(static_cast<char>(0x10 | sp));
        appendBE(out, n.intValue, nb);
        break;
    }
    case BPType::Int128:
        if (n.int128Bytes.size() == 16) {
            out.push_back('\x14'); // 0x1 | log2(16)
            out.append(n.int128Bytes);
        } else {
            out.push_back('\x13'); // 退化成 8 字节 0，保证结构合法
            appendBE(out, 0, 8);
        }
        break;
    case BPType::Real:
    case BPType::Date: {
        out.push_back(n.type == BPType::Real ? '\x23' : '\x33');
        std::uint64_t bits{};
        std::memcpy(&bits, &n.realValue, 8);
        appendBE(out, bits, 8);
        break;
    }
    case BPType::Data:
        writeLength(out, n.strValue.size(), 0x40);
        out.append(n.strValue);
        break;
    case BPType::String: {
        if (isAsciiOnly(n.strValue)) {
            writeLength(out, n.strValue.size(), 0x50);
            out.append(n.strValue);
        } else {
            auto units = bpUtf8ToUtf16(n.strValue);
            writeLength(out, units.size(), 0x60);
            for (auto u : units) appendBE(out, u, 2);
        }
        break;
    }
    case BPType::UID: {
        const int nb = calcIntBytes(n.intValue);
        out.push_back(static_cast<char>(0x80u | (nb - 1)));
        appendBE(out, n.intValue, nb);
        break;
    }
    case BPType::Array:
    case BPType::Set:
    case BPType::OrderedSet: {
        const std::uint8_t tag = n.type == BPType::Array ? 0xA0 : (n.type == BPType::Set ? 0xC0 : 0xB0);
        writeLength(out, f.refs.size(), tag);
        for (auto r : f.refs) appendBE(out, r, refSize);
        break;
    }
    case BPType::Dict:
        writeLength(out, f.refs.size() / 2, 0xD0);
        for (auto r : f.refs) appendBE(out, r, refSize);
        break;
    }
}

static std::string bpSerialize(const BPListNode& root) {
    std::vector<BPFlat> flat{};
    if (!bpFlatten(root, flat) || flat.empty()) return {};
    const auto count = flat.size();
    int refSize = 1;
    if (count > 0xFF) refSize = 2;
    if (count > 0xFFFF) refSize = 4;
    if (count > 0xFFFFFFFFULL) refSize = 8;

    std::string out{};
    out.append("bplist00", 8);
    std::vector<std::uint64_t> offsets{};
    offsets.reserve(count);
    for (const auto& f : flat) {
        offsets.push_back(out.size());
        bpWriteObject(out, f, refSize);
    }
    const auto maxOff = out.size();
    int offSize = 1;
    if (maxOff > 0xFF) offSize = 2;
    if (maxOff > 0xFFFF) offSize = 4;
    if (maxOff > 0xFFFFFFFFULL) offSize = 8;
    const auto tableOff = out.size();
    for (auto o : offsets) appendBE(out, o, offSize);

    out.append(6, '\0');
    out.push_back(static_cast<char>(offSize));
    out.push_back(static_cast<char>(refSize));
    appendBE(out, count, 8);
    appendBE(out, 0, 8); // 根节点恒为对象 0
    appendBE(out, tableOff, 8);
    return out;
}

/// 原生树 -> XML。XML 无法表达的类型输出固定降级占位，写回时靠 bpDegrade 等价
/// 判定识别「上层没动过这个节点」，从而把原生节点原样保留下来。
static void bpNodeToXML(const BPListNode& n, std::string& out, const int depth) {
    const std::string ind(depth, '\t');
    switch (n.type) {
    case BPType::Null:
        out += ind + "<false/>\n";
        break;
    case BPType::Bool:
        out += ind + (n.boolValue ? "<true/>\n" : "<false/>\n");
        break;
    case BPType::Int:
        out += ind + "<integer>" + std::to_string(static_cast<std::int64_t>(n.intValue)) + "</integer>\n";
        break;
    case BPType::Int128:
    case BPType::Set:
    case BPType::OrderedSet:
        out += ind + "<data></data>\n";
        break;
    case BPType::Real:
        out += ind + "<real>" + std::format("{:.17g}", n.realValue) + "</real>\n";
        break;
    case BPType::Date:
        out += ind + "<date>" + bplistDateToISO8601(n.realValue) + "</date>\n";
        break;
    case BPType::Data:
        out += ind + "<data>" + bpBase64Encode(n.strValue) + "</data>\n";
        break;
    case BPType::String:
        out += ind + "<string>" + xmlEscape(n.strValue) + "</string>\n";
        break;
    case BPType::UID:
        out += ind + "<dict>\n";
        out += ind + "\t<key>CF$UID</key>\n";
        out += ind + "\t<integer>" + std::to_string(n.intValue) + "</integer>\n";
        out += ind + "</dict>\n";
        break;
    case BPType::Array:
        out += ind + "<array>\n";
        for (const auto& c : n.items) bpNodeToXML(c, out, depth + 1);
        out += ind + "</array>\n";
        break;
    case BPType::Dict:
        out += ind + "<dict>\n";
        for (const auto& [k, v] : n.dict) {
            out += ind + "\t<key>" + xmlEscape(k) + "</key>\n";
            bpNodeToXML(v, out, depth + 1);
        }
        out += ind + "</dict>\n";
        break;
    }
}

static std::string bpTreeToXMLDoc(const BPListNode& root) {
    std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                      "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                      "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                      "<plist version=\"1.0\">\n";
    bpNodeToXML(root, out, 0);
    out += "</plist>\n";
    return out;
}

/// XML -> 对象树。这里故意不把 dict{CF$UID} 还原成 UID：保持与 bpDegrade(UID)
/// 相同的形态，合并时才能判定「未改动」并沿用原生 UID 节点。
static std::optional<BPListNode> bpParseXMLNode(const pugi::xml_node& node, const int depth = 0) {
    if (depth > 64) return std::nullopt;
    const std::string_view name(node.name());
    BPListNode n{};
    if (name == "true" || name == "false") return BPListNode::ofBool(name == "true");
    if (name == "integer") return BPListNode::ofInt(parsePlistInteger(node.child_value()));
    if (name == "real") {
        n.type = BPType::Real;
        n.realValue = std::strtod(node.child_value(), nullptr);
        return n;
    }
    if (name == "date") {
        n.type = BPType::Date;
        n.realValue = iso8601ToBplistDate(node.child_value()).value_or(0.0);
        return n;
    }
    if (name == "data") return BPListNode::ofData(bpBase64Decode(node.child_value()));
    if (name == "string") return BPListNode::ofString(node.child_value());
    if (name == "array") {
        n.type = BPType::Array;
        for (auto c = node.first_child(); c; c = c.next_sibling()) {
            if (c.type() != pugi::node_element) continue;
            auto child = bpParseXMLNode(c, depth + 1);
            if (!child) return std::nullopt;
            n.items.push_back(std::move(*child));
        }
        return n;
    }
    if (name == "dict") {
        n.type = BPType::Dict;
        for (auto it = node.begin(); it != node.end(); ++it) {
            if (std::string_view(it->name()) != "key") continue;
            std::string key(it->child_value());
            auto val = it->next_sibling();
            while (val && val.type() != pugi::node_element) val = val.next_sibling();
            if (!val) return std::nullopt;
            auto v = bpParseXMLNode(val, depth + 1);
            if (!v) return std::nullopt;
            n.dict.emplace_back(std::move(key), std::move(*v));
            it = val; // 跳过 value 节点
        }
        return n;
    }
    return BPListNode::ofString("");
}

static std::optional<BPListNode> bpXMLToTree(const std::string_view xml) {
    pugi::xml_document doc{};
    if (!doc.load_buffer(xml.data(), xml.size())) return std::nullopt;
    auto plistNode = doc.child(PLIST_TAG_ROOT);
    if (!plistNode) return std::nullopt;
    for (auto c = plistNode.first_child(); c; c = c.next_sibling())
        if (c.type() == pugi::node_element) return bpParseXMLNode(c);
    return std::nullopt;
}

/// 把原生节点降级成它在 XML 中间表示里的形态，用于判断该节点是否未被改动。
static BPListNode bpDegrade(const BPListNode& n) {
    if (n.type == BPType::Null) return BPListNode::ofBool(false);
    if (n.type == BPType::Set || n.type == BPType::OrderedSet || n.type == BPType::Int128)
        return BPListNode::ofData("");
    if (n.type == BPType::UID) {
        BPListNode r{};
        r.type = BPType::Dict;
        r.dict.emplace_back("CF$UID", BPListNode::ofInt(n.intValue));
        return r;
    }
    if (n.type == BPType::Array) {
        BPListNode r{};
        r.type = BPType::Array;
        for (const auto& c : n.items) r.items.push_back(bpDegrade(c));
        return r;
    }
    if (n.type == BPType::Dict) {
        BPListNode r{};
        r.type = BPType::Dict;
        for (const auto& [k, v] : n.dict) r.dict.emplace_back(k, bpDegrade(v));
        return r;
    }
    return n;
}

static bool bpEqual(const BPListNode& a, const BPListNode& b) {
    if (a.type != b.type) return false;
    switch (a.type) {
    case BPType::Null:
        return true;
    case BPType::Bool:
        return a.boolValue == b.boolValue;
    case BPType::Int:
    case BPType::UID:
        return a.intValue == b.intValue;
    case BPType::Int128:
        return a.int128Bytes == b.int128Bytes;
    case BPType::Real:
        return a.realValue == b.realValue; // 17 位有效数字往返可精确复原
    case BPType::Date:
        return std::abs(a.realValue - b.realValue) < 1e-5; // ISO8601 只保留到微秒
    case BPType::Data:
    case BPType::String:
        return a.strValue == b.strValue;
    case BPType::Array:
    case BPType::Set:
    case BPType::OrderedSet:
        if (a.items.size() != b.items.size()) return false;
        for (std::size_t i{}; i < a.items.size(); ++i)
            if (!bpEqual(a.items[i], b.items[i])) return false;
        return true;
    case BPType::Dict:
        if (a.dict.size() != b.dict.size()) return false;
        for (std::size_t i{}; i < a.dict.size(); ++i) {
            if (a.dict[i].first != b.dict[i].first) return false;
            if (!bpEqual(a.dict[i].second, b.dict[i].second)) return false;
        }
        return true;
    }
    return false;
}

/// 结构对齐合并：以 newN（上层编辑结果）为准，未变化的分支沿用 oldN 原生节点。
static BPListNode bpMerge(const BPListNode& oldN, const BPListNode& newN, const int depth = 0) {
    if (bpEqual(bpDegrade(oldN), newN)) return oldN;
    if (depth > 64) return newN;
    if (oldN.type == BPType::Dict && newN.type == BPType::Dict) {
        BPListNode r{};
        r.type = BPType::Dict;
        for (const auto& [k, v] : newN.dict) {
            const BPListNode* o = nullptr;
            for (const auto& [ok, ov] : oldN.dict)
                if (ok == k) {
                    o = &ov;
                    break;
                }
            r.dict.emplace_back(k, o ? bpMerge(*o, v, depth + 1) : v);
        }
        return r;
    }
    if (oldN.type == BPType::Array && newN.type == BPType::Array && oldN.items.size() == newN.items.size()) {
        BPListNode r{};
        r.type = BPType::Array;
        for (std::size_t i{}; i < newN.items.size(); ++i)
            r.items.push_back(bpMerge(oldN.items[i], newN.items[i], depth + 1));
        return r;
    }
    return newN;
}

} // namespace

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

    const auto format = DetectPListFormat(*dataOpt);
    if (format != PListFormat::Binary) {
        // XML（以及按 XML 处理的未知格式）：缓存原始字节与原格式，写回时保持 XML。
        std::lock_guard lock(g_plistSourceMutex);
        g_plistSources[plistCacheKey(filePath)] = PListSourceBytes{*dataOpt, *dataOpt, PListFormat::XML, {}};
        return dataOpt;
    }

    Logger::debug("detected binary plist, parsing native object tree:", filePath.string());
    auto tree = bpParse(*dataOpt);
    std::string xml{};
    if (tree) {
        xml = bpTreeToXMLDoc(*tree);
    } else if (auto fallback = BPListToXML(*dataOpt)) {
        // 原生解析失败时退回旧解析器（不缓存对象树，仍可走格式保持/字节透传）。
        xml = std::move(*fallback);
    }
    if (xml.empty()) return std::nullopt;

    std::shared_ptr<BPListNode> ptr{};
    if (tree) ptr = std::make_shared<BPListNode>(std::move(*tree));
    {
        std::lock_guard lock(g_plistSourceMutex);
        g_plistSources[plistCacheKey(filePath)] = PListSourceBytes{*dataOpt, xml, PListFormat::Binary, std::move(ptr)};
    }
    return xml;
}

/**
 * @brief 把（可能被修改过的）XML plist 写回文件。
 *
 * - Info.plist 强制写成 bplist00：zsign -C 等工具的 plist 解析器只认二进制
 *   plist，XML 的 Info.plist 会读不到 CFBundleExecutable，被判定为「未签名」。
 * - 原文件是 bplist：把新 XML 解析成树，与解析原始字节得到的原生对象树做
 *   结构对齐合并（未改动分支保留 set / UID / null / Int128 等原生类型），
 *   再重新序列化为 bplist。
 * - 其余 plist（InfoPlist.strings 等）：按原格式写回；内容未变时字节级透传。
 */
bool WritePListFile(const std::filesystem::path& filePath, const std::string_view xmlPlist) {
    const bool requireBinary = filePath.filename() == FILE_NAME_PLIST;

    PListSourceBytes cached{};
    bool hit = false;
    {
        std::lock_guard lock(g_plistSourceMutex);
        auto it = g_plistSources.find(plistCacheKey(filePath));
        if (it != g_plistSources.end()) {
            cached = it->second;
            hit = true;
        }
    }

    // 内容未变且已经满足格式要求时，直接写回原始字节（字节级无损）。
    if (hit && cached.xml == xmlPlist && (!requireBinary || cached.format == PListFormat::Binary))
        return WriteFile(filePath, cached.original);

    // 原生对象树打补丁：bplist 特有类型不经过 XML 往返。
    std::string bytes{};
    if (hit && cached.format == PListFormat::Binary && cached.tree) {
        if (auto newTree = bpXMLToTree(xmlPlist)) bytes = bpSerialize(bpMerge(*cached.tree, *newTree));
    }

    // Info.plist（或原本就是 bplist 的文件）必须以 bplist00 落盘。
    if (bytes.empty() && (requireBinary || (hit && cached.format == PListFormat::Binary))) {
        if (auto bpOpt = XMLToBPList(xmlPlist)) bytes = std::move(*bpOpt);
    }
    if (!bytes.empty()) return WriteFile(filePath, bytes);

    // 其余场景：按传入的 XML 文本写回（含无读取记录的新文件）。
    return WriteFile(filePath, xmlPlist);
}

}
