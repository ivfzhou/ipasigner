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
std::string WrapperPListXMLTag(const std::string_view s) { return std::string("<plist>") + s.data() + "</plist>"; }

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

}
