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
 * @file common.hpp
 * @brief 通用工具函数接口声明。
 *
 * 提供项目中广泛使用的通用工具函数，包括：
 * - 字节序交换（大端/小端转换）
 * - 文件读写操作
 * - 错误信息获取（OpenSSL、libzip）
 * - IPA 包目录查找
 * - 字符串处理（去空白、替换、大小写比较）
 * - plist XML 标签包装/拆包
 * - 列表合并（去重/不去重）
 * - 目录创建和 Bundle ID 校验
 */

#ifndef IPASIGNER_COMMON_HPP
#define IPASIGNER_COMMON_HPP

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gitee::com::ivfzhou::ipasigner {

// 交换 16 位无符号整数的字节序（大端 <-> 小端），即交换高低两个字节的位置。
std::uint16_t Swap(std::uint16_t value);

// 交换 32 位无符号整数的字节序（大端 <-> 小端）。
// 第一步：交换每对相邻字节（奇偶字节互换）；第二步：交换前后两个半字（16 位）。
std::uint32_t Swap(std::uint32_t value);

// 交换 64 位无符号整数的字节序（大端 <-> 小端）。
// 第一步：交换前后两个 32 位半部分；第二步：在每个 32 位内交换前后两个 16 位；第三步：在每个 16 位内交换前后两个字节。
std::uint64_t Swap(std::uint64_t value);

// 交换 32 位无符号整数的字节序（大端 <-> 小端），功能与 Swap(uint32_t) 相同。
std::uint32_t SwapInt32(std::uint32_t value);

// 读取文件内容。
std::optional<std::string> ReadFile(const std::filesystem::path& filePath);

// 写入文件内容。
bool WriteFile(const std::filesystem::path& filePath, std::string_view data);

// 获取 OpenSSL 错误栈中的错误信息，以 std::string 形式返回。
std::string GetOpensslErrors();

// 打印 zip 错误信息。
std::string GetZipErrors(int err);

// 查找解压后的 ipa 文件夹中第一个以 .app 结尾的文件夹，返回其绝对路径。
std::optional<std::filesystem::path> FindIPAAppFolder(const std::filesystem::path& ipaDir);

// 寻找文件夹下以 .app 或 .appx 结尾的文件夹。
std::optional<std::vector<std::filesystem::path>> FindIPAPluginFolders(const std::filesystem::path& appDir);

// 去除字符串首尾的空白字符。
std::string StringTrimBlank(std::string_view value);

// 忽略大小写比较两个 C 字符串是否相等。
bool StringEqualIgnoreCase(std::string_view a, std::string_view b);

// 将字符串 str 中所有出现的子串 from 替换为 to。
void StringReplaceAll(std::string& str, std::string_view from, std::string_view to);

// 包裹 plist 标签。
std::string WrapperPListXMLTag(std::string_view s);

// 去除 plist 标签。
std::string UnwrapPListXMLTag(std::string_view s);

/// plist 文件格式枚举。
enum class PListFormat { XML, Binary, Unknown };

/**
 * @brief 检测 plist 数据的格式（XML / Binary / Unknown）。
 * @param data plist 文件的原始二进制数据。
 * @return 检测到的格式类型。
 */
PListFormat DetectPListFormat(std::string_view data);

/**
 * @brief 将 Binary Plist 数据转换为 XML 格式的 plist 字符串。
 *
 * 解析 Apple Binary Plist（bplist00）格式，递归遍历对象表，
 * 生成等价的 XML plist 输出。支持 dict、array、string、integer、real、
 * boolean、data、date 等数据类型。
 *
 * @param data Binary Plist 的原始二进制数据。
 * @return 成功返回 XML 格式 plist 字符串，失败返回 std::nullopt。
 */
std::optional<std::string> BPListToXML(std::string_view data);

/**
 * @brief 读取 plist 文件并确保返回 XML 格式。
 *
 * 先以二进制模式读取文件内容，检测格式后：
 * - 若为 XML 格式则直接返回
 * - 若为 Binary Plist 格式则自动转换为 XML 后返回
 * - 若格式未知则尝试作为 XML 返回
 *
 * @param filePath plist 文件路径。
 * @return 成功返回 XML 格式 plist 字符串，失败返回 std::nullopt。
 */
std::optional<std::string> ReadPListAsXML(const std::filesystem::path& filePath);

// 合并两个列表，不去重。
/**
 * @brief 合并两个列表，不去重。
 * @tparam R 输入范围类型（需满足 input_range）。
 * @param a 第一个列表。
 * @param b 第二个列表。
 * @return 合并后的 vector，元素顺序为 a 的元素在前，b 的元素在后。
 */
template <std::ranges::input_range R> auto MergeList(R&& a, R&& b) {
    using T = std::ranges::range_value_t<R>;
    std::vector<T> result{};
    if constexpr (std::ranges::sized_range<R>) {
        result.reserve(std::ranges::size(a) + std::ranges::size(b));
    }
    for (auto&& val : std::forward<R>(a)) result.push_back(std::move(val));
    for (auto&& val : std::forward<R>(b)) result.push_back(std::move(val));
    return result;
}

// 合并两个列表并去重，保留原始顺序。
/**
 * @brief 合并两个列表并去重，保留原始顺序。
 * @tparam R 输入范围类型（需满足 forward_range 且元素可比较）。
 * @param a 第一个列表。
 * @param b 第二个列表。
 * @return 去重后的 vector，元素按首次出现的顺序排列。
 */
template <std::ranges::forward_range R>
    requires std::equality_comparable<std::ranges::range_value_t<R>>
auto MergeListUnique(R&& a, R&& b) {
    using T = std::ranges::range_value_t<R>;
    std::vector<T> result{};
    for (auto&& val : std::forward<R>(a)) {
        if (std::ranges::find(result, val) == result.end()) result.push_back(val);
    }
    for (auto&& val : std::forward<R>(b)) {
        if (std::ranges::find(result, val) == result.end()) result.push_back(val);
    }
    return result;
}

// 创建文件夹，若文件夹已存在则打印警告日志不做处理。
bool MakeDir(const std::filesystem::path& dirPath, std::filesystem::perms perm);

// 校验 bundle 格式。
bool IsInvalidBundleValue(std::string_view bundle);

}

#endif
