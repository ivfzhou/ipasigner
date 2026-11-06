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
 * @file compress.hpp
 * @brief ZIP 压缩/解压接口声明。
 *
 * 提供 IPA 文件（本质为 ZIP 格式）的解压和压缩功能。
 * 解压支持多线程并行处理，压缩支持目录、普通文件和符号链接。
 */

#ifndef COM_GITEE_IVFZHOU_IPASIGNER_COMPRESS_HPP
#define COM_GITEE_IVFZHOU_IPASIGNER_COMPRESS_HPP

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace com::gitee::ivfzhou::ipasigner {

/**
 * @brief 解压 IPA 文件（ZIP 格式）到指定目录。
 *
 * 使用 libzip 库进行多线程并行解压。解压时按 ZIP 条目的外部属性还原
 * 符号链接和 Unix 权限；Windows 下若无法创建符号链接，则退化为占位文件，
 * 但会在进程内记录链接目标，保证重新打包时仍能写出符号链接条目。
 *
 * @param ipaPath 源 IPA 文件路径（IPA 本质是 ZIP 格式归档文件）。
 * @param destDir 解压目标目录路径（若不存在会自动创建）。
 * @return 成功返回 true，失败返回 false 并输出错误日志。
 */
bool Unzip(const std::filesystem::path& ipaPath, const std::filesystem::path& destDir);

/**
 * @brief 将 IPA 文件夹打包为 IPA 文件（ZIP 格式）。
 *
 * 递归遍历目录下的所有文件、子目录和符号链接条目，按标准 IPA/ZIP 格式输出。
 * 普通文件使用 DEFLATE，符号链接以 STORE 方式写入并保留 S_IFLNK 外部属性；
 * 每个条目的 Unix 权限按解压时记录的原始属性还原（主 Mach-O 的可执行位不会丢失）。
 * 采用分块流式压缩（内存占用与 IPA 大小无关），并在条目大小 / 偏移 / 数量超过
 * 传统 ZIP 上限时自动写出 ZIP64 extra field、ZIP64 EOCD record 与 locator。
 *
 * @param ipaDir 待打包的 IPA 目录路径（即解压后的根目录，其下应包含 Payload 等子目录）。
 * @param outputPath 输出的 IPA 文件路径（若已存在将被覆盖）。
 * @return 成功返回 true，失败返回 false 并输出错误日志。
 */
bool Zip(const std::filesystem::path& ipaDir, const std::filesystem::path& outputPath, int compressLevel);

/**
 * @brief 判断 path 是否为符号链接条目，并返回链接目标（UTF-8、'/' 分隔）。
 *
 * 真实符号链接（POSIX / Windows 开发者模式）与 Windows 上无法建链时写出的
 * 占位文件都返回 true，使不同系统下 CodeResources 与 ZIP 打包的行为一致。
 */
bool IsZipSymlinkEntry(const std::filesystem::path& path, std::string& target);

/**
 * @brief 返回条目在原始 IPA 中的 Unix 权限位（低 12 位），未知时返回 0。
 */
std::uint16_t ZipEntryUnixPerms(const std::filesystem::path& path);

/**
 * @brief 将路径转换为 UTF-8 字符串（Windows 下显式按 UTF-16 -> UTF-8 转换）。
 */
std::string PathToUtf8(const std::filesystem::path& path);

/// 将路径转成以 '/' 分隔的 UTF-8 字符串（ZIP 条目名 / CodeResources key）。
std::string PathToUtf8Generic(const std::filesystem::path& path);

/// 将 UTF-8（'/' 分隔）的归档内路径还原为文件系统路径（Windows 下按 UTF-16 构造）。
std::filesystem::path Utf8ToPath(std::string_view utf8);

}

#endif
