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

#ifndef IPASIGNER_COMPRESS_HPP
#define IPASIGNER_COMPRESS_HPP

#include <filesystem>

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 解压 IPA 文件（ZIP 格式）到指定目录。
 *
 * 使用 libzip 库进行多线程并行解压，支持 ZIP_BUFFER_SIZE 大小的缓冲区读取。
 * 解压过程中会自动创建目标目录结构，保留文件权限和符号链接。
 *
 * @param ipaPath 源 IPA 文件路径（IPA 本质是 ZIP 格式归档文件）。
 * @param destDir 解压目标目录路径（若不存在会自动创建）。
 * @return 成功返回 true，失败返回 false 并输出错误日志。
 */
bool Unzip(const std::filesystem::path& ipaPath, const std::filesystem::path& destDir);

/**
 * @brief 将 IPA 文件夹打包为 IPA 文件（ZIP 格式）。
 *
 * 递归遍历目录下的所有文件、子目录和符号链接，
 * 按照标准 IPA/ZIP 格式压缩输出。使用 DEFLATE 算法压缩普通文件，
 * 符号链接以存储方式写入。Payload 目录作为 IPA 的根内容。
 *
 * @param ipaDir 待打包的 IPA 目录路径（即解压后的根目录，其下应包含 Payload 等子目录）。
 * @param outputPath 输出的 IPA 文件路径（若已存在将被覆盖）。
 * @return 成功返回 true，失败返回 false 并输出错误日志。
 */
bool Zip(const std::filesystem::path& ipaDir, const std::filesystem::path& outputPath);

}

#endif
