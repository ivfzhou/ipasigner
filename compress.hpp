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

// 解压 IPA 文件到指定目录。
// ipaPath: IPA 文件路径。
// destDir: 解压目标目录路径。
// 返回值：成功返回 true，失败返回 false。
bool Unzip(const std::filesystem::path& ipaPath, const std::filesystem::path& destDir);

// 将 IPA 文件夹打包为 IPA 文件（ZIP 格式）。
// ipaDir: 待打包的 IPA 文件夹路径（即解压后的根目录，其下应包含 Payload 等目录）。
// outputPath: 输出的 IPA 文件路径。
// 返回值：成功返回 true，失败返回 false。
bool Zip(const std::filesystem::path& ipaDir, const std::filesystem::path& outputPath);

}

#endif
