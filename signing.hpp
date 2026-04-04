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
 * @file signing.hpp
 * @brief 代码签名 slot 构建与 Mach-O 签名接口声明。
 *
 * 提供构建 Apple CodeSignature 各 Slot 的函数：
 * - Requirements Slot
 * - Entitlements Slot / DER Entitlements Slot
 * - CodeDirectory Slot（SHA1 / SHA256）
 * - CMS Signature Slot
 * - SuperBlob 组装
 *
 * 以及 Mach-O 文件签名的顶层接口。
 */

#ifndef IPASIGNER_SIGNING_HPP
#define IPASIGNER_SIGNING_HPP

#include <filesystem>
#include <string_view>

namespace gitee::com::ivfzhou::ipasigner {

/// 签名单个 Mach-O 文件（支持 Fat Binary）。
bool SignMachOFile(const std::filesystem::path& filePath, X509* cert, EVP_PKEY* pkey, std::string_view bundleId,
                   std::string_view teamId, std::string_view subjectCN, std::string_view entitlements,
                   std::string_view infoPlistSHA1, std::string_view infoPlistSHA256,
                   std::string_view codeResourcesData);

/// 向 Mach-O 文件注入动态库加载命令。
/// @param filePath Mach-O 文件路径。
/// @param dylibPath dylib 加载路径（如 @executable_path/xxx.dylib）。
/// @param weakInject true 使用 LC_LOAD_WEAK_DYLIB，false 使用 LC_LOAD_DYLIB。
bool InjectDyLib(const std::filesystem::path& filePath, std::string_view dylibPath, bool weakInject);

}

#endif
