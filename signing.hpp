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

#include <openssl/types.h>

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 签名单个 Mach-O 文件（支持 Fat Binary 多架构）。
 *
 * 读取文件后根据 Mach-O magic 判断类型（Fat / 32位 / 64位），
 * 对每个架构构建完整的 CodeSignature SuperBlob 并写入文件。
 *
 * @param filePath 待签名的 Mach-O 文件路径（.app 内的可执行文件或 .dylib）。
 * @param cert 用于签名的 X509 证书指针（调用方负责生命周期管理）。
 * @param pkey 对应的私钥指针（调用方负责生命周期管理）。
 * @param bundleId 应用的 Bundle ID 标识符，可为空字符串（如签名 dylib 时）。
 * @param teamId 团队标识符（Team ID），可为空字符串。
 * @param subjectCN 签名证书的主体通用名称（用于 Requirements 表达式），可为空字符串。
 * @param entitlements 权限配置 XML 内容，仅主可执行文件需要非空值。
 * @param infoPlistSHA1 Info.plist 文件的 SHA1 原始哈希（20 字节二进制数据）。
 * @param infoPlistSHA256 Info.plist 文件的 SHA256 原始哈希（32 字节二进制数据）。
 * @param codeResourcesData CodeResources plist 文件的原始内容（用于资源完整性校验）。
 * @return 成功返回 true，失败返回 false 并输出错误日志。
 */
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
