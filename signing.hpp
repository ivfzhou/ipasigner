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

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "crypto.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/// 构建 Requirements Slot 二进制数据。
std::string SlotBuildRequirements(std::string_view bundleId, std::string_view subjectCN);

/// 构建 Entitlements Slot（XML plist 格式 + magic header）。
std::string SlotBuildEntitlements(std::string_view entitlements);

/// 构建 DER 格式 Entitlements Slot。
std::string SlotBuildDerEntitlements(std::string_view entitlements);

/// 构建 CodeDirectory Slot。
/// @param bAlternate true 表示 SHA256（alternate），false 表示 SHA1。
/// @param codeBase 代码区基地址指针。
/// @param codeLength 代码区长度。
/// @param execSegLimit __TEXT segment 的 vmsize。
/// @param execSegFlags execSeg 标志位（如含 get-task-allow）。
/// @param bundleId Bundle ID。
/// @param teamId 团队 ID。
/// @param infoPlistSHA Special Slot 的 Info.plist 哈希（原始二进制）。
/// @param requirementsSHA Special Slot 的 Requirements 哈希。
/// @param codeResourcesSHA Special Slot 的 CodeResources 哈希。
/// @param entitlementsSHA Special Slot 的 Entitlements 哈希。
/// @param derEntitlementsSHA Special Slot 的 DER Entitlements 哈希。
/// @param isExecuteArch 是否为可执行架构（影响 Special Slots 数量）。
std::string SlotBuildCodeDirectory(bool bAlternate, const std::uint8_t* codeBase, std::uint32_t codeLength,
                                   std::uint64_t execSegLimit, std::uint64_t execSegFlags, std::string_view bundleId,
                                   std::string_view teamId, std::string_view infoPlistSHA,
                                   std::string_view requirementsSHA, std::string_view codeResourcesSHA,
                                   std::string_view entitlementsSHA, std::string_view derEntitlementsSHA,
                                   bool isExecuteArch);

/// 构建 CMS 签名 Slot。
std::optional<std::string> SlotBuildCMSSignature(X509* cert, EVP_PKEY* pkey, std::string_view codeDirectorySlot,
                                                 std::string_view alternateCodeDirectorySlot);

/// 组装完整的 CodeSignature SuperBlob。
std::string BuildCodeSignature(X509* cert, EVP_PKEY* pkey, const std::uint8_t* codeBase, std::uint32_t codeLength,
                               std::uint64_t execSegLimit, bool isExecute, std::string_view bundleId,
                               std::string_view teamId, std::string_view subjectCN, std::string_view entitlements,
                               std::string_view infoPlistSHA1, std::string_view infoPlistSHA256,
                               std::string_view codeResourcesSHA1, std::string_view codeResourcesSHA256);

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

/// 计算原始二进制 SHA 哈希（非十六进制字符串）。
std::string SHARaw(int hashType, const void* data, std::size_t size);

/// 计算数据的 SHA1 和 SHA256 原始二进制哈希。
std::pair<std::string, std::string> SHASumRaw(std::string_view data);

/// 计算文件的 SHA1 和 SHA256 并做 Base64 编码。
std::pair<std::string, std::string> SHASumBase64File(const std::filesystem::path& filePath);

/// 计算数据的 SHA1 和 SHA256 并做 Base64 编码。
std::pair<std::string, std::string> SHASumBase64(std::string_view data);

}

#endif
