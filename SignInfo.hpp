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
 * @file SignInfo.hpp
 * @brief 签名信息数据结构定义。
 *
 * 定义了 SignInfo 类，用于描述 IPA 包中每个可签名组件（.app、.appex、.framework 等）
 * 的签名相关信息，包括 Bundle ID、可执行文件名、plist 哈希值、子组件列表等。
 * 该结构以树形方式组织，根节点为主 .app，子节点为插件和框架。
 */

#ifndef IPASIGNER_SIGNINFO_HPP
#define IPASIGNER_SIGNINFO_HPP

#include <string>
#include <vector>

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 签名信息类，描述一个可签名组件的元数据。
 *
 * 以树形结构组织：主 .app 为根节点，其下的 .appex、.framework 等为子节点。
 * 每个节点记录了签名所需的关键信息。
 */
class SignInfo final {
  public:
    /// 组件相对于根 .app 目录的路径（根节点为 "/"）。
    std::string path;

    /// Bundle ID（CFBundleIdentifier）。
    std::string bundleId;

    /// Bundle 版本号（CFBundleVersion）。
    std::string bundleVersion;

    /// 可执行文件名（CFBundleExecutable）。
    std::string execute;

    /// Info.plist 文件的 SHA1 哈希值（十六进制字符串）。
    std::string plistSha1;

    /// Info.plist 文件的 SHA256 哈希值（十六进制字符串）。
    std::string plistSha256;

    /// 显示名称（优先取 CFBundleDisplayName，其次 CFBundleName）。
    std::string name;

    /// 子组件列表（.appex、.framework、.xctest 等）。
    std::vector<SignInfo> folders;

    /// 需要签名的独立文件列表（如 .dylib 文件）。
    std::vector<std::string> files;

    /// 所有需要记录到 CodeResources 中的已变更文件路径列表。
    std::vector<std::string> changed;
};

}

#endif
