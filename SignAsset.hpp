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
 * @file SignAsset.hpp
 * @brief 签名资产数据结构定义。
 *
 * 定义了 SignAsset 类，用于聚合签名过程中所需的全部资源和中间数据，
 * 包括描述文件内容、证书、团队 ID、权限配置、解压路径、签名信息树等。
 * 该类在 DoSign 流程中作为核心数据载体贯穿整个签名过程。
 */

#ifndef IPASIGNER_SIGNASSET_HPP
#define IPASIGNER_SIGNASSET_HPP

#include <filesystem>
#include <map>
#include <string>

#include "SignInfo.hpp"
#include "crypto.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 签名资产类，聚合签名流程中所需的全部资源。
 */
class SignAsset final {
  public:
    /// 描述文件（.mobileprovision）的原始二进制内容。
    std::string provision;

    /// 从描述文件中提取的 plist XML 内容。
    std::string plist;

    /// 开发者团队 ID（从描述文件 plist 的 TeamIdentifier 字段获取）。
    std::string teamId;

    /// 从描述文件 plist 中提取的权限配置（Entitlements）XML 片段。
    std::string plistEntitlements;

    /// 签名证书的通用名称（Common Name），用于日志和标识。
    std::string certificateName;

    /// 签名证书的私钥和 X509 证书对。
    std::pair<EvpPkeyPtr, X509Ptr> certificate;

    /// 插件（.appex）对应的描述文件内容映射，键为插件名称，值为描述文件二进制内容。
    std::map<std::string, std::string> appxProvisions;

    /// 插件对应的 Bundle ID 映射，键为插件名称，值为从描述文件中解析出的 Bundle ID。
    std::map<std::string, std::string> appxProvisionBundleIds;

    /// IPA 解压后的临时目录路径。
    std::filesystem::path ipaDir;

    /// 签名后输出的 IPA 文件路径。
    std::filesystem::path ipaOutputPath;

    /// 解压后找到的 .app 目录路径。
    std::filesystem::path appDir;

    /// 签名信息树（根节点为主 .app，子节点为插件和框架）。
    SignInfo signInfo;

    /// 动态库加载路径（如 @executable_path/xxx.dylib），空表示不注入。
    std::string dylibPath;

    /// 是否弱注入动态库。
    bool weakInject{};

    int compressLevel{};
};

}

#endif
