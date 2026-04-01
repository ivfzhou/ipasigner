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
 * @file Configuration.hpp
 * @brief 签名配置类声明。
 *
 * 定义了 Configuration 类，用于承载从 YAML 配置文件中解析出的所有签名参数，
 * 包括 IPA 文件路径、证书信息、描述文件、Bundle 修改选项、能力配置等。
 * 同时提供 YAML 序列化/反序列化支持和配置校验函数。
 */

#ifndef IPASIGNER_CONFIGURATION_HPP
#define IPASIGNER_CONFIGURATION_HPP

#include <map>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include <yaml-cpp/yaml.h>

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 签名配置类，对应 YAML 配置文件中的所有字段。
 *
 * 每个成员变量对应 config.yml 中的一个配置项。
 */
class Configuration final {
    /// 友元函数，用于将配置格式化输出到流。
    friend std::ostream& operator<<(std::ostream& out, const Configuration& cfg);

  public:
    /// 待签名的 IPA 文件路径。
    std::string ipaFilePath;

    /// 签名后输出的 IPA 文件路径。
    std::string destinationIpaFilePath;

    /// 签名证书文件路径（支持 PEM、DER、PKCS#12 格式）。
    std::string certificateFilePath;

    /// 签名证书密码（用于 PKCS#12 解密）。
    std::string certificatePassword;

    /// 描述文件（.mobileprovision）路径。
    std::string mobileProvisionFilePath;

    /// 动态库（.dylib）文件路径，用于注入。
    std::string dylibFilePath;

    /// 是否使用弱注入方式加载动态库。
    bool weakInject{};

    /// Universal Link 域名列表，会添加到 Entitlements 的 associated-domains 中。
    std::vector<std::string> universalLinkDomains;

    /// Associated Domain 关联域名列表，会添加到 Entitlements 的 associated-domains 中。
    std::vector<std::string> associatedDomains;

    /// 钥匙串访问组列表，会添加到 Entitlements 的 keychain-access-groups 中。
    std::vector<std::string> keychainGroups;

    /// 苹果安全应用组列表，会添加到 Entitlements 的 application-groups 中。
    std::vector<std::string> securityGroups;

    /// 插件（.appex）对应的子描述文件映射，键为插件名称，值为描述文件路径。
    std::map<std::string, std::string> appxProvisions;

    /// 新的 Bundle ID，用于替换原有的 CFBundleIdentifier。
    std::string newBundleId;

    /// 新的 Bundle 名称，用于替换 CFBundleName 和 CFBundleDisplayName。
    std::string newBundleName;

    /// 新的 Bundle 版本号，用于替换 CFBundleVersion 和 CFBundleShortVersionString。
    std::string newBundleVersion;

    /// 要添加/修改的 Info.plist 键值对，支持点号分隔的嵌套路径。
    std::map<std::string, std::string> addPlistStringKey;

    /// 要从 Info.plist 中移除的键列表，支持点号分隔的嵌套路径。
    std::vector<std::string> removePlistStringKey;

    /// 要在 .app 目录下创建的附加文件名。
    std::string additionalFileName;

    /// 附加文件的内容。
    std::string additionalFileData;
};

/**
 * @brief 解析 YAML 配置文件。
 * @param filePath YAML 配置文件路径。
 * @return 成功返回 Configuration 对象，失败返回 std::nullopt。
 */
std::optional<Configuration> ParseYAMLConfiguration(std::string_view filePath);

/**
 * @brief 校验配置参数的合法性。
 *
 * 检查文件是否存在、路径是否合法、列表是否包含空串等。
 *
 * @param cfg 待校验的配置对象。
 * @return 校验通过返回 true，否则返回 false。
 */
bool ValidateYAMLConfiguration(const Configuration& cfg);

}

namespace YAML {

using namespace gitee::com::ivfzhou;

/**
 * @brief yaml-cpp 序列化/反序列化特化，实现 Configuration 与 YAML 节点的互转。
 */
template <> struct convert<ipasigner::Configuration> final {
    /**
     * @brief 将 Configuration 对象序列化为 YAML 节点。
     * @param cfg 配置对象。
     * @return YAML 节点。
     */
    static Node encode(const ipasigner::Configuration& cfg);

    /**
     * @brief 从 YAML 节点反序列化为 Configuration 对象。
     * @param node YAML 节点。
     * @param cfg 输出的配置对象。
     * @return 成功返回 true。
     */
    static bool decode(const Node& node, ipasigner::Configuration& cfg);
};

}

#endif
