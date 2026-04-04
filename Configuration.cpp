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
 * @file Configuration.cpp
 * @brief 签名配置类实现。
 *
 * 实现 YAML 配置文件的解析、校验以及 yaml-cpp 的序列化/反序列化。
 * 校验逻辑包括文件存在性检查、路径合法性检查、列表空串检查等。
 */

#include <exception>
#include <filesystem>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include <yaml-cpp/yaml.h>

#include "Configuration.hpp"
#include "Logger.tpp"
#include "constants.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 友元函数，将 Configuration 对象以 YAML 格式输出到流。
 * @param out 输出流。
 * @param cfg 配置对象。
 * @return 输出流的引用。
 */
std::ostream& operator<<(std::ostream& out, const Configuration& cfg) {
    return out << YAML::convert<Configuration>::encode(cfg) << std::endl;
}

/**
 * @brief 解析 YAML 配置文件。
 *
 * 使用 yaml-cpp 库加载并解析指定路径的 YAML 文件。
 *
 * @param filePath YAML 配置文件路径。
 * @return 成功返回 Configuration 对象，失败返回 std::nullopt。
 */
std::optional<Configuration> ParseYAMLConfiguration(const std::string_view filePath) {
    try {
        // 解析 yaml 配置文件。
        return YAML::LoadFile(filePath.data()).as<Configuration>();
    } catch (const std::exception& e) {
        Logger::error("failed to parse yaml configuration file:", e.what());
        return std::nullopt;
    }
}

/**
 * @brief 校验配置参数的合法性。
 *
 * 校验内容包括：
 * - 源 IPA 文件存在且为普通文件
 * - 输出路径不是目录
 * - 证书文件和描述文件存在
 * - dylib 文件存在（若配置了）
 * - 插件描述文件存在
 * - 各列表不包含空串
 * - 附加文件名和内容配对
 *
 * @param cfg 待校验的配置对象。
 * @return 校验通过返回 true，否则返回 false。
 */
bool ValidateYAMLConfiguration(const Configuration& cfg) {
    // 检查源 ipa 文件是否存在且合法。
    auto ipaFilePath = std::filesystem::absolute(std::filesystem::path(cfg.ipaFilePath));
    if (!std::filesystem::exists(ipaFilePath)) {
        Logger::error("ipa file not found:", cfg.ipaFilePath);
        return false;
    }
    if (!std::filesystem::is_regular_file(ipaFilePath)) {
        Logger::error("ipa file is not a regular file:", cfg.ipaFilePath);
        return false;
    }

    // 检查输出 ipa 文件路径是否合法。
    if (auto destinationIpaFilePath = std::filesystem::absolute(std::filesystem::path(cfg.destinationIpaFilePath));
        std::filesystem::exists(destinationIpaFilePath)) {
        if (std::filesystem::is_directory(destinationIpaFilePath)) {
            Logger::error("destination ipa file is a directory:", cfg.destinationIpaFilePath);
            return false;
        }
        Logger::warn("destination ipa file exists, will overwrite the file:", cfg.destinationIpaFilePath);
    }

    // 校验证书文件是否存在。
    auto certificateFilePath = std::filesystem::absolute(std::filesystem::path(cfg.certificateFilePath));
    if (!std::filesystem::exists(certificateFilePath)) {
        Logger::error("certificate file not found:", cfg.certificateFilePath);
        return false;
    }
    if (!std::filesystem::is_regular_file(certificateFilePath)) {
        Logger::error("certificate file is not a regular file:", cfg.certificateFilePath);
        return false;
    }

    // 校验描述文件是否存在。
    auto mobileProvisionFilePath = std::filesystem::absolute(std::filesystem::path(cfg.mobileProvisionFilePath));
    if (!std::filesystem::exists(mobileProvisionFilePath)) {
        Logger::error("mobile provision file not found:", cfg.mobileProvisionFilePath);
        return false;
    }
    if (!std::filesystem::is_regular_file(mobileProvisionFilePath)) {
        Logger::error("mobile provision file is not a regular file:", cfg.mobileProvisionFilePath);
        return false;
    }

    // 检查 dylib 文件。
    if (!cfg.dylibFilePath.empty()) {
        auto dylibFilePath = std::filesystem::absolute(std::filesystem::path(cfg.dylibFilePath));
        if (!std::filesystem::exists(dylibFilePath)) {
            Logger::error("dylib file not found:", cfg.dylibFilePath);
            return false;
        }
        if (!std::filesystem::is_regular_file(dylibFilePath)) {
            Logger::error("dylib file is not a regular file:", cfg.dylibFilePath);
            return false;
        }
    }

    // 不能存在空串，文件存在。
    for (auto&& [key, value] : cfg.appxProvisions) {
        if (key.empty()) {
            Logger::error("appx provisions has empty key");
            return false;
        }
        auto filePath = std::filesystem::absolute(value);
        if (!std::filesystem::exists(filePath)) {
            Logger::error("appx provision file not found:", filePath);
            return false;
        }
        if (!std::filesystem::is_regular_file(filePath)) {
            Logger::error("mobile provision file is not a regular file:", filePath);
            return false;
        }
    }

    // 不能存在空串。
    for (auto&& v : cfg.universalLinkDomains) {
        if (v.empty()) {
            Logger::error("universal link domains has empty element");
            return false;
        }
    }

    // 不能存在空串。
    for (auto&& v : cfg.associatedDomains) {
        if (v.empty()) {
            Logger::error("associated domains has empty element");
            return false;
        }
    }

    // 不能存在空串。
    for (auto&& v : cfg.keychainGroups) {
        if (v.empty()) {
            Logger::error("keychain groups has empty element");
            return false;
        }
    }

    // 不能存在空串。
    for (auto&& v : cfg.securityGroups) {
        if (v.empty()) {
            Logger::error("security groups has empty elemment");
            return false;
        }
    }

    // 校验附加文件名和文件内容。
    if (cfg.additionalFileName.empty() && !cfg.additionalFileData.empty()) {
        Logger::error("additional file name is empty, but additional file data has value, will be no effect");
    }

    if (!cfg.additionalFileName.empty() && cfg.additionalFileData.empty()) {
        Logger::error("additional file data is empty, but additional file name has value, will be no effect");
    }

    return true;
}

}

namespace YAML {

using namespace gitee::com::ivfzhou;

/**
 * @brief 从 YAML 节点中获取字符串值。
 * @param node YAML 节点。
 * @param key 键名。
 * @return 字符串值，不存在则返回空字符串。
 * @throws std::runtime_error 若节点存在但类型不是标量。
 */
static std::string getString(const Node& node, const std::string& key) {
    if (node[key]) {
        if (node[key].IsScalar()) return node[key].as<std::string>();

        if (!node[key].IsNull()) throw std::runtime_error(key + " should be a scalar type");
    }

    return {};
}

/**
 * @brief 从 YAML 节点中获取字符串数组值。
 * @param node YAML 节点。
 * @param key 键名。
 * @return 字符串数组，不存在则返回空数组。
 * @throws std::runtime_error 若节点存在但类型不是序列。
 */
static std::vector<std::string> getStringVector(const Node& node, const std::string& key) {
    if (node[key]) {
        if (node[key].IsSequence()) return node[key].as<std::vector<std::string>>();

        if (!node[key].IsNull()) throw std::runtime_error(key + " should be a sequence type");
    }

    return {};
}

/**
 * @brief 从 YAML 节点中获取字符串映射值。
 * @param node YAML 节点。
 * @param key 键名。
 * @return 字符串映射，不存在则返回空映射。
 * @throws std::runtime_error 若节点存在但类型不是映射。
 */
static std::map<std::string, std::string> getStringMap(const Node& node, const std::string& key) {
    if (node[key]) {
        if (node[key].IsMap()) return node[key].as<std::map<std::string, std::string>>();

        if (!node[key].IsNull()) throw std::runtime_error(key + " should be a map type");
    }

    return {};
}

/**
 * @brief 从 YAML 节点中获取布尔值。
 * @param node YAML 节点。
 * @param key 键名。
 * @return 布尔值，不存在则返回 false。
 * @throws std::runtime_error 若节点存在但类型不是标量。
 */
static bool getBool(const Node& node, const std::string& key) {
    if (node[key]) {
        if (node[key].IsScalar()) return node[key].as<bool>();

        if (!node[key].IsNull()) throw std::runtime_error(key + " should be a scalar type");
    }

    return {};
}

/// 将 Configuration 对象序列化为 YAML 节点。
Node convert<ipasigner::Configuration>::encode(const ipasigner::Configuration& cfg) {
    Node node{};
    node[ipasigner::YAML_FIELD_IPA_FILE_PATH] = cfg.ipaFilePath;
    node[ipasigner::YAML_FIELD_DESTINATION_IPA_FILE_PATH] = cfg.destinationIpaFilePath;
    node[ipasigner::YAML_FIELD_CERTIFICATE_FILE_PATH] = cfg.certificateFilePath;
    node[ipasigner::YAML_FIELD_CERTIFICATE_PASSWORD] = cfg.certificatePassword;
    node[ipasigner::YAML_FIELD_MOBILE_PROVISION_FILE_PATH] = cfg.mobileProvisionFilePath;
    node[ipasigner::YAML_FIELD_DYLIB_FILE_PATH] = cfg.dylibFilePath;
    node[ipasigner::YAML_FIELD_WEAK_INJECT] = cfg.weakInject;
    node[ipasigner::YAML_FIELD_UNIVERSAL_LINK_DOMAINS] = cfg.universalLinkDomains;
    node[ipasigner::YAML_FIELD_ASSOCIATED_DOMAINS] = cfg.associatedDomains;
    node[ipasigner::YAML_FIELD_KEYCHAIN_GROUPS] = cfg.keychainGroups;
    node[ipasigner::YAML_FIELD_SECURITY_GROUPS] = cfg.securityGroups;
    node[ipasigner::YAML_FIELD_APPX_PROVISIONS] = cfg.appxProvisions;
    node[ipasigner::YAML_FIELD_NEW_BUNDLE_ID] = cfg.newBundleId;
    node[ipasigner::YAML_FIELD_NEW_BUNDLE_NAME] = cfg.newBundleName;
    node[ipasigner::YAML_FIELD_NEW_BUNDLE_VERSION] = cfg.newBundleVersion;
    node[ipasigner::YAML_FIELD_ADD_PLIST_STRING_KEY] = cfg.addPlistStringKey;
    node[ipasigner::YAML_FIELD_REMOVE_PLIST_STRING_KEY] = cfg.removePlistStringKey;
    node[ipasigner::YAML_FIELD_ADDITIONAL_FILE_NAME] = cfg.additionalFileName;
    node[ipasigner::YAML_FIELD_ADDITIONAL_FILE_DATA] = cfg.additionalFileData;
    return node;
}

/// 从 YAML 节点反序列化为 Configuration 对象。
bool convert<ipasigner::Configuration>::decode(const Node& node, ipasigner::Configuration& cfg) {
    cfg.ipaFilePath = getString(node, ipasigner::YAML_FIELD_IPA_FILE_PATH);
    cfg.destinationIpaFilePath = getString(node, ipasigner::YAML_FIELD_DESTINATION_IPA_FILE_PATH);
    cfg.certificateFilePath = getString(node, ipasigner::YAML_FIELD_CERTIFICATE_FILE_PATH);
    cfg.certificatePassword = getString(node, ipasigner::YAML_FIELD_CERTIFICATE_PASSWORD);
    cfg.mobileProvisionFilePath = getString(node, ipasigner::YAML_FIELD_MOBILE_PROVISION_FILE_PATH);
    cfg.dylibFilePath = getString(node, ipasigner::YAML_FIELD_DYLIB_FILE_PATH);
    cfg.weakInject = getBool(node, ipasigner::YAML_FIELD_WEAK_INJECT);
    cfg.universalLinkDomains = getStringVector(node, ipasigner::YAML_FIELD_UNIVERSAL_LINK_DOMAINS);
    cfg.associatedDomains = getStringVector(node, ipasigner::YAML_FIELD_ASSOCIATED_DOMAINS);
    cfg.keychainGroups = getStringVector(node, ipasigner::YAML_FIELD_KEYCHAIN_GROUPS);
    cfg.securityGroups = getStringVector(node, ipasigner::YAML_FIELD_SECURITY_GROUPS);
    cfg.appxProvisions = getStringMap(node, ipasigner::YAML_FIELD_APPX_PROVISIONS);
    cfg.newBundleId = getString(node, ipasigner::YAML_FIELD_NEW_BUNDLE_ID);
    cfg.newBundleName = getString(node, ipasigner::YAML_FIELD_NEW_BUNDLE_NAME);
    cfg.newBundleVersion = getString(node, ipasigner::YAML_FIELD_NEW_BUNDLE_VERSION);
    cfg.addPlistStringKey = getStringMap(node, ipasigner::YAML_FIELD_ADD_PLIST_STRING_KEY);
    cfg.removePlistStringKey = getStringVector(node, ipasigner::YAML_FIELD_REMOVE_PLIST_STRING_KEY);
    cfg.additionalFileName = getString(node, ipasigner::YAML_FIELD_ADDITIONAL_FILE_NAME);
    cfg.additionalFileData = getString(node, ipasigner::YAML_FIELD_ADDITIONAL_FILE_DATA);
    return true;
}

}
