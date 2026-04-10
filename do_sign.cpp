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
 * @file do_sign.cpp
 * @brief IPA 签名主流程实现。
 *
 * 实现了完整的 IPA 重签名流程，主要步骤包括：
 * 1. 解析 YAML 配置文件并校验参数
 * 2. 读取描述文件并提取 plist、团队 ID、权限配置
 * 3. 解析签名证书（私钥 + X509）
 * 4. 解压 IPA 文件
 * 5. 修改 Bundle ID、Bundle 名称、版本号、plist 配置
 * 6. 写入描述文件、注入动态库、创建附加文件
 * 7. 收集签名信息并执行代码签名
 * 8. 重新打包为 IPA 文件
 * 9. 清理临时文件
 *
 * 每个步骤封装为独立的 static 函数，通过返回退出码指示成功或失败。
 */

#include <filesystem>
#include <format>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "Configuration.hpp"
#include "Logger.tpp"
#include "SignAsset.hpp"
#include "SignInfo.hpp"
#include "arguments.hpp"
#include "common.hpp"
#include "compress.hpp"
#include "crypto.hpp"
#include "do_sign.hpp"
#include "plist.hpp"
#include "signing.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 解析并校验 YAML 配置文件。
 * @param cfg 输出的配置对象。
 * @param filePath YAML 配置文件路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int getYAMLConfiguration(Configuration& cfg, const std::string& filePath) {
    // 解析 yaml 配置文件。
    Logger::info("parse yaml configuration file:", filePath);
    auto cfgOpt = ParseYAMLConfiguration(filePath);
    if (!cfgOpt) return EXIT_CODE_PARSE_CONFIGURATION_ERROR;

    // 校验 yaml 配置文件。
    Logger::info("verify configuration file");
    if (!ValidateYAMLConfiguration(*cfgOpt)) return EXIT_CODE_VALIDATE_CONFIGURATION_ERROR;

    cfg = std::move(*cfgOpt);
    return 0;
}

/**
 * @brief 读取描述文件（.mobileprovision）的原始二进制内容。
 * @param provision 输出的描述文件内容。
 * @param filePath 描述文件路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int readProvisionFile(std::string& provision, const std::string& filePath) {
    // 读取描述文件。
    Logger::info("read mobile provision file:", filePath);
    auto provisionDataOpt = ReadFile(filePath);
    if (!provisionDataOpt) {
        Logger::error("failed to read provision file:", filePath);
        return EXIT_CODE_READ_FILE_ERROR;
    }

    provision = std::move(*provisionDataOpt);
    return 0;
}

/**
 * @brief 从描述文件中提取 CMS 签名的 plist 数据。
 * @param plist 输出的 plist XML 字符串。
 * @param provision 描述文件的原始二进制内容。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int getProvisionPList(std::string& plist, const std::string& provision) {
    // 获取描述文件的 plist 内容。
    Logger::info("get provision plist data");
    auto cmsContentOpt = GetCMSFromProvision(provision);
    if (!cmsContentOpt) {
        Logger::error("failed to get plist data from provision");
        return EXIT_CODE_READ_PLIST_ERROR;
    }

    plist = std::move(*cmsContentOpt);
    return 0;
}

/**
 * @brief 从 plist 中提取团队 ID（TeamIdentifier）。
 * @param teamId 输出的团队 ID。
 * @param plist 描述文件的 plist XML 内容。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int getTeamIdFromPList(std::string& teamId, const std::string& plist) {
    // 获取 teamId。
    Logger::info("get team id from plist");
    auto teamIdsOpt = GetPListArrayString(plist, PLIST_KEY_TEAM_IDENTIFIER);
    if (!teamIdsOpt || teamIdsOpt->empty()) {
        Logger::error("team id not found in plist");
        return EXIT_CODE_TEAM_ID_NOT_FOUND;
    }
    teamId = teamIdsOpt->front();
    if (teamId.empty()) {
        Logger::error("team id is empty");
        return EXIT_CODE_TEAM_ID_NOT_FOUND;
    }
    Logger::info("team id is", teamId);

    return 0;
}

/**
 * @brief 从 plist 中提取权限配置（Entitlements），并根据配置添加能力项。
 *
 * 将 universalLinkDomains 和 associatedDomains 合并后添加到 associated-domains，
 * 将 keychainGroups 添加到 keychain-access-groups，
 * 将 securityGroups 添加到 application-groups。
 *
 * @param plistEntitlements 输出的权限配置 XML 片段。
 * @param plist 描述文件的 plist XML 内容。
 * @param universalLinkDomains Universal Link 域名列表。
 * @param associatedDomains Associated Domain 域名列表。
 * @param keychainGroups 钥匙串访问组列表。
 * @param securityGroups 安全应用组列表。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int getPListEntitlements(std::string& plistEntitlements, const std::string& plist,
                                const std::vector<std::string>& universalLinkDomains,
                                const std::vector<std::string>& associatedDomains,
                                const std::vector<std::string>& keychainGroups,
                                const std::vector<std::string>& securityGroups) {
    // 获取能力项信息。
    Logger::info("get entitlements from plist");
    auto plistEntitlementsOpt = GetPListXMLValue(plist, PLIST_KEY_ENTITLEMENTS);
    if (!plistEntitlementsOpt) {
        Logger::error("plist entitlements not found in plist:", plist);
        return EXIT_CODE_READ_PLIST_ERROR;
    }
    plistEntitlements = std::move(*plistEntitlementsOpt);

    // 如果列表都是空就不处理。
    if (universalLinkDomains.empty() && associatedDomains.empty() && keychainGroups.empty() && securityGroups.empty())
        return 0;

    // 添加 universal link。
    Logger::info("update plist entitlements");
    auto plistTmp = WrapperPListXMLTag(plistEntitlements);
    if (auto list = MergeList(universalLinkDomains, associatedDomains);
        !list.empty() && !SetPListArrayString(plistTmp, PLIST_KEY_ASSOCIATED_DOMAINS, list)) {
        Logger::error("failed to add universal links to plist entitlements:", plistTmp);
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }
    if (!keychainGroups.empty() && !SetPListArrayString(plistTmp, PLIST_KEY_KEYCHAIN_ACCESS_GROUPS, keychainGroups)) {
        Logger::error("failed to add keychain groups to plist entitlements:", plistTmp);
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }
    if (!securityGroups.empty() && !SetPListArrayString(plistTmp, PLIST_KEY_APPLICATION_GROUPS, securityGroups)) {
        Logger::error("failed to add security groups to plist entitlements:", plistTmp);
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }

    plistEntitlements = UnwrapPListXMLTag(plistTmp);
    return 0;
}

/**
 * @brief 解析证书文件，提取私钥和 X509 证书。
 * @param certificate 输出的 (私钥, X509证书) 对。
 * @param filePath 证书文件路径。
 * @param password 证书密码。
 * @param plist 描述文件的 plist XML 内容（用于匹配证书）。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int parseCertificate(std::pair<EvpPkeyPtr, X509Ptr>& certificate, const std::string& filePath,
                            const std::string& password, const std::string& plist) {
    // 读取证书文件。
    Logger::info("read certificate file:", filePath);
    auto certificateDataOpt = ReadFile(filePath);
    if (!certificateDataOpt) {
        Logger::error("failed to read certificate file:", filePath);
        return EXIT_CODE_READ_FILE_ERROR;
    }

    // 获取 plist 中的证书数据。
    Logger::info("get certificates from plist");
    auto plistCertificatesOpt = GetPListArrayString(plist, PLIST_KEY_DEVELOPER_CERTIFICATES);
    Logger::info("plist certificates number", plistCertificatesOpt ? plistCertificatesOpt->size() : 0);

    // 解析证书。
    Logger::info("parse certificates");
    auto plistCertificates = plistCertificatesOpt ? *plistCertificatesOpt : std::vector<std::string>{};
    auto certificateOpt = ParseCertificate(*certificateDataOpt, password, plistCertificates);
    if (!certificateOpt) {
        Logger::error("failed to parse certificate");
        return EXIT_CODE_PARSE_CERTIFICATE_ERROR;
    }

    certificate = std::move(*certificateOpt);
    return 0;
}

/**
 * @brief 获取证书的通用名称（Common Name）。
 * @param certificateName 输出的证书名称。
 * @param certificate 证书对（私钥 + X509）。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int getCertificateName(std::string& certificateName, const std::pair<EvpPkeyPtr, X509Ptr>& certificate) {
    // 提取证书的通用名称（Common Name），后续可能用于签名标记或日志。
    Logger::info("get certificate common name");
    auto subjectOpt = GetCommonNameFromCertificate(certificate.second.get());
    if (!subjectOpt) {
        Logger::error("failed to get certificate common name");
        return EXIT_CODE_PARSE_CERTIFICATE_ERROR;
    }
    Logger::info("certificate common name is", *subjectOpt);

    certificateName = std::move(*subjectOpt);
    return 0;
}

/**
 * @brief 读取插件对应的描述文件内容。
 * @param appxProvisions 输出的插件名称到描述文件内容的映射。
 * @param appNameToFilePath 插件名称到描述文件路径的映射。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int readAppxProvisionFile(std::map<std::string, std::string>& appxProvisions,
                                 const std::map<std::string, std::string>& appNameToFilePath) {
    // 读取描述文件。
    Logger::info("get appx provisions");
    for (auto&& [key, value] : appNameToFilePath) {
        auto fileDataOpt = ReadFile(value);
        if (!fileDataOpt) {
            Logger::error("failed to read provision file:", key, value);
            return EXIT_CODE_READ_FILE_ERROR;
        }
        appxProvisions[key] = std::move(*fileDataOpt);
    }

    return 0;
}

/**
 * @brief 从插件描述文件中提取 Bundle ID。
 * @param appxProvisionBundleIds 输出的插件名称到 Bundle ID 的映射。
 * @param appxProvisions 插件名称到描述文件内容的映射。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int getAppxProvisionBundleIds(std::map<std::string, std::string>& appxProvisionBundleIds,
                                     const std::map<std::string, std::string>& appxProvisions) {
    // 获取描述文件的 bundle。
    Logger::info("get appx provision bundles");
    for (auto&& [key, value] : appxProvisions) {
        auto plistOpt = GetCMSFromProvision(value);
        if (!plistOpt) {
            Logger::error("failed to get plist from profile:", key);
            return EXIT_CODE_READ_PLIST_ERROR;
        }
        auto entitlementsOpt = GetPListXMLValue(*plistOpt, PLIST_KEY_ENTITLEMENTS);
        if (!entitlementsOpt) {
            Logger::error("failed to get plist entitlements from plist:", key);
            return EXIT_CODE_READ_PLIST_ERROR;
        }
        auto bundleIdOpt = GetPListString(WrapperPListXMLTag(*entitlementsOpt), PLIST_KEY_APPLICATION_IDENTIFIER);
        if (!bundleIdOpt) {
            Logger::error("failed to get bundle:", key);
            return EXIT_CODE_BUNDLE_NOT_FOUND;
        }
        Logger::info("appx is", key, "bundle id is", *bundleIdOpt);
        appxProvisionBundleIds[key] = std::move(*bundleIdOpt);
    }

    return 0;
}

/**
 * @brief 解压 IPA 文件到临时目录。
 *
 * 在系统临时目录下创建以 IPA 文件名命名的子目录，
 * 若已存在则自动追加数字后缀避免冲突。
 *
 * @param ipaDir 输出的解压目录路径。
 * @param filePath IPA 文件路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int unzipIPAFile(std::filesystem::path& ipaDir, const std::string& filePath) {
    // 寻找空闲文件夹。
    ipaDir = std::filesystem::temp_directory_path() / std::filesystem::path(filePath).stem();
    auto baseName = std::filesystem::path(filePath).stem().string();
    for (int i = 1; std::filesystem::exists(ipaDir); i++) {
        ipaDir = std::filesystem::temp_directory_path() / (baseName + "_" + std::to_string(i));
    }

    // 解压 ipa 文件。
    Logger::info("ipa extracted to", ipaDir.string());
    if (!Unzip(filePath, ipaDir)) {
        Logger::error("failed to extract ipa file:", filePath);
        return EXIT_CODE_READ_FILE_ERROR;
    }

    return 0;
}

/**
 * @brief 在解压目录中查找 .app 目录。
 * @param appDir 输出的 .app 目录路径。
 * @param ipaDir IPA 解压后的根目录。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int findAppDir(std::filesystem::path& appDir, const std::filesystem::path& ipaDir) {
    // 查找 .app 文件夹。
    auto appDirOpt = FindIPAAppFolder(ipaDir);
    if (!appDirOpt) {
        Logger::error(".app folder not found in directory:", ipaDir.string());
        return EXIT_CODE_READ_FILE_ERROR;
    }
    Logger::info("found .app directory:", appDirOpt->string());

    appDir = std::move(*appDirOpt);
    return 0;
}

/**
 * @brief 修改主应用和插件的 Bundle ID。
 *
 * 若配置了新的 Bundle ID，则：
 * 1. 修改主应用的 CFBundleIdentifier
 * 2. 遍历所有插件，替换其 Bundle ID（使用插件描述文件或字符串替换）
 * 3. 同步修改 WKCompanionAppBundleIdentifier 等关联字段
 * 4. 应用 addPlistStringKey 和 removePlistStringKey 配置
 *
 * @param bundleId 新的 Bundle ID，空字符串表示不修改。
 * @param appDir .app 目录路径。
 * @param appxProvisions 插件描述文件内容映射。
 * @param appxProvisionBundleIds 插件 Bundle ID 映射。
 * @param addPlistStringKey 要添加的 plist 键值对。
 * @param removePlistStringKey 要移除的 plist 键列表。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int updateBundleIdIfNeed(const std::string& bundleId, const std::filesystem::path& appDir,
                                const std::map<std::string, std::string>& appxProvisions,
                                const std::map<std::string, std::string>& appxProvisionBundleIds,
                                const std::map<std::string, std::string>& addPlistStringKey,
                                const std::vector<std::string>& removePlistStringKey) {
    if (bundleId.empty()) return 0;

    Logger::info("modify bundle id:", bundleId);

    // 获取 plist。
    auto plistOpt = ReadPListAsXML(appDir / FILE_NAME_PLIST);
    if (!plistOpt) {
        Logger::error("failed to read plist file:", appDir / FILE_NAME_PLIST);
        return EXIT_CODE_READ_FILE_ERROR;
    }
    auto plist = std::move(*plistOpt);

    // 获取 bundle id。
    auto oldBundleIdOpt = GetPListString(plist, PLIST_KEY_CF_BUNDLE_IDENTIFIER);
    if (!oldBundleIdOpt) {
        Logger::error("bundle id not found:", appDir / FILE_NAME_PLIST);
        return EXIT_CODE_BUNDLE_NOT_FOUND;
    }

    // bundleId 写入文件。
    if (!SetPListString(plist, PLIST_KEY_CF_BUNDLE_IDENTIFIER, bundleId)) {
        Logger::error("failed to set plist value");
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }
    if (!WriteFile(appDir / FILE_NAME_PLIST, plist)) {
        Logger::error("failed to write plist file:", appDir / FILE_NAME_PLIST);
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    // 获取插件文件夹。
    auto pluginAppDirsOpt = FindIPAPluginFolders(appDir);
    if (!pluginAppDirsOpt) return 0;

    // 修改插件的 bundle id。
    for (auto&& pluginAppDir : *pluginAppDirsOpt) {
        Logger::info("found plugin directory:", pluginAppDir.string());

        auto pluginAppPlistOpt = ReadPListAsXML(pluginAppDir / FILE_NAME_PLIST);
        if (!pluginAppPlistOpt) {
            Logger::warn("no plist file found:", pluginAppDir);
            continue;
        }
        auto pluginAppPlist = std::move(*pluginAppPlistOpt);

        auto pluginAppBundleIdOpt = GetPListString(pluginAppPlist, PLIST_KEY_CF_BUNDLE_IDENTIFIER);
        auto pluginAppBundleId = pluginAppBundleIdOpt ? *pluginAppBundleIdOpt : "";

        if (auto appName = pluginAppDir.stem().string(); appxProvisionBundleIds.contains(appName)) {
            pluginAppBundleId = appxProvisionBundleIds.at(appName);
            if (!WriteFile(pluginAppDir / FILE_NAME_EMBEDDED_MOBILEPROVISION, appxProvisions.at(appName))) {
                Logger::error("failed to write plugin plist file:", pluginAppDir / FILE_NAME_EMBEDDED_MOBILEPROVISION);
                return EXIT_CODE_WRITE_FILE_ERROR;
            }
        } else {
            StringReplaceAll(pluginAppBundleId, *oldBundleIdOpt, bundleId);
        }
        if (!SetPListString(pluginAppPlist, PLIST_KEY_CF_BUNDLE_IDENTIFIER, pluginAppBundleId)) {
            Logger::error("failed to set plugin app plist bundle");
            return EXIT_CODE_WRITE_PLIST_ERROR;
        }

        if (auto OldWkBundleIdOpt = GetPListString(pluginAppPlist, PLIST_KEY_WK_COMPANION_APP_BUNDLE_IDENTIFIER)) {
            std::string newWKCBundleId = *OldWkBundleIdOpt;
            StringReplaceAll(newWKCBundleId, *oldBundleIdOpt, bundleId);
            if (!SetPListString(pluginAppPlist, PLIST_KEY_WK_COMPANION_APP_BUNDLE_IDENTIFIER, newWKCBundleId)) {
                Logger::error("failed to set plugin app plist wk bundle");
                return EXIT_CODE_WRITE_PLIST_ERROR;
            }
        }

        // 添加和移除 plist 键值对。
        auto key = std::format("{}.{}.{}", PLIST_KEY_NS_EXTENSION, PLIST_KEY_NS_EXTENSION_ATTRIBUTES,
                               PLIST_KEY_WK_APP_BUNDLE_IDENTIFIER);
        if (addPlistStringKey.contains(key)) {
            if (auto nsExtensionOpt = GetPListXMLValue(pluginAppPlist, PLIST_KEY_NS_EXTENSION)) {
                auto nsExtensionPlist = WrapperPListXMLTag(*nsExtensionOpt);
                if (auto nsExtensionAttributesOpt =
                        GetPListXMLValue(nsExtensionPlist, PLIST_KEY_NS_EXTENSION_ATTRIBUTES)) {
                    auto nsExtensionAttributesPlist = WrapperPListXMLTag(*nsExtensionAttributesOpt);
                    auto wkAppBundleIdentifierOpt =
                        GetPListString(nsExtensionAttributesPlist, PLIST_KEY_WK_APP_BUNDLE_IDENTIFIER);
                    if (wkAppBundleIdentifierOpt) {
                        if (!SetPListString(nsExtensionAttributesPlist, PLIST_KEY_WK_APP_BUNDLE_IDENTIFIER,
                                            addPlistStringKey.at(key))) {
                            Logger::error("failed to update plugin app plist");
                            return EXIT_CODE_WRITE_PLIST_ERROR;
                        }
                        if (!SetPListXMLValue(nsExtensionPlist, PLIST_KEY_NS_EXTENSION_ATTRIBUTES,
                                              UnwrapPListXMLTag(nsExtensionAttributesPlist))) {
                            Logger::error("failed to update plugin app plist");
                            return EXIT_CODE_WRITE_PLIST_ERROR;
                        }
                        if (!SetPListXMLValue(pluginAppPlist, PLIST_KEY_NS_EXTENSION,
                                              UnwrapPListXMLTag(nsExtensionPlist))) {
                            Logger::error("failed to update plugin app plist");
                            return EXIT_CODE_WRITE_PLIST_ERROR;
                        }
                    }
                }
            }
        }
        for (auto&& [first, second] : addPlistStringKey) {
            if (first == key) continue;

            if (!SetPListStringByChain(pluginAppPlist, first, second))
                Logger::warn("failed to update plugin app plist,", "key is", first, "value is", second);
        }
        for (auto&& v : removePlistStringKey) {
            if (!DeletePListStringByChain(pluginAppPlist, v))
                Logger::warn("failed to remove plugin app plist,", "key is", v);
        }

        // 修改后的 plist 写回文件。
        if (!WriteFile(pluginAppDir / FILE_NAME_PLIST, pluginAppPlist)) {
            Logger::error("failed to write plugin app plist");
            return EXIT_CODE_WRITE_FILE_ERROR;
        }
    }

    return 0;
}

/**
 * @brief 修改应用的 Bundle 名称（CFBundleName 和 CFBundleDisplayName）。
 * @param bundleName 新的 Bundle 名称，空字符串表示不修改。
 * @param appDir .app 目录路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int updateBundleNameIfNeed(const std::string& bundleName, const std::filesystem::path& appDir) {
    if (bundleName.empty()) return 0;

    // 读取 plist。
    auto plistOpt = ReadPListAsXML(appDir / FILE_NAME_PLIST);
    if (!plistOpt) {
        Logger::error("failed to read plist/xml file:", appDir / FILE_NAME_PLIST);
        return EXIT_CODE_READ_FILE_ERROR;
    }
    auto plist = std::move(*plistOpt);

    // 修改 plist。
    if (!SetPListString(plist, PLIST_KEY_CF_BUNDLE_NAME, bundleName)) {
        Logger::error("failed to append plist/xml file");
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }
    if (!SetPListString(plist, PLIST_KEY_CF_BUNDLE_DISPLAY_NAME, bundleName)) {
        Logger::error("failed to append plist/xml file");
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }

    // 写回 plist。
    if (!WriteFile(appDir / FILE_NAME_PLIST, plist)) {
        Logger::error("failed to write plist file:", appDir / FILE_NAME_PLIST);
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    return 0;
}

/**
 * @brief 修改应用的 Bundle 版本号（CFBundleVersion 和 CFBundleShortVersionString）。
 * @param bundleVersion 新的版本号，空字符串表示不修改。
 * @param appDir .app 目录路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int updateBundleVersionIfNeed(const std::string& bundleVersion, const std::filesystem::path& appDir) {
    if (bundleVersion.empty()) return 0;

    // 读取 plist。
    auto plistOpt = ReadPListAsXML(appDir / FILE_NAME_PLIST);
    if (!plistOpt) {
        Logger::error("failed to read plist/xml file:", appDir / FILE_NAME_PLIST);
        return EXIT_CODE_READ_FILE_ERROR;
    }
    auto plist = std::move(*plistOpt);

    // 修改 plist。
    if (!SetPListString(plist, PLIST_KEY_CF_BUNDLE_VERSION, bundleVersion)) {
        Logger::error("failed to append plist/xml file");
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }
    if (!SetPListString(plist, PLIST_KEY_CF_BUNDLE_SHORT_VERSION_STRING, bundleVersion)) {
        Logger::error("failed to append plist/xml file");
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }

    // 写回 plist。
    if (!WriteFile(appDir / FILE_NAME_PLIST, plist)) {
        Logger::error("failed to write plist file:", appDir / FILE_NAME_PLIST);
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    return 0;
}

/**
 * @brief 根据配置添加/移除主应用 Info.plist 中的键值对。
 * @param appDir .app 目录路径。
 * @param addPlistStringKey 要添加的键值对。
 * @param removePlistStringKey 要移除的键列表。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int updatePList(const std::filesystem::path& appDir, const std::map<std::string, std::string>& addPlistStringKey,
                       const std::vector<std::string>& removePlistStringKey) {
    // 读取 plist。
    auto plistOpt = ReadPListAsXML(appDir / FILE_NAME_PLIST);
    if (!plistOpt) {
        Logger::error("failed to read plist/xml file:", (appDir / FILE_NAME_PLIST).string());
        return EXIT_CODE_READ_FILE_ERROR;
    }
    auto plist = std::move(*plistOpt);

    // 修改 plist。
    auto key = std::format("{}.{}.{}", PLIST_KEY_NS_EXTENSION, PLIST_KEY_NS_EXTENSION_ATTRIBUTES,
                           PLIST_KEY_WK_APP_BUNDLE_IDENTIFIER);
    for (auto&& [first, second] : addPlistStringKey) {
        if (first == key) continue;

        if (!SetPListStringByChain(plist, first, second))
            Logger::warn("failed to update app plist,", "key is", first, "value is", second);
    }
    for (auto&& v : removePlistStringKey) {
        if (!DeletePListStringByChain(plist, v)) Logger::warn("failed to remove app plist,", "key is", v);
    }

    // 写回 plist。
    if (!WriteFile(appDir / FILE_NAME_PLIST, plist)) {
        Logger::error("failed to write plugin app plist:", (appDir / FILE_NAME_PLIST).string());
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    return 0;
}

/**
 * @brief 修改中文本地化文件（zh_CN.lproj/InfoPlist.strings）中的显示名称。
 * @param bundleName 新的 Bundle 名称，空字符串表示不修改。
 * @param appDir .app 目录路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int updateZhLocaleFile(const std::string& bundleName, const std::filesystem::path& appDir) {
    if (bundleName.empty()) return 0;

    // 读取文件。
    auto plistOpt = ReadPListAsXML(appDir / FILE_PATH_IPA_ZH_LOCALE);
    if (!plistOpt) {
        Logger::warn("no", FILE_PATH_IPA_ZH_LOCALE, "found");
        return 0;
    }
    auto plist = std::move(*plistOpt);

    // 修改文件。
    if (!SetPListString(plist, PLIST_KEY_CF_BUNDLE_NAME, bundleName)) {
        Logger::error("failed to set plist/xml file");
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }
    if (!SetPListString(plist, PLIST_KEY_CF_BUNDLE_DISPLAY_NAME, bundleName)) {
        Logger::error("failed to set plist/xml file");
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }

    // 写回文件。
    if (!WriteFile(appDir / FILE_PATH_IPA_ZH_LOCALE, plist)) {
        Logger::error("failed to write plist file:", appDir / FILE_PATH_IPA_ZH_LOCALE);
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    return 0;
}

/**
 * @brief 修改新版中文本地化文件（zh-Hans.lproj/InfoPlist.strings）中的显示名称。
 * @param bundleName 新的 Bundle 名称，空字符串表示不修改。
 * @param appDir .app 目录路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int updateNewZhLocaleFile(const std::string& bundleName, const std::filesystem::path& appDir) {
    if (bundleName.empty()) return 0;

    // 读取文件。
    auto plistOpt = ReadPListAsXML(appDir / FILE_PATH_NEW_IPA_ZH_LOCALE);
    if (!plistOpt) {
        Logger::warn("no", FILE_PATH_NEW_IPA_ZH_LOCALE, "found");
        return 0;
    }
    auto plist = std::move(*plistOpt);

    // 修改文件。
    if (!SetPListString(plist, PLIST_KEY_CF_BUNDLE_NAME, bundleName)) {
        Logger::error("failed to set plist/xml file");
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }
    if (!SetPListString(plist, PLIST_KEY_CF_BUNDLE_DISPLAY_NAME, bundleName)) {
        Logger::error("failed to set plist/xml file");
        return EXIT_CODE_WRITE_PLIST_ERROR;
    }

    // 写回文件。
    if (!WriteFile(appDir / FILE_PATH_NEW_IPA_ZH_LOCALE, plist)) {
        Logger::error("failed to write plist file:", appDir / FILE_PATH_NEW_IPA_ZH_LOCALE);
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    return 0;
}

/**
 * @brief 将描述文件复制到 .app 目录下（embedded.mobileprovision）。
 * @param appDir .app 目录路径。
 * @param provisionFilePath 描述文件路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int writeProvisionFile(const std::filesystem::path& appDir, const std::string& provisionFilePath) {
    auto fileOpt = ReadFile(provisionFilePath);
    if (!fileOpt) {
        Logger::error("failed to read provision file:", provisionFilePath);
        return EXIT_CODE_READ_FILE_ERROR;
    }

    if (!WriteFile(appDir / FILE_NAME_EMBEDDED_MOBILEPROVISION, *fileOpt)) {
        Logger::error("failed to write provision file:", (appDir / FILE_NAME_EMBEDDED_MOBILEPROVISION).string());
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    return 0;
}

/**
 * @brief 删除 .app 目录下的原有代码签名目录（_CodeSignature）。
 *
 * 在重新签名前必须清除旧签名，否则可能导致签名冲突或验证失败。
 * 同时删除 _CodeSignature/CodeResources 等遗留文件。
 *
 * @param appDir .app 目录路径。
 */
static void removeCodeSignatureFolder(const std::filesystem::path& appDir) {
    std::filesystem::remove_all(appDir / FILE_NAME_CODE_RESOURCES);
}

/**
 * @brief 在 .app 目录下创建附加文件。
 *
 * 若文件已存在则拒绝创建，避免覆盖原有文件。
 *
 * @param appDir .app 目录路径。
 * @param additionFileName 附加文件名，空字符串表示不创建。
 * @param additionFileData 附加文件内容。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int createAdditionFile(const std::filesystem::path& appDir, const std::string& additionFileName,
                              const std::string& additionFileData) {
    if (additionFileName.empty() || additionFileData.empty()) return 0;

    Logger::info("create additional file:", (appDir / additionFileName).string());

    // 判断文件不存在，避免覆盖已有的文件。
    if (std::filesystem::exists(appDir / additionFileName)) {
        Logger::error("addition file already exists:", (appDir / additionFileName).string());
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    // 创建文件。
    if (!WriteFile(appDir / additionFileName, additionFileData)) {
        Logger::error("failed to write addition file:", (appDir / additionFileName).string());
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    return 0;
}

/**
 * @brief 将动态库文件复制到 .app 目录下，并设置加载路径。
 * @param dylibPath 输出的动态库加载路径（@executable_path/xxx.dylib）。
 * @param appDir .app 目录路径。
 * @param dylibFilePath 动态库源文件路径，空字符串表示不注入。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int writeDylibFileIfNeed(std::string& dylibPath, const std::filesystem::path& appDir,
                                const std::string& dylibFilePath) {
    if (dylibFilePath.empty()) return 0;

    Logger::info("write dylib file to .app folder:", dylibFilePath);

    // 检测原文件存在。
    auto dylibFilePath2 = std::filesystem::path(dylibFilePath);
    if (!std::filesystem::exists(dylibFilePath2) || !std::filesystem::is_regular_file(dylibFilePath2)) {
        Logger::error("dylib file not found:", dylibFilePath);
        return EXIT_CODE_FILE_NOT_FOUND;
    }

    // 检测文件是否已存在。
    auto fileName = std::filesystem::path(dylibFilePath).filename().string();
    auto destFilePath = appDir / fileName;
    if (std::filesystem::exists(destFilePath))
        Logger::info("file exists, will be over write file:", destFilePath.string());

    // 复制文件到 .app 目录下。
    std::error_code ec;
    std::filesystem::copy_file(dylibFilePath2, destFilePath, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        Logger::error("copy dylib file failed:", ec.message());
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    // 设置动态库路径。
    dylibPath = "@executable_path/" + fileName;

    return 0;
}

/**
 * @brief 校验 .app 目录下的 Info.plist 文件内容是否合法。
 *
 * 检查 CFBundleIdentifier、CFBundleExecutable、CFBundleVersion、
 * CFBundleShortVersionString 是否存在且合法。
 *
 * @param appDir .app 目录路径。
 * @return 0 表示校验通过，非 0 表示失败的退出码。
 */
static int verifyPList(const std::filesystem::path& appDir) {
    // 读取 plist 文件。
    auto plistOpt = ReadPListAsXML(appDir / FILE_NAME_PLIST);
    if (!plistOpt) {
        Logger::error("failed to read plist file:", (appDir / FILE_NAME_PLIST).string());
        return EXIT_CODE_READ_FILE_ERROR;
    }

    // 校验。
    if (auto bundleIdOpt = GetPListString(*plistOpt, PLIST_KEY_CF_BUNDLE_IDENTIFIER);
        !bundleIdOpt || bundleIdOpt->empty() || !IsInvalidBundleValue(*bundleIdOpt)) {
        Logger::error("bundle id is invalid:", bundleIdOpt ? *bundleIdOpt : "<null>");
        return EXIT_CODE_BUNDLE_INVALID;
    }
    if (auto executeOpt = GetPListString(*plistOpt, PLIST_KEY_CF_BUNDLE_EXECUTABLE);
        !executeOpt || executeOpt->empty()) {
        Logger::error("bundle execute is invalid:", executeOpt ? *executeOpt : "<null>");
        return EXIT_CODE_PLIST_INVALID;
    }
    if (auto versionOpt = GetPListString(*plistOpt, PLIST_KEY_CF_BUNDLE_VERSION); !versionOpt || versionOpt->empty()) {
        Logger::error("bundle version is invalid:", versionOpt ? *versionOpt : "<null>");
        return EXIT_CODE_PLIST_INVALID;
    }
    if (auto shortVersionOpt = GetPListString(*plistOpt, PLIST_KEY_CF_BUNDLE_SHORT_VERSION_STRING);
        !shortVersionOpt || shortVersionOpt->empty()) {
        Logger::error("bundle short version is invalid:", shortVersionOpt ? *shortVersionOpt : "<null>");
        return EXIT_CODE_PLIST_INVALID;
    }

    return 0;
}

/**
 * @brief 从 .app 目录的 Info.plist 中提取签名所需的元数据。
 * @param signInfo 输出的签名信息对象。
 * @param appDir .app 目录路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int getSignInfo(SignInfo& signInfo, const std::filesystem::path& appDir) {
    // 读取 plist 文件。
    auto plistOpt = ReadPListAsXML(appDir / FILE_NAME_PLIST);
    if (!plistOpt) {
        Logger::error("failed to read plist file:", (appDir / FILE_NAME_PLIST).string());
        return EXIT_CODE_READ_FILE_ERROR;
    }

    signInfo.bundleId = *GetPListString(*plistOpt, PLIST_KEY_CF_BUNDLE_IDENTIFIER);
    signInfo.execute = *GetPListString(*plistOpt, PLIST_KEY_CF_BUNDLE_EXECUTABLE);
    signInfo.bundleVersion = *GetPListString(*plistOpt, PLIST_KEY_CF_BUNDLE_VERSION);
    if (auto plistSha1Opt = SHA1Hex(*plistOpt)) signInfo.plistSha1 = *plistSha1Opt;
    if (auto plistSha256Opt = SHA256Hex(*plistOpt)) signInfo.plistSha256 = *plistSha256Opt;
    auto displayNameOpt = GetPListString(*plistOpt, PLIST_KEY_CF_BUNDLE_DISPLAY_NAME);
    if (!displayNameOpt || displayNameOpt->empty())
        displayNameOpt = GetPListString(*plistOpt, PLIST_KEY_CF_BUNDLE_NAME);
    if (displayNameOpt) signInfo.name = *displayNameOpt;

    return 0;
}

/**
 * @brief 递归遍历 .app 目录，收集所有子组件的签名信息。
 *
 * 处理 .app/.appex、.framework/.xctest 目录和 .dylib 文件，
 * 构建树形的 SignInfo 结构。
 *
 * @param signInfo 当前节点的签名信息（子组件会追加到其 folders/files 中）。
 * @param rootAppDir 根 .app 目录路径（用于计算相对路径）。
 * @param appDir 当前遍历的目录路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int getPluginSignInfos(SignInfo& signInfo, const std::filesystem::path& rootAppDir,
                              const std::filesystem::path& appDir) {
    // 判断文件夹存在。
    if (!std::filesystem::exists(appDir) || !std::filesystem::is_directory(appDir)) {
        Logger::error("app directory not exists:", appDir.string());
        return EXIT_CODE_FILE_NOT_FOUND;
    }

    // 遍历文件夹内文件。
    for (auto&& entry : std::filesystem::directory_iterator(appDir)) {
        auto name = entry.path().filename().string();
        if (entry.is_directory()) {
            // 排除 . 与 .. 文件夹。
            if (name == FILE_NAME_DOT || name == FILE_NAME_DOUBLE_DOT) continue;

            if (name.ends_with(FILE_NAME_SUFFIX_APP) || name.ends_with(FILE_NAME_SUFFIX_APPEX)) {
                SignInfo subSignInfo{};
                subSignInfo.path =
                    std::filesystem::absolute(entry.path()).string().substr(rootAppDir.string().size() + 1);
                if (auto code = verifyPList(entry.path())) return code;
                if (auto code = getSignInfo(subSignInfo, entry.path())) return code;
                if (!getPluginSignInfos(subSignInfo, rootAppDir, entry.path()))
                    signInfo.folders.push_back(std::move(subSignInfo));
            } else if (name.ends_with(FILE_NAME_SUFFIX_FRAMEWORK) || name.ends_with(FILE_NAME_SUFFIX_XCTEST)) {
                SignInfo subSignInfo{};
                subSignInfo.path =
                    std::filesystem::absolute(entry.path()).string().substr(rootAppDir.string().size() + 1);
                if (!getSignInfo(subSignInfo, entry.path())) {
                    if (!getPluginSignInfos(subSignInfo, rootAppDir, entry.path()))
                        signInfo.folders.push_back(std::move(subSignInfo));
                }
            } else {
                if (auto code = getPluginSignInfos(signInfo, rootAppDir, entry.path())) return code;
            }
        } else if (entry.is_regular_file()) {
            if (name.ends_with(FILE_NAME_SUFFIX_DYLIB)) {
                signInfo.files.push_back(
                    std::filesystem::absolute(entry.path()).string().substr(rootAppDir.string().size() + 1));
            }
        }
    }

    return 0;
}

/**
 * @brief 递归收集所有需要记录到 CodeResources 中的已变更文件路径。
 *
 * 遍历 SignInfo 树形结构，收集所有 .dylib 文件路径和子组件的
 * CodeResources / 可执行文件路径，用于生成 CodeResources 的 changed 部分。
 *
 * @param changed [输出] 收集到的变更文件相对路径列表。
 * @param signInfo 当前节点的签名信息。
 */
static void getChangedFiles(std::vector<std::string>& changed, const SignInfo& signInfo) {
    for (auto&& v : signInfo.files) changed.push_back(v);

    for (auto&& v : signInfo.folders) {
        getChangedFiles(changed, v);
        changed.push_back(v.path + FILE_PATH_CODE_RESOURCES);
        changed.push_back(v.path + FILE_NAME_SLASH + v.execute);
    }
}

/**
 * @brief 为每个签名节点计算并设置其 changed 列表（包含所有子组件的变更文件）。
 *
 * 自底向上递归处理：先让子节点计算自身的 changed，再合并当前节点的文件和
 * 子组件的 CodeResources / 可执行文件路径。根节点还会追加 embedded.mobileprovision。
 *
 * @param signInfo 当前节点（递归修改其 changed 成员）。
 */
static void setSignInfoChanged(SignInfo& signInfo) {
    for (auto&& v : signInfo.folders) setSignInfoChanged(v);

    std::vector<std::string> changed{};
    getChangedFiles(changed, signInfo);
    signInfo.changed = std::move(changed);

    if (signInfo.path == FILE_NAME_SLASH) signInfo.changed.emplace_back(FILE_NAME_EMBEDDED_MOBILEPROVISION);
}

/**
 * @brief 递归设置目录及其所有子文件/子目录的权限为完全访问（0777）。
 *
 * 在签名前确保所有文件具有可读写执行权限，避免因权限不足导致
 * 签名写入或文件修改失败。对每个操作单独捕获错误并记录日志，
 * 不中断整体流程。
 *
 * @param dir 要修改权限的根目录路径。
 */
static void changeFilesPermission(const std::filesystem::path& dir) {
    constexpr auto perms = std::filesystem::perms::all;
    std::error_code ec{};

    // 设置目录自身的权限。
    std::filesystem::permissions(dir, perms, std::filesystem::perm_options::replace, ec);
    if (ec) {
        Logger::warn("failed to change permission of", dir.string(), ec.message());
        ec.clear();
    }

    // 递归遍历目录内的文件和子目录。
    for (auto&& entry : std::filesystem::recursive_directory_iterator(
             dir, std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (ec) {
            Logger::warn("failed to iterate directory", dir.string(), ec.message());
            break;
        }
        std::filesystem::permissions(entry.path(), perms, std::filesystem::perm_options::replace, ec);
        if (ec) {
            Logger::warn("failed to change permission of", entry.path().string(), ec.message());
            ec.clear();
        }
    }
}

/**
 * @brief 递归收集目录下所有文件的相对路径（排除 . 和 ..）。
 *
 * 遍历目录中的普通文件和子目录，将每个文件相对于 baseFolder 的路径
 * 插入 set 中（自动去重和排序）。结果用于生成 CodeResources 文件列表。
 *
 * @param folder 当前遍历的目录路径。
 * @param baseFolder 计算相对路径的基准目录。
 * @param files [输出] 收集到的相对文件路径集合。
 */
static void getFolderFiles(const std::filesystem::path& folder, const std::filesystem::path& baseFolder,
                           std::set<std::string>& files) {
    for (auto&& entry : std::filesystem::directory_iterator(folder)) {
        auto name = entry.path().filename().string();
        if (name == FILE_NAME_DOT || name == FILE_NAME_DOUBLE_DOT) continue;
        if (entry.is_directory()) {
            getFolderFiles(entry.path(), baseFolder, files);
        } else if (entry.is_regular_file()) {
            auto rel = std::filesystem::relative(entry.path(), baseFolder).generic_string();
            files.insert(rel);
        }
    }
}

/// 生成 CodeResources plist 文件。
static int generateCodeResources(std::string& codeResources, const std::filesystem::path& appDir) {
    // 收集所有文件。
    std::set<std::string> setFiles{};
    getFolderFiles(appDir, appDir, setFiles);

    // 获取可执行文件名。
    auto plistOpt = ReadPListAsXML(appDir / FILE_NAME_PLIST);
    if (!plistOpt) return EXIT_CODE_READ_FILE_ERROR;
    if (auto execNameOpt = GetPListString(*plistOpt, PLIST_KEY_CF_BUNDLE_EXECUTABLE)) setFiles.erase(*execNameOpt);
    setFiles.erase(FILE_PATH_CODE_RESOURCES2);

    // 构建 files 和 files2 字典的 XML 片段。
    std::string filesXml, files2Xml;
    for (auto&& key : setFiles) {
        auto filePath = appDir / key;
        auto [sha1B64, sha256B64] = SHASumBase64File(filePath);
        if (sha1B64.empty()) continue;

        bool omit1{}, omit2{};
        if (key == FILE_NAME_PLIST || key == FILE_NAME_PKG_INFO) omit2 = true;
        if (key.ends_with(FILE_NAME_DS_STORE)) omit2 = true;
        if (key.ends_with(FILE_PATH_LOCVERSION)) {
            omit1 = true;
            omit2 = true;
        }

        if (!omit1) {
            if (key.find(FILE_PATH_LPROJ) != std::string::npos) {
                filesXml =
                    std::format("{}<key>{}</key><dict><key>hash</key><data>{}</data><key>optional</key><true/></dict>",
                                filesXml, key, sha1B64);
            } else {
                filesXml = std::format("{}<key>{}</key><data>{}</data>", filesXml, key, sha1B64);
            }
        }
        if (!omit2) {
            files2Xml =
                std::format("{}<key>{}</key><dict><key>hash</key><data>{}</data><key>hash2</key><data>{}</data>",
                            files2Xml, key, sha1B64, sha256B64);
            if (key.find(FILE_PATH_LPROJ) != std::string::npos)
                files2Xml = std::format("{}<key>optional</key><true/>", files2Xml);
            files2Xml += "</dict>";
        }
    }

    // 构建 rules 和 rules2。
    std::string rulesXml =
        R"++(<key>^.*</key>
<true/>
<key>^.*\.lproj/</key>
<dict><key>optional</key><true/><key>weight</key><real>1000</real></dict>
<key>^.*\.lproj/locversion.plist$</key>
<dict><key>omit</key><true/><key>weight</key><real>1100</real></dict>
<key>^Base\.lproj/</key>
<dict><key>weight</key><real>1010</real></dict>
<key>^version.plist$</key>
<true/>)++";

    std::string rules2Xml =
        R"++(<key>^.*</key>
<true/>
<key>.*\.dSYM($|/)</key>
<dict><key>weight</key><real>11</real></dict>
<key>^(.*/)?\.DS_Store$</key>
<dict><key>omit</key><true/><key>weight</key><real>2000</real></dict>
<key>^.*\.lproj/</key>
<dict><key>optional</key><true/><key>weight</key><real>1000</real></dict>
<key>^.*\.lproj/locversion.plist$</key>
<dict><key>omit</key><true/><key>weight</key><real>1100</real></dict>
<key>^Base\.lproj/</key>
<dict><key>weight</key><real>1010</real></dict>
<key>^Info\.plist$</key>
<dict><key>omit</key><true/><key>weight</key><real>20</real></dict>
<key>^PkgInfo$</key>
<dict><key>omit</key><true/><key>weight</key><real>20</real></dict>
<key>^embedded\.provisionprofile$</key><dict><key>weight</key>
<real>20</real></dict>
<key>^version\.plist$</key>
<dict><key>weight</key><real>20</real></dict>)++";

    // 组装完整 plist。
    codeResources = std::format(R"++(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>files</key>
<dict>{}</dict>
<key>files2</key>
<dict>{}</dict>
<key>rules</key>
<dict>{}</dict>
<key>rules2</key>
<dict>{}</dict>
</dict>
</plist>)++",
                                filesXml, files2Xml, rulesXml, rules2Xml);

    return 0;
}

/**
 * @brief 递归执行代码签名。
 *
 * 先递归签名所有子组件，然后签名当前组件的 .dylib 文件和可执行文件。
 * 签名后创建 _CodeSignature 目录并写入 CodeResources 文件。
 *
 * @param signInfo 当前组件的签名信息。
 * @param signAsset 签名资产（证书、描述文件等）。
 * @param rootAppDir 根 .app 目录路径。
 * @return 0 表示成功，非 0 表示失败的退出码。
 */
static int signFiles(const SignInfo& signInfo, const SignAsset& signAsset, const std::filesystem::path& rootAppDir) {
    for (auto&& v : signInfo.folders)
        if (auto code = signFiles(v, signAsset, rootAppDir)) return code;

    auto dir = signInfo.path;
    if (dir == FILE_NAME_SLASH) {
        dir = rootAppDir.string();
    } else {
        dir = (rootAppDir / dir).string();
    }

    changeFilesPermission(dir);

    // 签名独立 dylib 文件。
    for (auto&& v : signInfo.files) {
        Logger::info("sign dylib file:", v);
        auto dylibPath = rootAppDir / v;
        if (!SignMachOFile(dylibPath, signAsset.certificate.second.get(), signAsset.certificate.first.get(), "", "", "",
                           "", "", "", "")) {
            Logger::error("failed to sign dylib file:", v);
            return EXIT_CODE_SIGN_ERROR;
        }
    }

    auto baseDir = rootAppDir;
    if (signInfo.path != FILE_NAME_SLASH) baseDir = baseDir / signInfo.path;
    auto executableFilePath = baseDir / signInfo.execute;

    // Framework 写入描述文件。
    if (signInfo.path.ends_with(FILE_NAME_SUFFIX_FRAMEWORK)) {
        if (!WriteFile(baseDir / FILE_NAME_EMBEDDED_MOBILEPROVISION, signAsset.provision))
            Logger::error("failed to write provision file:", baseDir / FILE_NAME_EMBEDDED_MOBILEPROVISION);
    }

    // 生成 CodeResources。
    MakeDir(baseDir / FILE_NAME_CODE_RESOURCES2,
            std::filesystem::perms::owner_all | std::filesystem::perms::group_exec |
                std::filesystem::perms::group_read | std::filesystem::perms::others_exec |
                std::filesystem::perms::others_read);
    auto codeResourceFile = baseDir / FILE_NAME_CODE_RESOURCES2 / FILE_NAME_CODE_RESOURCES;

    std::string codeResData{};
    if (auto code = generateCodeResources(codeResData, baseDir)) {
        Logger::error("failed to generate CodeResources");
        return code;
    }
    if (!WriteFile(codeResourceFile, codeResData)) {
        Logger::error("failed to write CodeResources:", codeResourceFile.string());
        return EXIT_CODE_WRITE_FILE_ERROR;
    }

    // 读取 Info.plist 计算原始二进制哈希（非十六进制字符串）。
    auto plistDataOpt = ReadFile(baseDir / FILE_NAME_PLIST);
    std::string infoPlistSHA1, infoPlistSHA256;
    if (plistDataOpt) {
        auto [s1, s256] = SHASumRaw(*plistDataOpt);
        infoPlistSHA1 = std::move(s1);
        infoPlistSHA256 = std::move(s256);
    } else {
        infoPlistSHA1.assign(20, '\0');
        infoPlistSHA256.assign(32, '\0');
    }

    // 在根节点签名前注入 dylib。
    if (signInfo.path == FILE_NAME_SLASH && !signAsset.dylibPath.empty()) {
        Logger::info("inject dylib:", signAsset.dylibPath, "weak:", signAsset.weakInject);
        if (!InjectDyLib(executableFilePath, signAsset.dylibPath, signAsset.weakInject)) {
            Logger::error("failed to inject dylib into:", executableFilePath.string());
            return EXIT_CODE_SIGN_ERROR;
        }
    }

    // 签名主可执行文件。
    Logger::info("sign executable:", executableFilePath.string());
    if (!SignMachOFile(executableFilePath, signAsset.certificate.second.get(), signAsset.certificate.first.get(),
                       signInfo.bundleId, signAsset.teamId, signAsset.certificateName, signAsset.plistEntitlements,
                       infoPlistSHA1, infoPlistSHA256, codeResData)) {
        Logger::error("failed to sign executable:", executableFilePath.string());
        return EXIT_CODE_SIGN_ERROR;
    }

    return 0;
}

/**
 * @brief 将 IPA 解压目录重新打包为 IPA 文件（ZIP 格式）。
 *
 * 调用 Zip() 函数将签名完成后的目录压缩为目标 IPA 文件。
 * 这是整个签名流程的最后一步（清理临时文件之前）。
 *
 * @param ipaDir 签名完成的 IPA 解压目录路径。
 * @param dest 输出的 IPA 文件路径（由配置文件指定）。
 * @return 0 表示成功，EXIT_CODE_ZIP_ERROR 表示打包失败。
 */
static int packageIPA(const std::filesystem::path& ipaDir, const std::filesystem::path& dest, const int compressLevel) {
    if (!Zip(ipaDir, dest, compressLevel)) return EXIT_CODE_ZIP_ERROR;

    return 0;
}

/**
 * @brief 清理 IPA 解压的临时目录。
 *
 * 签名和打包完成后，删除在系统临时目录下创建的 IPA 解压文件夹，
 * 释放磁盘空间。此操作不可逆。
 *
 * @param ipaDir 要删除的临时解压目录路径。
 */
static void removeIpaDir(const std::filesystem::path& ipaDir) {
    Logger::info("remove ipa temporary directory:", ipaDir.string());
    std::filesystem::remove_all(ipaDir);
}

/**
 * @brief 执行 IPA 签名主流程。
 *
 * 整个流程分为三个阶段：
 * 1. 准备阶段：解析配置、加载证书、解压 IPA、修改 plist、收集签名信息
 * 2. 签名阶段：递归签名所有组件
 * 3. 打包阶段：重新压缩为 IPA 并清理临时文件
 *
 * @param opts 命令行参数。
 * @return 程序退出码，0 表示成功。
 */
int DoSign(const Options& opts) {
    Logger::info("start to sign ipa file");

    // 准备工作。
    SignAsset signAsset{};
    {
        Configuration cfg{};
        if (auto code = getYAMLConfiguration(cfg, opts.signOpts.configrationFilePath)) return code;
        signAsset.ipaOutputPath = cfg.destinationIpaFilePath;
        signAsset.compressLevel = cfg.zipLevel;

        if (auto code = readProvisionFile(signAsset.provision, cfg.mobileProvisionFilePath)) return code;

        if (auto code = getProvisionPList(signAsset.plist, signAsset.provision)) return code;

        if (auto code = getTeamIdFromPList(signAsset.teamId, signAsset.plist)) return code;

        if (auto code = getPListEntitlements(signAsset.plistEntitlements, signAsset.plist, cfg.universalLinkDomains,
                                             cfg.associatedDomains, cfg.keychainGroups, cfg.securityGroups))
            return code;

        if (auto code = parseCertificate(signAsset.certificate, cfg.certificateFilePath, cfg.certificatePassword,
                                         signAsset.plist))
            return code;

        if (auto code = getCertificateName(signAsset.certificateName, signAsset.certificate)) return code;

        if (auto code = readAppxProvisionFile(signAsset.appxProvisions, cfg.appxProvisions)) return code;

        if (auto code = getAppxProvisionBundleIds(signAsset.appxProvisionBundleIds, signAsset.appxProvisions))
            return code;

        if (auto code = unzipIPAFile(signAsset.ipaDir, cfg.ipaFilePath)) return code;


        if (auto code = findAppDir(signAsset.appDir, signAsset.ipaDir)) return code;

        if (auto code =
                updateBundleIdIfNeed(cfg.newBundleId, signAsset.appDir, signAsset.appxProvisions,
                                     signAsset.appxProvisionBundleIds, cfg.addPlistStringKey, cfg.removePlistStringKey))
            return code;

        if (auto code = updateBundleNameIfNeed(cfg.newBundleName, signAsset.appDir)) return code;

        if (auto code = updateBundleVersionIfNeed(cfg.newBundleVersion, signAsset.appDir)) return code;

        if (auto code = updatePList(signAsset.appDir, cfg.addPlistStringKey, cfg.removePlistStringKey)) return code;

        if (auto code = updateZhLocaleFile(cfg.newBundleName, signAsset.appDir)) return code;

        if (auto code = updateNewZhLocaleFile(cfg.newBundleName, signAsset.appDir)) return code;

        if (auto code = writeProvisionFile(signAsset.appDir, cfg.mobileProvisionFilePath)) return code;

        removeCodeSignatureFolder(signAsset.appDir);

        if (auto code = createAdditionFile(signAsset.appDir, cfg.additionalFileName, cfg.additionalFileData))
            return code;

        std::string dylibPath{};
        if (auto code = writeDylibFileIfNeed(dylibPath, signAsset.appDir, cfg.dylibFilePath)) return code;
        signAsset.dylibPath = std::move(dylibPath);
        signAsset.weakInject = cfg.weakInject;

        if (auto code = verifyPList(signAsset.appDir)) return code;

        signAsset.signInfo.path = FILE_NAME_SLASH;
        if (auto code = getSignInfo(signAsset.signInfo, signAsset.appDir)) return code;

        if (auto code = getPluginSignInfos(signAsset.signInfo, signAsset.appDir, signAsset.appDir)) return code;

        setSignInfoChanged(signAsset.signInfo);
    }

    // 签名。
    if (auto code = signFiles(signAsset.signInfo, signAsset, signAsset.appDir)) return code;

    // 压缩文件。
    if (auto code = packageIPA(signAsset.ipaDir, signAsset.ipaOutputPath, signAsset.compressLevel)) return code;

    // 清理文件。
    removeIpaDir(signAsset.ipaDir);

    return 0;
}

}
