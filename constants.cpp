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
 * @file constants.cpp
 * @brief 全局常量定义。
 *
 * 定义 constants.hpp 中声明的所有外部链接常量的具体值。
 */

#include "constants.hpp"

namespace gitee::com::ivfzhou::ipasigner {

// 程序退出码定义：1~15 分别对应不同类型的错误。
const int EXIT_CODE_PARSE_OPTIONS_ERROR = 1;
const int EXIT_CODE_PARSE_CONFIGURATION_ERROR = 2;
const int EXIT_CODE_VALIDATE_CONFIGURATION_ERROR = 3;
const int EXIT_CODE_PARSE_CERTIFICATE_ERROR = 4;
const int EXIT_CODE_READ_FILE_ERROR = 5;
const int EXIT_CODE_WRITE_FILE_ERROR = 6;
const int EXIT_CODE_READ_PLIST_ERROR = 7;
const int EXIT_CODE_WRITE_PLIST_ERROR = 8;
const int EXIT_CODE_TEAM_ID_NOT_FOUND = 9;
const int EXIT_CODE_BUNDLE_NOT_FOUND = 10;
const int EXIT_CODE_FILE_NOT_FOUND = 11;
const int EXIT_CODE_BUNDLE_INVALID = 12;
const int EXIT_CODE_PLIST_INVALID = 13;
const int EXIT_CODE_SIGN_ERROR = 14;
const int EXIT_CODE_ZIP_ERROR = 15;

// YAML 配置文件字段名定义。
const char* const YAML_FIELD_IPA_FILE_PATH = "ipaFilePath";
const char* const YAML_FIELD_DESTINATION_IPA_FILE_PATH = "destinationIpaFilePath";
const char* const YAML_FIELD_CERTIFICATE_FILE_PATH = "certificateFilePath";
const char* const YAML_FIELD_CERTIFICATE_PASSWORD = "certificatePassword";
const char* const YAML_FIELD_MOBILE_PROVISION_FILE_PATH = "mobileProvisionFilePath";
const char* const YAML_FIELD_DYLIB_FILE_PATH = "dylibFilePath";
const char* const YAML_FIELD_WEAK_INJECT = "weakInject";
const char* const YAML_FIELD_UNIVERSAL_LINK_DOMAINS = "universalLinkDomains";
const char* const YAML_FIELD_ASSOCIATED_DOMAINS = "associatedDomains";
const char* const YAML_FIELD_KEYCHAIN_GROUPS = "keychainGroups";
const char* const YAML_FIELD_SECURITY_GROUPS = "securityGroups";
const char* const YAML_FIELD_APPX_PROVISIONS = "appxProvisions";
const char* const YAML_FIELD_NEW_BUNDLE_ID = "newBundleId";
const char* const YAML_FIELD_NEW_BUNDLE_NAME = "newBundleName";
const char* const YAML_FIELD_NEW_BUNDLE_VERSION = "newBundleVersion";
const char* const YAML_FIELD_ADD_PLIST_STRING_KEY = "addPlistStringKey";
const char* const YAML_FIELD_REMOVE_PLIST_STRING_KEY = "removePlistStringKey";
const char* const YAML_FIELD_ADDITIONAL_FILE_NAME = "additionalFileName";
const char* const YAML_FIELD_ADDITIONAL_FILE_DATA = "additionalFileData";

// 命令行参数常量定义。
const char* const OPTION_PREFIXES = "/-";
const char* const OPTION_CONFIGURATION_FILE_PATH = "configuration";
const char* const OPTION_SUBCOMMAND_SIGN = "sign";

// plist/XML 标签名定义。
const char* const PLIST_TAG_KEY = "key";
const char* const PLIST_TAG_ROOT = "plist";
const char* const PLIST_TAG_DICT = "dict";
const char* const PLIST_TAG_ARRAY = "array";
const char* const PLIST_TAG_STRING = "string";

// plist/XML 键名定义：对应 Apple 描述文件和 Info.plist 中的标准键。
const char* const PLIST_KEY_ASSOCIATED_DOMAINS = "com.apple.developer.associated-domains";
const char* const PLIST_KEY_KEYCHAIN_ACCESS_GROUPS = "keychain-access-groups";
const char* const PLIST_KEY_APPLICATION_GROUPS = "com.apple.security.application-groups";
const char* const PLIST_KEY_TEAM_IDENTIFIER = "TeamIdentifier";
const char* const PLIST_KEY_ENTITLEMENTS = "Entitlements";
const char* const PLIST_KEY_DEVELOPER_CERTIFICATES = "DeveloperCertificates";
const char* const PLIST_KEY_APPLICATION_IDENTIFIER = "application-identifier";
const char* const PLIST_KEY_CF_BUNDLE_IDENTIFIER = "CFBundleIdentifier";
const char* const PLIST_KEY_WK_COMPANION_APP_BUNDLE_IDENTIFIER = "WKCompanionAppBundleIdentifier";
const char* const PLIST_KEY_NS_EXTENSION = "NSExtension";
const char* const PLIST_KEY_NS_EXTENSION_ATTRIBUTES = "NSExtensionAttributes";
const char* const PLIST_KEY_WK_APP_BUNDLE_IDENTIFIER = "WKAppBundleIdentifier";
const char* const PLIST_KEY_CF_BUNDLE_NAME = "CFBundleName";
const char* const PLIST_KEY_CF_BUNDLE_DISPLAY_NAME = "CFBundleDisplayName";
const char* const PLIST_KEY_CF_BUNDLE_VERSION = "CFBundleVersion";
const char* const PLIST_KEY_CF_BUNDLE_SHORT_VERSION_STRING = "CFBundleShortVersionString";
const char* const PLIST_KEY_CF_BUNDLE_EXECUTABLE = "CFBundleExecutable";

// 日志级别字符串定义。
const char* const LEVEL_INFO = "INFO";
const char* const LEVEL_WARN = "WARN";
const char* const LEVEL_ERROR = "ERROR";

// 文件名、路径和后缀常量定义。
const char* const FILE_NAME_PLIST = "Info.plist";
const char* const FILE_NAME_DOT = ".";
const char* const FILE_NAME_DOUBLE_DOT = "..";
const char* const FILE_NAME_SLASH = "/";
const char* const FILE_NAME_EMBEDDED_MOBILEPROVISION = "embedded.mobileprovision";
const char* const FILE_NAME_CODE_RESOURCES = "CodeResources";
const char* const FILE_NAME_CODE_RESOURCES2 = "_CodeSignature";
const char* const FILE_NAME_SUFFIX_APP = ".app";
const char* const FILE_NAME_SUFFIX_APPEX = ".appex";
const char* const FILE_NAME_SUFFIX_FRAMEWORK = ".framework";
const char* const FILE_NAME_SUFFIX_XCTEST = ".xctest";
const char* const FILE_NAME_SUFFIX_DYLIB = ".dylib";
const char* const FILE_PATH_IPA_ZH_LOCALE = "zh_CN.lproj/InfoPlist.strings";
const char* const FILE_PATH_NEW_IPA_ZH_LOCALE = "zh-Hans.lproj/InfoPlist.strings";
const char* const FILE_PATH_CODE_RESOURCES = "/_CodeSignature/CodeResources";

}
