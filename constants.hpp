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
 * @file constants.hpp
 * @brief 全局常量声明。
 *
 * 定义程序中使用的各类常量，包括：
 * - 程序退出码（用于标识不同类型的错误）
 * - YAML 配置文件字段名
 * - 命令行参数名
 * - plist/XML 标签名和键名
 * - 日志级别字符串
 * - 文件名和文件后缀常量
 */

#ifndef IPASIGNER_CONSTANTS_HPP
#define IPASIGNER_CONSTANTS_HPP

namespace gitee::com::ivfzhou::ipasigner {

/// ZIP 解压缓冲区大小（8KB）。
constexpr int ZIP_BUFFER_SIZE = 8 * 1024;

// 程序退出码：每个退出码对应一种特定的错误类型，便于调用方判断失败原因。
extern const int EXIT_CODE_PARSE_OPTIONS_ERROR; ///< 命令行参数解析失败。
extern const int EXIT_CODE_PARSE_CONFIGURATION_ERROR; ///< YAML 配置文件解析失败。
extern const int EXIT_CODE_VALIDATE_CONFIGURATION_ERROR; ///< YAML 配置文件校验失败。
extern const int EXIT_CODE_PARSE_CERTIFICATE_ERROR; ///< 证书解析失败。
extern const int EXIT_CODE_READ_FILE_ERROR; ///< 读取文件失败。
extern const int EXIT_CODE_WRITE_FILE_ERROR; ///< 写入文件失败。
extern const int EXIT_CODE_READ_PLIST_ERROR; ///< 读取 plist 失败。
extern const int EXIT_CODE_WRITE_PLIST_ERROR; ///< 写入 plist 失败。
extern const int EXIT_CODE_TEAM_ID_NOT_FOUND; ///< 未找到 Team ID。
extern const int EXIT_CODE_BUNDLE_NOT_FOUND; ///< 未找到 Bundle ID。
extern const int EXIT_CODE_FILE_NOT_FOUND; ///< 文件不存在。
extern const int EXIT_CODE_BUNDLE_INVALID; ///< Bundle ID 格式无效。
extern const int EXIT_CODE_PLIST_INVALID; ///< plist 内容无效。
extern const int EXIT_CODE_SIGN_ERROR; ///< 签名失败。
extern const int EXIT_CODE_ZIP_ERROR; ///< ZIP 压缩/解压失败。

// YAML 配置文件字段名：与 config.yml 中的键名一一对应。
extern const char* const YAML_FIELD_IPA_FILE_PATH; ///< 源 IPA 文件路径。
extern const char* const YAML_FIELD_DESTINATION_IPA_FILE_PATH; ///< 输出 IPA 文件路径。
extern const char* const YAML_FIELD_CERTIFICATE_FILE_PATH; ///< 证书文件路径。
extern const char* const YAML_FIELD_CERTIFICATE_PASSWORD; ///< 证书密码。
extern const char* const YAML_FIELD_MOBILE_PROVISION_FILE_PATH; ///< 描述文件路径。
extern const char* const YAML_FIELD_DYLIB_FILE_PATH; ///< 动态库文件路径。
extern const char* const YAML_FIELD_WEAK_INJECT; ///< 是否弱注入。
extern const char* const YAML_FIELD_UNIVERSAL_LINK_DOMAINS; ///< Universal Link 域名列表。
extern const char* const YAML_FIELD_ASSOCIATED_DOMAINS; ///< Associated Domain 关联域名列表。
extern const char* const YAML_FIELD_KEYCHAIN_GROUPS; ///< 钥匙串访问组列表。
extern const char* const YAML_FIELD_SECURITY_GROUPS; ///< 安全应用组列表。
extern const char* const YAML_FIELD_APPX_PROVISIONS; ///< 插件描述文件映射。
extern const char* const YAML_FIELD_NEW_BUNDLE_ID; ///< 新 Bundle ID。
extern const char* const YAML_FIELD_NEW_BUNDLE_NAME; ///< 新 Bundle 名称。
extern const char* const YAML_FIELD_NEW_BUNDLE_VERSION; ///< 新 Bundle 版本号。
extern const char* const YAML_FIELD_ADD_PLIST_STRING_KEY; ///< 添加的 plist 键值对。
extern const char* const YAML_FIELD_REMOVE_PLIST_STRING_KEY; ///< 移除的 plist 键列表。
extern const char* const YAML_FIELD_ADDITIONAL_FILE_NAME; ///< 附加文件名。
extern const char* const YAML_FIELD_ADDITIONAL_FILE_DATA; ///< 附加文件内容。

// 命令行参数相关常量。
extern const char* const OPTION_PREFIXES; ///< 参数前缀字符（支持 / 和 -）。
extern const char* const OPTION_CONFIGURATION_FILE_PATH; ///< 配置文件参数名。
extern const char* const OPTION_SUBCOMMAND_SIGN; ///< 签名子命令名。

// plist/XML 标签名常量。
extern const char* const PLIST_TAG_KEY; ///< <key> 标签。
extern const char* const PLIST_TAG_ROOT; ///< <plist> 根标签。
extern const char* const PLIST_TAG_DICT; ///< <dict> 字典标签。
extern const char* const PLIST_TAG_ARRAY; ///< <array> 数组标签。
extern const char* const PLIST_TAG_STRING; ///< <string> 字符串标签。
extern const char* const PLIST_TAG_TRUE;
extern const char* const PLIST_TAG_FALSE;
extern const char* const PLIST_TAG_INTEGER;

// plist/XML 键名常量：对应 Apple 描述文件和 Info.plist 中的标准键。
extern const char* const PLIST_KEY_ASSOCIATED_DOMAINS; ///< 关联域名能力键。
extern const char* const PLIST_KEY_KEYCHAIN_ACCESS_GROUPS; ///< 钥匙串访问组键。
extern const char* const PLIST_KEY_APPLICATION_GROUPS; ///< 应用组键。
extern const char* const PLIST_KEY_TEAM_IDENTIFIER; ///< 团队标识符键。
extern const char* const PLIST_KEY_ENTITLEMENTS; ///< 权限配置键。
extern const char* const PLIST_KEY_DEVELOPER_CERTIFICATES; ///< 开发者证书键。
extern const char* const PLIST_KEY_APPLICATION_IDENTIFIER; ///< 应用标识符键。
extern const char* const PLIST_KEY_CF_BUNDLE_IDENTIFIER; ///< Bundle ID 键。
extern const char* const PLIST_KEY_WK_COMPANION_APP_BUNDLE_IDENTIFIER; ///< WatchKit 伴侣应用 Bundle ID 键。
extern const char* const PLIST_KEY_NS_EXTENSION; ///< 扩展配置键。
extern const char* const PLIST_KEY_NS_EXTENSION_ATTRIBUTES; ///< 扩展属性键。
extern const char* const PLIST_KEY_WK_APP_BUNDLE_IDENTIFIER; ///< WatchKit 应用 Bundle ID 键。
extern const char* const PLIST_KEY_CF_BUNDLE_NAME; ///< Bundle 名称键。
extern const char* const PLIST_KEY_CF_BUNDLE_DISPLAY_NAME; ///< Bundle 显示名称键。
extern const char* const PLIST_KEY_CF_BUNDLE_VERSION; ///< Bundle 版本号键。
extern const char* const PLIST_KEY_CF_BUNDLE_SHORT_VERSION_STRING; ///< Bundle 短版本号键。
extern const char* const PLIST_KEY_CF_BUNDLE_EXECUTABLE; ///< 可执行文件名键。

// 日志级别字符串常量。
extern const char* const LEVEL_INFO; ///< 信息级别。
extern const char* const LEVEL_WARN; ///< 警告级别。
extern const char* const LEVEL_ERROR; ///< 错误级别。

// 文件名和路径相关常量。
extern const char* const FILE_NAME_PLIST; ///< Info.plist 文件名。
extern const char* const FILE_NAME_DOT; ///< 当前目录 "."。
extern const char* const FILE_NAME_DOUBLE_DOT; ///< 父目录 ".."。
extern const char* const FILE_NAME_SLASH; ///< 路径分隔符 "/"。
extern const char* const FILE_NAME_EMBEDDED_MOBILEPROVISION; ///< 嵌入式描述文件名。
extern const char* const FILE_NAME_CODE_RESOURCES; ///< CodeResources 文件名。
extern const char* const FILE_NAME_CODE_RESOURCES2; ///< _CodeSignature 目录名。
extern const char* const FILE_NAME_SUFFIX_APP; ///< .app 后缀。
extern const char* const FILE_NAME_SUFFIX_APPEX; ///< .appex 后缀。
extern const char* const FILE_NAME_SUFFIX_FRAMEWORK; ///< .framework 后缀。
extern const char* const FILE_NAME_SUFFIX_XCTEST; ///< .xctest 后缀。
extern const char* const FILE_NAME_SUFFIX_DYLIB; ///< .dylib 后缀。
extern const char* const FILE_NAME_PKG_INFO;
extern const char* const FILE_NAME_DS_STORE;
extern const char* const FILE_PATH_IPA_ZH_LOCALE; ///< 中文本地化文件路径（旧版）。
extern const char* const FILE_PATH_NEW_IPA_ZH_LOCALE; ///< 中文本地化文件路径（新版）。
extern const char* const FILE_PATH_CODE_RESOURCES; ///< CodeResources 相对路径。
extern const char* const FILE_PATH_CODE_RESOURCES2;
extern const char* const FILE_PATH_LOCVERSION;
extern const char* const FILE_PATH_LPROJ;

// 证书。
extern const char* const CERTIFICATE_APPLE_ROOT_CA; // Apple Root CA 证书
extern const char* const CERTIFICATE_APPLE_DEV_G3_CA; // Apple WWDR CA 证书（G3）

/**
 * @brief 获取平台对应的换行符。
 * @return Windows 下返回 "\r\n"，其他平台返回 "\n"。
 */
constexpr const char* NewLine() {
#ifdef WINDOWS
    return "\r\n";
#elif defined LINUX
    return "\n";
#endif
    return "\n";
}

}

#endif
