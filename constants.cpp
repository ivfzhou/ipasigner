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
const char* const PLIST_TAG_TRUE = "true";
const char* const PLIST_TAG_FALSE = "false";
const char* const PLIST_TAG_INTEGER = "integer";

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
const char* const FILE_NAME_PKG_INFO = "PkgInfo";
const char* const FILE_NAME_DS_STORE = ".DS_Store";
const char* const FILE_PATH_IPA_ZH_LOCALE = "zh_CN.lproj/InfoPlist.strings";
const char* const FILE_PATH_NEW_IPA_ZH_LOCALE = "zh-Hans.lproj/InfoPlist.strings";
const char* const FILE_PATH_CODE_RESOURCES = "/_CodeSignature/CodeResources";
const char* const FILE_PATH_CODE_RESOURCES2 = "_CodeSignature/CodeResources";
const char* const FILE_PATH_LOCVERSION = ".lproj/locversion.plist";
const char* const FILE_PATH_LPROJ = ".lproj/";

// 证书。
const char* const CERTIFICATE_APPLE_ROOT_CA = R"++(-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MDk0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----)++";

const char* const CERTIFICATE_APPLE_DEV_G3_CA = R"++(-----BEGIN CERTIFICATE-----
MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBi
MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBw
bGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3Qg
Q0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtB
cHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJ
BgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZ
C4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbW
BpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj
+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b
5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A
0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LS
VpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j
BBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsG
AQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNh
MC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3Js
MB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYw
EAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJH
Qr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qA
HXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETK
XXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7
bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTC
NwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVza
UDSdlTs=
-----END CERTIFICATE-----)++";

}
