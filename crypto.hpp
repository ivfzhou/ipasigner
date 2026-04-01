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
 * @file crypto.hpp
 * @brief 加密与证书操作接口声明。
 *
 * 提供基于 OpenSSL 的加密工具函数，包括：
 * - 从描述文件（.mobileprovision）中提取 CMS 签名内容
 * - 解析 PKCS#12 / PEM 格式的签名证书和私钥
 * - 获取 X509 证书的通用名称（Common Name）
 * - SHA1 / SHA256 哈希计算
 * - Base64 编码
 *
 * 同时定义了 EVP_PKEY 和 X509 的智能指针类型，通过自定义删除器实现 RAII 资源管理。
 */

#ifndef IPASIGNER_CRYPTO_HPP
#define IPASIGNER_CRYPTO_HPP

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "openssl/evp.h"
#include "openssl/types.h"
#include "openssl/x509.h"

namespace gitee::com::ivfzhou::ipasigner {

/// EVP_PKEY 自定义删除器，释放 OpenSSL 私钥资源。
struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept {
        Logger::info("free private key");
        EVP_PKEY_free(p);
    }
};

/// X509 自定义删除器，释放 OpenSSL 证书资源。
struct X509Deleter {
    void operator()(X509* p) const noexcept {
        Logger::info("free certificate");
        X509_free(p);
    }
};

/// 私钥智能指针类型（自动释放）。
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

/// X509 证书智能指针类型（自动释放）。
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

/**
 * @brief 从描述文件（.mobileprovision）的二进制数据中提取 CMS 签名的 plist 内容。
 * @param data 描述文件的原始二进制数据。
 * @return 成功返回 plist XML 字符串，失败返回 std::nullopt。
 */
std::optional<std::string> GetCMSFromProvision(std::string_view data);

/**
 * @brief 获取 X509 证书的主体通用名称（Common Name）。
 * @param certificate X509 证书指针。
 * @return 成功返回通用名称字符串，失败返回 std::nullopt。
 */
std::optional<std::string> GetCommonNameFromCertificate(const X509* certificate);

/**
 * @brief 解析证书文件，提取私钥和 X509 证书。
 *
 * 依次尝试 PEM 私钥、DER 私钥、PKCS#12 三种格式解析。
 * 若证书文件中未包含 X509 证书，则从描述文件的 plist 证书列表中匹配。
 *
 * @param certificate 证书文件的原始内容。
 * @param password 证书密码（用于 PKCS#12 解密）。
 * @param plistCertificates 描述文件中的 DeveloperCertificates 列表（DER 编码）。
 * @return 成功返回 (私钥, X509证书) 对，失败返回 std::nullopt。
 */
std::optional<std::pair<EvpPkeyPtr, X509Ptr>> ParseCertificate(std::string_view certificate, std::string_view password,
                                                               const std::vector<std::string>& plistCertificates);

/**
 * @brief 计算数据的 SHA256 哈希值。
 * @param data 待计算的数据。
 * @return 成功返回小写十六进制哈希字符串，失败返回 std::nullopt。
 */
std::optional<std::string> SHA256Hex(std::string_view data);

/**
 * @brief 计算数据的 SHA1 哈希值。
 * @param data 待计算的数据。
 * @return 成功返回小写十六进制哈希字符串，失败返回 std::nullopt。
 */
std::optional<std::string> SHA1Hex(std::string_view data);

/**
 * @brief 将二进制数据进行 Base64 编码。
 * @param data 待编码的数据。
 * @return Base64 编码后的字符串。
 */
std::string Base64Encode(std::string_view data);

}

#endif
