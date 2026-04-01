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
 * @file crypto.cpp
 * @brief 加密与证书操作实现。
 *
 * 实现基于 OpenSSL 的加密工具函数，包括 CMS 内容提取、证书解析、
 * 哈希计算和 Base64 编码等功能。
 */

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "openssl/types.h"
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include "Logger.tpp"
#include "ScopeGuard.hpp"
#include "common.hpp"
#include "crypto.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 从描述文件的二进制数据中提取 CMS 签名的 plist 内容。
 *
 * 描述文件（.mobileprovision）采用 DER 编码的 CMS（PKCS#7）格式，
 * 本函数解析 CMS 结构并提取其中的签名内容（即 plist XML 数据）。
 *
 * @param data 描述文件的原始二进制数据。
 * @return 成功返回 plist XML 字符串，失败返回 std::nullopt。
 */
std::optional<std::string> GetCMSFromProvision(const std::string_view data) {
    // 创建内存 BIO，用于将数据喂给 OpenSSL 的 CMS 解析器。
    auto in = BIO_new(BIO_s_mem());
    if (!in) {
        Logger::error("BIO_new failed:", GetOpensslErrors());
        return std::nullopt;
    }
    ScopeGuard inDeleter{[&in] { BIO_free(in); }};

    // 将描述文件数据写入 BIO。
    if (auto dataSize = static_cast<int>(data.size()); BIO_write(in, data.data(), dataSize) != dataSize)
        return std::nullopt;

    // 从 BIO 中解析 DER 编码的 CMS 结构。
    auto cms = d2i_CMS_bio(in, nullptr);
    if (!cms) return std::nullopt;
    ScopeGuard cmsDeleter{[&cms] { CMS_ContentInfo_free(cms); }};

    // 获取 CMS 签名内容（即 plist 数据）。
    auto pos = CMS_get0_content(cms);
    if (!pos || !*pos) return std::nullopt;

    // 将 ASN1_OCTET_STRING 转换为 std::string 返回。
    return std::string(reinterpret_cast<const char*>((*pos)->data), (*pos)->length);
}

/**
 * @brief 获取 X509 证书的主体通用名称（Common Name）。
 *
 * 从证书的 Subject 字段中查找 NID_commonName 条目并返回其值。
 *
 * @param certificate X509 证书指针。
 * @return 成功返回去除首尾空白的通用名称字符串，失败返回 std::nullopt。
 */
std::optional<std::string> GetCommonNameFromCertificate(const X509* certificate) {
    if (!certificate) return std::nullopt;

    // 获取证书的主体名称（Subject）。
    auto name = X509_get_subject_name(certificate);
    if (!name) {
        Logger::error("X509_get_subject_name failed:", GetOpensslErrors());
        return std::nullopt;
    }

    // 在主体名称中查找 Common Name（CN）字段的索引位置。
    auto commonNameLoc = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (commonNameLoc < 0) {
        Logger::error("X509_NAME_get_index_by_NID failed:", GetOpensslErrors());
        return std::nullopt;
    }

    // 获取 Common Name 条目。
    auto commonNameEntry = X509_NAME_get_entry(name, commonNameLoc);
    if (!commonNameEntry) {
        Logger::error("X509_NAME_get_entry failed:", GetOpensslErrors());
        return std::nullopt;
    }

    // 获取条目的 ASN1 数据。
    auto commonNameASN1 = X509_NAME_ENTRY_get_data(commonNameEntry);
    if (!commonNameASN1) {
        Logger::error("X509_NAME_ENTRY_get_data failed:", GetOpensslErrors());
        return std::nullopt;
    }

    return StringTrimBlank(
        std::string_view(reinterpret_cast<const char*>(commonNameASN1->data), commonNameASN1->length));
}

/**
 * @brief 解析证书文件，提取私钥和 X509 证书。
 *
 * 解析策略（按优先级依次尝试）：
 * 1. PEM 格式私钥（PEM_read_bio_PrivateKey）
 * 2. DER 格式私钥（d2i_PrivateKey_bio）
 * 3. PKCS#12 格式（d2i_PKCS12_bio + PKCS12_parse），同时提取证书
 *
 * 若从 PKCS#12 中提取的证书与私钥不匹配，或未从证书文件中获取到证书，
 * 则从描述文件的 DeveloperCertificates 列表中逐一匹配。
 *
 * @param certificate 证书文件的原始内容。
 * @param password 证书密码。
 * @param plistCertificates 描述文件中的开发者证书列表（DER 编码）。
 * @return 成功返回 (私钥, X509证书) 对，失败返回 std::nullopt。
 */
std::optional<std::pair<EvpPkeyPtr, X509Ptr>> ParseCertificate(std::string_view certificate, std::string_view password,
                                                               const std::vector<std::string>& plistCertificates) {

    EvpPkeyPtr evpPKey{};
    X509Ptr x509Cert{};

    // 创建内存 BIO，用于从证书数据中读取私钥。
    auto bioPKey = BIO_new_mem_buf(certificate.data(), static_cast<int>(certificate.size()));
    if (!bioPKey) {
        Logger::error("BIO_new_mem_buf failed:", GetOpensslErrors());
        return std::nullopt;
    }
    ScopeGuard bioPKeyDeleter{[&bioPKey] { BIO_free(bioPKey); }};

    // 尝试方式一：以 PEM 格式读取私钥。
    evpPKey.reset(PEM_read_bio_PrivateKey(bioPKey, nullptr, nullptr,
                                          const_cast<void*>(static_cast<const void*>(password.data()))));
    // 尝试方式二：以 DER 格式读取私钥。
    if (!evpPKey) {
        (void)BIO_reset(bioPKey);
        Logger::warn("PEM_read_bio_PrivateKey failed:", GetOpensslErrors());
        evpPKey.reset(d2i_PrivateKey_bio(bioPKey, nullptr));
    }
    // 尝试方式三：以 PKCS#12 格式解析（需要加载 legacy 和 default provider 以支持旧算法）。
    if (!evpPKey) {
        (void)BIO_reset(bioPKey);
        Logger::warn("d2i_PrivateKey_bio failed:", GetOpensslErrors());
        auto legacyProvider = OSSL_PROVIDER_load(nullptr, "legacy");
        auto defaultProvider = OSSL_PROVIDER_load(nullptr, "default");
        ScopeGuard providerDeleter{[&legacyProvider, &defaultProvider] {
            if (legacyProvider) OSSL_PROVIDER_unload(legacyProvider);
            if (defaultProvider) OSSL_PROVIDER_unload(defaultProvider);
        }};
        if (auto p12 = d2i_PKCS12_bio(bioPKey, nullptr)) {
            EVP_PKEY* rawPKey{};
            X509* rawCert{};
            if (PKCS12_parse(p12, password.data(), &rawPKey, &rawCert, nullptr) == 0) {
                Logger::warn("PKCS12_parse failed:", GetOpensslErrors());
                EVP_PKEY_free(rawPKey);
                X509_free(rawCert);
                rawPKey = nullptr;
                rawCert = nullptr;
            } else {
                evpPKey.reset(rawPKey);
                x509Cert.reset(rawCert);
            }
            PKCS12_free(p12);
        }
    }
    if (!evpPKey) {
        Logger::error("failed to load certificate");
        return std::nullopt;
    }

    // 验证证书与私钥是否匹配，不匹配则丢弃证书。
    if (x509Cert && !X509_check_private_key(x509Cert.get(), evpPKey.get())) x509Cert.reset();

    // 若仍无有效证书，从描述文件的 DeveloperCertificates 列表中逐一尝试匹配。
    if (!x509Cert && !plistCertificates.empty()) {
        for (auto&& v : plistCertificates) {
            auto bioCert = BIO_new_mem_buf(v.c_str(), static_cast<int>(v.size()));
            if (!bioCert) continue;
            ScopeGuard bioCertDeleter{[&bioCert] { BIO_free(bioCert); }};

            x509Cert.reset(d2i_X509_bio(bioCert, nullptr));
            if (!x509Cert) continue;

            if (X509_check_private_key(x509Cert.get(), evpPKey.get())) break;

            x509Cert.reset();
        }
    }
    if (!x509Cert) {
        Logger::error("failed to load certificate");
        return std::nullopt;
    }

    return std::pair(std::move(evpPKey), std::move(x509Cert));
}

// 计算 SHA256。
std::optional<std::string> SHA256Hex(const std::string_view data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength;

    // 创建并初始化摘要上下文。
    auto ctx = EVP_MD_CTX_new();
    if (!ctx) return std::nullopt;
    ScopeGuard ctxDeleter{[&ctx] { EVP_MD_CTX_free(ctx); }};

    // 初始化摘要操作，指定使用 SHA256 算法。
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)) return std::nullopt;

    // 喂入数据进行计算。
    if (!EVP_DigestUpdate(ctx, data.data(), data.size())) return std::nullopt;

    // 完成计算，获取最终的哈希值。
    if (!EVP_DigestFinal_ex(ctx, hash, &hashLength)) return std::nullopt;

    // 打印结果。
    std::string result{};
    result.resize(hashLength * 2);
    auto it = result.begin();
    for (unsigned int&& i = 0; i < hashLength; i++) it = std::format_to(it, "{:02x}", hash[i]);

    return result;
}

// 计算 SHA1。
std::optional<std::string> SHA1Hex(std::string_view data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength;

    // 创建并初始化摘要上下文。
    auto ctx = EVP_MD_CTX_new();
    if (!ctx) return std::nullopt;
    ScopeGuard ctxDeleter{[&ctx] { EVP_MD_CTX_free(ctx); }};

    // 初始化摘要操作，指定使用 SHA1 算法。
    if (!EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr)) return std::nullopt;

    // 喂入数据进行计算。
    if (!EVP_DigestUpdate(ctx, data.data(), data.size())) return std::nullopt;

    // 完成计算，获取最终的哈希值。
    if (!EVP_DigestFinal_ex(ctx, hash, &hashLength)) return std::nullopt;

    // 打印结果。
    std::string result{};
    result.resize(hashLength * 2);
    auto it = result.begin();
    for (unsigned int&& i = 0; i < hashLength; i++) it = std::format_to(it, "{:02x}", hash[i]);

    return result;
}

/**
 * @brief 将二进制数据进行 Base64 编码。
 * @param data 待编码的数据。
 * @return Base64 编码后的字符串。
 */
std::string Base64Encode(const std::string_view data) {
    auto dataLen = static_cast<int>(data.size());
    // 计算 Base64 编码后的长度：每 3 字节编码为 4 字符，加 1 字节用于 null 终止符。
    auto base64Len = 4 * ((dataLen + 2) / 3) + 1;
    std::vector<unsigned char> base64Buf(base64Len);
    EVP_EncodeBlock(base64Buf.data(), reinterpret_cast<const unsigned char*>(data.data()), dataLen);
    return {reinterpret_cast<char*>(base64Buf.data())};
}

}
