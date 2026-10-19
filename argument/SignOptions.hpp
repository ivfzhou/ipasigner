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
 * @file SignOptions.hpp
 * @brief 签名子命令配置选项声明。
 *
 * 定义 sign 子命令解析得到的配置数据类 SignOptions，
 * 目前仅承载 YAML 格式的签名配置文件路径。
 */

#ifndef COM_GITEE_IVFZHOU_IPASIGNER_ARGUMENT_SIGNOPTIONS_HPP
#define COM_GITEE_IVFZHOU_IPASIGNER_ARGUMENT_SIGNOPTIONS_HPP

#include <string>

namespace com::gitee::ivfzhou::ipasigner {

/**
 * @brief 签名子命令的配置选项。
 */
class SignOptions final {
  public:
    /// YAML 格式的签名配置文件路径。
    std::string configurationFilePath;
};

}

#endif
