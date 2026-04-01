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
 * @file arguments.hpp
 * @brief 命令行参数解析接口声明。
 *
 * 定义了命令行参数相关的数据结构（Options、SignOptions）和解析函数。
 * 本程序使用子命令模式：`ipasigner sign <configuration>` 执行签名操作。
 */

#ifndef IPASIGNER_ARGUMENTS_HPP
#define IPASIGNER_ARGUMENTS_HPP

#include <optional>
#include <ostream>
#include <string>

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 签名子命令的配置选项。
 */
class SignOptions final {
  public:
    /// YAML 格式的签名配置文件路径。
    std::string configrationFilePath;
};

/**
 * @brief 命令行参数解析结果。
 *
 * 包含全局选项（版本、帮助）和子命令选项（签名配置）。
 */
class Options final {
    /// 友元函数，用于将 Options 格式化输出到流。
    friend std::ostream& operator<<(std::ostream& out, const Options& opts);

  public:
    /// 是否请求打印版本信息（--version）。
    bool version{};

    /// 是否请求打印帮助信息（--help）。
    bool help{};

    /// 是否使用签名子命令（sign）。
    bool sign{};

    /// 签名子命令的配置选项。
    SignOptions signOpts;
};

/**
 * @brief 解析命令行参数。
 *
 * 使用 argparse 库解析命令行参数，支持 sign 子命令。
 * 若解析失败或未指定子命令，会打印帮助信息。
 *
 * @param argc 命令行参数个数。
 * @param argv 命令行参数数组。
 * @return 成功返回解析后的 Options 对象，失败返回 std::nullopt。
 */
std::optional<Options> ParseCommandFlags(int argc, const char* argv[]);

}

#endif
