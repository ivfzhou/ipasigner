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
 * @file Options.hpp
 * @brief 命令行参数解析结果声明。
 *
 * 定义 Options 类，用于承载解析得到的全局选项
 * （版本、帮助、详细输出）与签名子命令选项（SignOptions）。
 */

#ifndef COM_GITEE_IVFZHOU_IPASIGNER_ARGUMENT_OPTIONS_HPP
#define COM_GITEE_IVFZHOU_IPASIGNER_ARGUMENT_OPTIONS_HPP

#include <ostream>

#include "argument/SignOptions.hpp"

namespace com::gitee::ivfzhou::ipasigner {

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

    /// 是否启用详细输出（DEBUG 日志）。
    bool verbose{};

    /// 签名子命令的配置选项。
    SignOptions signOpts;
};

}

#endif
