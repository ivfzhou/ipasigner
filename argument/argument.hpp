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
 * @file argument.hpp
 * @brief 命令行参数解析接口声明。
 *
 * 定义了命令行参数相关的数据结构（Options、SignOptions）和解析函数。
 * 本程序使用子命令模式：`ipasigner sign <configuration>` 执行签名操作。
 */

#ifndef COM_GITEE_IVFZHOU_IPASIGNER_ARGUMENT_ARGUMENT_HPP
#define COM_GITEE_IVFZHOU_IPASIGNER_ARGUMENT_ARGUMENT_HPP

#include <optional>

#include "Options.hpp"

namespace com::gitee::ivfzhou::ipasigner {

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
