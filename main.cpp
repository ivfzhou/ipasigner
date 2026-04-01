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
 * @file main.cpp
 * @brief 程序入口文件。
 *
 * 本程序是一个 iOS IPA 文件重签名工具，支持通过命令行参数指定 YAML 配置文件，
 * 完成对 IPA 包的证书替换、描述文件替换、Bundle ID 修改、动态库注入等签名操作。
 */

#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>

#include "constants.hpp"
#include "do_sign.hpp"

using namespace gitee::com::ivfzhou;

/**
 * @brief 程序主入口函数。
 * @param argc 命令行参数个数。
 * @param argv 命令行参数数组。
 * @return 程序退出码，0 表示成功，非 0 表示失败（具体错误码见 constants.hpp）。
 */
int main(const int argc, const char* argv[]) {
#ifdef WINDOWS
    // 让控制台用 UTF-8 解码。
    SetConsoleOutputCP(CP_UTF8);
#endif

    // 解析命令行参数。
    auto opts = ipasigner::ParseCommandFlags(argc, argv);
    if (!opts) std::exit(ipasigner::EXIT_CODE_PARSE_OPTIONS_ERROR);

    // 执行签名。
    if (opts->sign) std::exit(ipasigner::DoSign(*opts));

    return 0;
}
