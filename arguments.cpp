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
 * @file arguments.cpp
 * @brief 命令行参数解析实现。
 *
 * 使用 argparse 库实现命令行参数解析，支持 sign 子命令。
 * sign 子命令接受一个必选参数：YAML 格式的签名配置文件路径。
 */

#include <exception>
#include <ios>
#include <iostream>
#include <optional>
#include <ostream>
#include <string>

#include <argparse/argparse.hpp>

#include "arguments.hpp"
#include "constants.hpp"
#include "version.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 友元函数，将 Options 对象格式化输出到流。
 * @param out 输出流。
 * @param opts 待输出的 Options 对象。
 * @return 输出流的引用。
 */
std::ostream& operator<<(std::ostream& out, const Options& opts) {
    out << "signOpts.configrationFilePath: " << opts.signOpts.configrationFilePath << std::endl;
    out << "version: " << std::boolalpha << opts.version << std::endl;
    out << "help: " << std::boolalpha << opts.help << std::endl;
    return out;
}

/**
 * @brief 解析命令行参数。
 *
 * 创建 argparse 解析器，注册 sign 子命令及其参数，
 * 解析命令行后提取各选项值。若未指定子命令则打印帮助信息。
 *
 * @param argc 命令行参数个数。
 * @param argv 命令行参数数组。
 * @return 成功返回解析后的 Options 对象，失败返回 std::nullopt。
 */
std::optional<Options> ParseCommandFlags(const int argc, const char* argv[]) {
    argparse::ArgumentParser parser(PROJECT_NAME, Version());
    argparse::ArgumentParser signCommand(OPTION_SUBCOMMAND_SIGN, "", argparse::default_arguments::help);
    try {
        // 设置解析器：配置前缀字符、描述信息和项目链接。
        parser.set_prefix_chars(OPTION_PREFIXES);
        parser.add_description("Used to signing ios/ipa file");
        parser.add_epilog("Contribute to https://github.com/ivfzhou/ipasigner");

        // 注册 sign 子命令的必选参数：配置文件路径。
        signCommand.add_argument(OPTION_CONFIGURATION_FILE_PATH).help("yaml format sign configuration file").required();
        parser.add_subparser(signCommand);

        // 执行命令行解析。
        parser.parse_args(argc, argv);

        // 从解析结果中提取各选项值。
        Options opts{};
        opts.help = parser["--help"] == true;
        opts.version = parser["--version"] == true;
        opts.sign = parser.is_subcommand_used(OPTION_SUBCOMMAND_SIGN);
        if (opts.sign)
            if (auto value = signCommand.present(OPTION_CONFIGURATION_FILE_PATH))
                opts.signOpts.configrationFilePath = *value;

        // 如果没有指定任何子命令，打印帮助信息供用户参考。
        if (!parser.is_subcommand_used(OPTION_SUBCOMMAND_SIGN)) std::cout << parser << std::endl;

        return opts;
    } catch (const std::exception& e) {
        // 解析失败时输出错误信息和对应的帮助文本。
        std::cout << e.what() << std::endl;

        // 根据是否使用了 sign 子命令，打印对应的帮助信息。
        if (parser.is_subcommand_used(OPTION_SUBCOMMAND_SIGN))
            std::cout << signCommand << std::endl;
        else
            std::cout << parser << std::endl;

        return std::nullopt;
    }
}

}
