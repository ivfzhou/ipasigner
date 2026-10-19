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
 * @file Options.cpp
 * @brief Options 的格式化输出实现。
 *
 * 实现 operator<< 友元函数，用于将 Options 对象
 * 以可读形式输出到输出流。
 */

#include <ios>
#include <ostream>

#include "Options.hpp"

namespace com::gitee::ivfzhou::ipasigner {

/**
 * @brief 友元函数，将 Options 对象格式化输出到流。
 * @param out 输出流。
 * @param opts 待输出的 Options 对象。
 * @return 输出流的引用。
 */
std::ostream& operator<<(std::ostream& out, const Options& opts) {
    out << "signOpts.configurationFilePath: " << opts.signOpts.configurationFilePath << std::endl;
    out << "version: " << std::boolalpha << opts.version << std::endl;
    out << "help: " << std::boolalpha << opts.help << std::endl;
    return out;
}

}
