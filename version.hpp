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
 * @file version.hpp
 * @brief 版本信息接口声明。
 *
 * 声明获取程序版本信息的函数，版本号、构建时间和 Git 提交 ID
 * 在 CMakeLists.txt 中通过宏定义注入。
 */

#ifndef IPASIGNER_VERSION_HPP
#define IPASIGNER_VERSION_HPP

#include <string>

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 获取程序版本信息字符串。
 * @return 包含版本号、构建时间和 Git 提交 ID 的多行字符串。
 */
std::string Version();

}

#endif
