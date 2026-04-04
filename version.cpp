/*
 * Copyright (c) 2024 ivfzhou
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
 * @file version.cpp
 * @brief 版本信息接口实现。
 *
 * 实现 Version() 函数，拼接由 CMake 注入的 VERSION、BUILT_TIME、GIT_COMMIT_ID 宏，
 * 生成可读的版本信息字符串。
 */

#include <string>

#include "constants.hpp"
#include "version.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 获取程序版本信息字符串。
 *
 * 拼接版本号、构建时间和 Git 提交 ID，每项占一行。
 * @return 格式化的版本信息字符串。
 */
std::string Version() {
    std::string info{};
    info.append("Version: ").append(VERSION).append(NewLine());
    info.append("Built Time: ").append(BUILT_TIME).append(NewLine());
    info.append("Git Commit ID: ").append(GIT_COMMIT_ID).append(NewLine());
    return info;
}

}
