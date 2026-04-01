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
 * @file do_sign.hpp
 * @brief IPA 签名主流程接口声明。
 *
 * 声明 DoSign 函数，该函数是整个 IPA 重签名流程的入口，
 * 负责协调配置解析、证书加载、IPA 解压、plist 修改、代码签名和重新打包等步骤。
 */

#ifndef IPASIGNER_DO_SIGN_HPP
#define IPASIGNER_DO_SIGN_HPP

#include "arguments.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 执行 IPA 签名主流程。
 * @param opts 命令行参数（包含配置文件路径等信息）。
 * @return 程序退出码，0 表示成功，非 0 表示失败（具体错误码见 constants.hpp）。
 */
int DoSign(const Options& opts);

}

#endif
