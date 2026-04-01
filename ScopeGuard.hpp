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
 * @file ScopeGuard.hpp
 * @brief 作用域守卫（RAII 资源清理器）。
 *
 * 提供一个通用的 ScopeGuard 模板类，用于在作用域退出时自动执行清理操作。
 * 典型用法：在获取资源后立即创建 ScopeGuard，确保无论正常退出还是异常退出都能释放资源。
 *
 * 示例：
 * @code
 *   auto file = fopen("test.txt", "r");
 *   ScopeGuard guard{[&file] { fclose(file); }};
 *   // ... 使用 file，离开作用域时自动关闭 ...
 * @endcode
 */

#ifndef IPASIGNER_SCOPE_GUARD_HPP
#define IPASIGNER_SCOPE_GUARD_HPP

#include <type_traits>
#include <utility>

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 作用域守卫模板类，析构时自动执行注册的清理函数。
 * @tparam F 可调用对象类型（lambda、函数指针、std::function 等）。
 */
template <typename F> class ScopeGuard {
    F fn; ///< 清理函数。
    bool active; ///< 是否激活（未被 dismiss）。

  public:
    /// 构造：接受右值可调用对象（完美转发）。
    explicit ScopeGuard(F&& fn) noexcept(std::is_nothrow_move_constructible_v<F>) : fn(std::move(fn)), active(true) {}

    /// 构造：接受左值可调用对象（拷贝）。
    explicit ScopeGuard(const F& fn) noexcept(std::is_nothrow_copy_constructible_v<F>) : fn(fn), active(true) {}

    /// 移动构造（转移所有权，原对象被 dismiss）。
    ScopeGuard(ScopeGuard&& other) noexcept(std::is_nothrow_move_constructible_v<F>)
        : fn(std::move(other.fn)), active(other.active) {
        other.dismiss();
    }

    // 禁止拷贝和赋值，防止重复执行清理。
    ScopeGuard(const ScopeGuard&) = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;
    ScopeGuard& operator=(ScopeGuard&&) = delete;

    /// 析构时若仍处于激活状态，则执行清理函数。
    ~ScopeGuard() noexcept {
        if (active) fn();
    }

    /// 手动取消守卫（不再执行清理），用于资源所有权已转移的场景。
    void dismiss() noexcept { active = false; }
};

/// CTAD 推导指引，允许从可调用对象直接构造 ScopeGuard。
template <typename F> ScopeGuard(F) -> ScopeGuard<F>;

}

#endif
