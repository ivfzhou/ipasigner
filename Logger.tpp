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
 * @file Logger.tpp
 * @brief 日志工具类（模板实现）。
 *
 * 提供一个轻量级的日志输出工具类 Logger，支持 info/warn/error 三个级别。
 * 日志格式为：时间戳 级别 消息内容（多个参数以空格分隔）。
 * 输出中的换行符会被转义为 \n，回车符转义为 \r，以保证单行输出。
 * 使用 C++20 的变参模板和折叠表达式实现任意数量参数的格式化输出。
 */

#ifndef IPASIGNER_LOGGER_TPP
#define IPASIGNER_LOGGER_TPP

#include <chrono>
#include <cstddef>
#include <format>
#include <iostream>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include "constants.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 日志工具类，提供静态方法输出带时间戳的日志。
 *
 * 所有方法均为静态方法，无需实例化。日志输出到 std::cout。
 */
class Logger final {
  public:
    /// 输出 INFO 级别日志。
    template <typename... T> static void info(T&&... args) { println(std::cout, LEVEL_INFO, std::forward<T>(args)...); }

    /// 输出 INFO 级别日志。
    template <typename... T> static void infof(const std::string_view& fmt, T&&... args) {
        println(std::cout, LEVEL_INFO, std::vformat(fmt, std::make_format_args(std::forward<T>(args)...)));
    }

    /// 输出 WARN 级别日志。
    template <typename... T> static void warn(T&&... args) { println(std::cout, LEVEL_WARN, std::forward<T>(args)...); }

    /// 输出 WARN 级别日志。
    template <typename... T> static void warnf(const std::string_view& fmt, T&&... args) {
        println(std::cout, LEVEL_WARN, std::vformat(fmt, std::make_format_args(std::forward<T>(args)...)));
    }

    /// 输出 ERROR 级别日志。
    template <typename... T> static void error(T&&... args) {
        println(std::cout, LEVEL_ERROR, std::forward<T>(args)...);
    }

    /// 输出 ERROR 级别日志。
    template <typename... T> static void errorf(const std::string_view& fmt, T&&... args) {
        println(std::cout, LEVEL_ERROR, std::vformat(fmt, std::make_format_args(std::forward<T>(args)...)));
    }

    /// 输出 DEBUG 级别日志。
    template <typename... T> static void debug(T&&... args) {
        println(std::cout, LEVEL_DEBUG, std::forward<T>(args)...);
    }

    /// 输出 DEBUG 级别日志。
    template <typename... T> static void debugf(const std::string_view& fmt, T&&... args) {
        println(std::cout, LEVEL_DEBUG, std::vformat(fmt, std::make_format_args(std::forward<T>(args)...)));
    }

    /**
     * @brief 格式化并输出一行日志到指定输出流。
     * @param out 输出流。
     * @param args 日志内容参数（第一个通常为日志级别）。
     */
    template <typename... T> static void println(std::ostream& out, T&&... args) {
        out << Logger::formatArguments(Logger::now(), std::forward<T>(args)...) << std::endl;
    }

  private:
    /**
     * @brief 将多个参数格式化为单行字符串，参数间以空格分隔。
     *
     * 对每个参数中的换行符和回车符进行转义，确保日志输出为单行。
     * @param args 待格式化的参数列表。
     * @return 格式化后的字符串。
     */
    template <typename... T> static std::string formatArguments(T&&... args) {
        std::ostringstream oss{};
        std::size_t index{};
        constexpr std::size_t total = sizeof...(args);
        // 转义函数：将参数转为字符串并转义其中的 \n 和 \r。
        auto escape_string = []<typename T1>(T1&& arg) {
            std::ostringstream temp{};
            temp << std::forward<T1>(arg);
            std::string escaped{};
            for (auto&& c : temp.str()) {
                if (c == '\n')
                    escaped += "\\n";
                else if (c == '\r')
                    escaped += "\\r";
                else
                    escaped += c;
            }
            return escaped;
        };
        // 使用折叠表达式依次输出每个参数，参数间以空格分隔。
        ((oss << escape_string(std::forward<T>(args)) << (++index < total ? " " : "")), ...);
        return oss.str();
    }

    /**
     * @brief 获取当前本地时间的格式化字符串。
     * @return 格式为 "YYYY-MM-DD HH:MM:SS.mmm" 的时间字符串。
     */
    static std::string now() {
        return std::format("{:%Y-%m-%d %H:%M:%S}",
                           std::chrono::current_zone()->to_local(
                               std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now())));
    }
};

}

#endif
