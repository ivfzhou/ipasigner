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
 * @file compress.cpp
 * @brief ZIP 压缩/解压实现。
 *
 * 基于 libzip 库实现 IPA 文件的解压和压缩。
 * - Unzip：多线程并行解压，每个工作线程独立打开归档文件以避免线程安全问题。
 * - Zip：递归遍历目录，支持目录、普通文件和符号链接的打包。
 */

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <ios>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <zip.h>

#include "Logger.tpp"
#include "ScopeGuard.hpp"
#include "common.hpp"
#include "compress.hpp"
#include "constants.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 解压 IPA 文件到指定目录。
 *
 * IPA 文件本质上是 ZIP 格式的压缩包，使用 libzip 多线程并行解压。
 * 由于 libzip 的 zip_t* 句柄非线程安全，每个工作线程独立打开归档文件。
 * 流程：先预扫描创建所有目录，再多线程并行解压文件。
 *
 * @param ipaPath IPA 文件路径。
 * @param destDir 解压目标目录。
 * @return 成功返回 true，失败返回 false。
 */
bool Unzip(const std::filesystem::path& ipaPath, const std::filesystem::path& destDir) {
    // 打开 ZIP 归档文件，用于预扫描条目信息。
    int err{};
    auto archive = zip_open(ipaPath.string().c_str(), ZIP_RDONLY, &err);
    if (!archive) {
        Logger::error("failed to open ipa file:", ipaPath, GetZipErrors(err));
        return false;
    }
    ScopeGuard archiveDeleter{[&archive] { zip_close(archive); }};

    // 获取归档中的条目数量。
    auto numEntries = zip_get_num_entries(archive, 0);
    if (numEntries < 0) {
        Logger::error("failed to get number of entries in ipa archive:", ipaPath);
        return false;
    }

    // 预扫描：收集所有条目信息，先创建所有目录，再收集需要解压的文件条目索引。
    std::vector<zip_uint64_t> fileEntries{};
    for (zip_int64_t i = 0; i < numEntries; i++) {
        auto entryName = zip_get_name(archive, i, 0);
        if (!entryName) {
            Logger::error("failed to get archive entry name, index:", std::to_string(i));
            return false;
        }

        auto destPath = std::filesystem::path(destDir) / entryName;

        // 如果条目名称以 / 结尾，则为目录，创建之。
        if (std::string entryNameStr(entryName); !entryNameStr.empty() && entryNameStr.back() == '/') {
            std::error_code ec{};
            std::filesystem::create_directories(destPath, ec);
            if (ec) {
                Logger::error("failed to create directory:", destPath.string(), ec.message());
                return false;
            }

            continue;
        }

        // 收集文件条目索引，后续多线程处理。
        fileEntries.push_back(i);
    }

    // 如果没有文件条目需要解压，直接返回成功。
    if (fileEntries.empty()) return true;

    // 确定线程数：取 CPU 核心数与文件条目数的较小值。
    auto cpuCores = std::thread::hardware_concurrency();
    auto threadCount =
        std::max(1u, std::min(cpuCores > 0 ? cpuCores + 1 : 1u, static_cast<unsigned>(fileEntries.size())));

    // 用于任务分发的共享状态。
    std::atomic<size_t> nextTask{};
    std::atomic<bool> hasError{};
    std::mutex errorMutex{};
    std::string errorMsg{};

    // 工作线程函数：每个线程独立打开归档文件，从任务队列中取条目索引进行解压。
    auto worker = [&] {
        // 每个线程独立打开归档，避免线程安全问题。
        int threadErr{};
        auto threadArchive = zip_open(ipaPath.string().c_str(), ZIP_RDONLY, &threadErr);
        if (!threadArchive) {
            std::lock_guard lock(errorMutex);
            errorMsg = "failed to open ipa file: " + GetZipErrors(threadErr);
            hasError.store(true);
            return;
        }
        ScopeGuard threadArchiveDeleter{[&threadArchive] { zip_close(threadArchive); }};

        // 循环获取任务并处理。
        while (!hasError.load()) {
            // 原子地获取下一个待处理的任务索引。
            auto taskIdx = nextTask.fetch_add(1);
            if (taskIdx >= fileEntries.size()) break;

            auto entryIndex = fileEntries[taskIdx];

            // 获取条目名称。
            auto entryName = zip_get_name(threadArchive, entryIndex, 0);
            if (!entryName) {
                std::lock_guard lock(errorMutex);
                errorMsg = "failed to get archive entry name, index is " + std::to_string(entryIndex);
                hasError.store(true);
                break;
            }

            std::string entryNameStr(entryName);
            auto destPath = std::filesystem::path(destDir) / entryNameStr;

            // 打开归档中的文件条目。
            auto zipFile = zip_fopen_index(threadArchive, entryIndex, 0);
            if (!zipFile) {
                std::lock_guard lock(errorMutex);
                errorMsg = "failed to open archive entry: " + entryNameStr;
                hasError.store(true);
                break;
            }
            ScopeGuard zipFileDeleter{[&zipFile] { zip_fclose(zipFile); }};

            // 创建输出文件。
            std::ofstream outFile(destPath, std::ios::binary | std::ios::trunc);
            if (!outFile.is_open()) {
                std::lock_guard lock(errorMutex);
                errorMsg = "failed to create output file: " + destPath.string();
                hasError.store(true);
                break;
            }
            ScopeGuard outFileDeleter{[&outFile] { outFile.close(); }};

            // 读取并写入文件内容。
            char buf[ZIP_BUFFER_SIZE];
            zip_int64_t bytesRead{};
            while ((bytesRead = zip_fread(zipFile, buf, ZIP_BUFFER_SIZE)) > 0) {
                outFile.write(buf, bytesRead);
                if (!outFile.good()) {
                    std::lock_guard lock(errorMutex);
                    errorMsg = "failed to write file: " + destPath.string();
                    hasError.store(true);
                    break;
                }
            }
        }
    };

    // 启动工作线程。
    std::vector<std::thread> threads{};
    threads.reserve(threadCount);
    for (unsigned t{}; t < threadCount; t++) threads.emplace_back(worker);

    // 等待所有线程完成。
    for (auto&& th : threads) th.join();

    // 检查是否有错误发生。
    if (hasError.load()) {
        Logger::error(errorMsg);
        return false;
    }

    return true;
}

/**
 * @brief 将 IPA 文件夹打包为 IPA 文件（ZIP 格式）。
 *
 * 递归遍历 ipaDir 下的所有文件和目录，将它们添加到 ZIP 归档中。
 * 支持目录、普通文件和符号链接三种类型。
 * 归档中的条目路径为相对于 ipaDir 的相对路径。
 *
 * @param ipaDir IPA 解压后的根目录。
 * @param outputPath 输出的 IPA 文件路径。
 * @return 成功返回 true，失败返回 false。
 */
bool Zip(const std::filesystem::path& ipaDir, const std::filesystem::path& outputPath) {
    // 创建新的 ZIP 归档文件（若已存在则截断覆盖）。
    int err{};
    auto archive = zip_open(outputPath.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!archive) {
        Logger::error("failed to create zip file:", outputPath, GetZipErrors(err));
        return false;
    }
    ScopeGuard archiveDeleter{[&archive] {
        if (archive) zip_close(archive);
    }};

    // 递归遍历 ipaDir 下的所有条目。
    std::error_code ec{};
    for (auto&& entry : std::filesystem::recursive_directory_iterator(ipaDir, ec)) {
        // 计算相对于 ipaDir 的相对路径，作为归档中的条目名称。
        auto relativePath = std::filesystem::relative(entry.path(), ipaDir, ec);
        if (ec) {
            Logger::error("failed to get relative path:", entry.path().string(), ec.message());
            zip_discard(archive);
            archive = nullptr;
            return false;
        }

        // 将路径分隔符统一为 /（ZIP 规范要求使用正斜杠）。
        auto entryName = relativePath.generic_string();

        if (entry.is_directory(ec)) {
            // 目录条目：名称以 / 结尾。
            auto dirName = entryName + "/";
            if (zip_dir_add(archive, dirName.c_str(), ZIP_FL_ENC_UTF_8) < 0) {
                Logger::error("failed to add directory to zip:", dirName, zip_strerror(archive));
                zip_discard(archive);
                archive = nullptr;
                return false;
            }
        } else if (entry.is_regular_file(ec)) {
            // 文件条目：使用 zip_source_file 从磁盘读取文件内容。
            auto source = zip_source_file(archive, entry.path().string().c_str(), 0, -1);
            if (!source) {
                Logger::error("failed to create zip source for file:", entry.path().string(), zip_strerror(archive));
                zip_discard(archive);
                archive = nullptr;
                return false;
            }

            // 将文件添加到归档中（若同名条目已存在则替换）。
            auto index = zip_file_add(archive, entryName.c_str(), source, ZIP_FL_ENC_UTF_8 | ZIP_FL_OVERWRITE);
            if (index < 0) {
                Logger::error("failed to add file to zip:", entryName, zip_strerror(archive));
                zip_source_free(source);
                zip_discard(archive);
                archive = nullptr;
                return false;
            }

            // 设置压缩方法为 Deflate。
            if (zip_set_file_compression(archive, index, ZIP_CM_DEFLATE, 5) < 0) {
                Logger::error("failed to set compression for file:", entryName, zip_strerror(archive));
                zip_discard(archive);
                archive = nullptr;
                return false;
            }
        } else if (entry.is_symlink(ec)) {
            // 符号链接条目：读取链接目标路径，将其作为文件内容存入归档（不压缩）。
            auto target = std::filesystem::read_symlink(entry.path(), ec);
            if (ec) {
                Logger::error("failed to read symlink:", entry.path().string(), ec.message());
                zip_discard(archive);
                archive = nullptr;
                return false;
            }

            auto targetStr = target.generic_string();
            auto source = zip_source_buffer(archive, targetStr.c_str(), targetStr.size(), 0);
            if (!source) {
                Logger::error("failed to create zip source for symlink:", entry.path().string(), zip_strerror(archive));
                zip_discard(archive);
                archive = nullptr;
                return false;
            }

            auto index = zip_file_add(archive, entryName.c_str(), source, ZIP_FL_ENC_UTF_8 | ZIP_FL_OVERWRITE);
            if (index < 0) {
                Logger::error("failed to add symlink to zip:", entryName, zip_strerror(archive));
                zip_source_free(source);
                zip_discard(archive);
                archive = nullptr;
                return false;
            }

            // 符号链接不压缩，使用 STORE 方式存储。
            if (zip_set_file_compression(archive, index, ZIP_CM_STORE, 0) < 0) {
                Logger::error("failed to set compression for symlink:", entryName, zip_strerror(archive));
                zip_discard(archive);
                archive = nullptr;
                return false;
            }

            // 设置外部属性标记为符号链接（Unix 符号链接标志 0xA0000000）。
            if (zip_file_set_external_attributes(archive, index, 0, ZIP_OPSYS_UNIX, 0xA1FF0000) < 0) {
                Logger::error("failed to set symlink attributes:", entryName, zip_strerror(archive));
                zip_discard(archive);
                archive = nullptr;
                return false;
            }
        }
    }

    if (ec) {
        Logger::error("failed to iterate directory:", ipaDir.string(), ec.message());
        zip_discard(archive);
        archive = nullptr;
        return false;
    }

    // zip_close 会将归档写入磁盘。成功后将 archive 置空，避免 ScopeGuard 重复关闭。
    if (zip_close(archive) < 0) {
        Logger::error("failed to write zip file:", outputPath, zip_strerror(archive));
        zip_discard(archive);
        archive = nullptr;
        return false;
    }
    archive = nullptr;

    return true;
}

}
