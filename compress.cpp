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
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <ios>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include <zip.h>
#include <zlib.h>

#include "Logger.tpp"
#include "ScopeGuard.hpp"
#include "common.hpp"
#include "compress.hpp"
#include "constants.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 将 std::filesystem::path 转换为 UTF-8 编码的 std::string。
 *
 * 在 Windows 上 path::string() 默认使用系统 ANSI 编码（如 CP936），
 * 这会导致非 ASCII 文件名（如中文名）在写入 zip 中央目录时被错误编码，
 * 进而使 zsign / Apple plist 工具读出乱码。本函数显式按 UTF-8 转换。
 *
 * @param p 文件系统路径。
 * @return UTF-8 编码的字符串表示。
 */
static std::string pathToUtf8(const std::filesystem::path& p) {
#ifdef _WIN32
    auto wide = p.wstring();
    if (wide.empty()) return {};
    auto u8len =
        WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (u8len <= 0) return p.string();
    std::string utf8(static_cast<std::size_t>(u8len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(), u8len, nullptr, nullptr);
    return utf8;
#else
    return p.string();
#endif
}

/**
 * @brief 将 UTF-8 编码的字符串安全地转换为 std::filesystem::path。
 *
 * 在 Windows 上 std::filesystem::path 默认假定 const char* 是系统 ANSI 编码（如 GBK/CP936），
 * 直接构造 path 时 UTF-8 字节会被错误解码为 ANSI，导致中文等非 ASCII 文件名被破坏。
 * 本函数显式将 UTF-8 字节转为 UTF-16 后再构造 path，保证文件名正确。
 *
 * @param utf8 UTF-8 编码的字符串。
 * @return 由 UTF-16 字符串构造的 std::filesystem::path。
 */
static std::filesystem::path utf8ToPath(const std::string_view utf8) {
#ifdef _WIN32
    if (utf8.empty()) return {};
    auto wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (wlen <= 0) return std::filesystem::path(std::string(utf8));
    std::wstring wide(static_cast<std::size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), wlen);
    return std::filesystem::path(wide);
#else
    return std::filesystem::path(std::string(utf8));
#endif
}

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

        auto destPath = std::filesystem::path(destDir) / utf8ToPath(entryName);

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
            auto destPath = std::filesystem::path(destDir) / utf8ToPath(entryNameStr);

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
 * 实现策略：
 *   1. 扫描 ipaDir，把所有目录条目、文件条目、符号链接条目分类收集；
 *   2. 多线程并行使用 zlib raw deflate（windowBits = -15）压缩各文件到内存缓冲区，
 *      并计算 CRC32；
 *   3. 主线程串行写入 ZIP 流：local file header + 已压缩数据 + central directory + EOCD。
 *
 * 这样压缩计算（CPU 密集）可以充分利用多核，IO 写入是顺序流式，避免在 libzip
 * 内部串行 deflate 成为瓶颈。
 *
 * @param ipaDir IPA 解压后的根目录。
 * @param outputPath 输出的 IPA 文件路径。
 * @param compressLevel 压缩等级 [0, 9]，0 = 不压缩，9 = 最高压缩。
 * @return 成功返回 true，失败返回 false。
 */
namespace {

/// ZIP 中央目录条目记录。
struct ZipEntry {
    enum class Kind { Dir, File, Symlink };
    Kind kind{};
    std::string name{}; ///< UTF-8 格式的归档条目名（目录以 / 结尾）。
    std::filesystem::path filePath{}; ///< 文件类型：磁盘上的源路径。
    std::string symlinkTarget{}; ///< 符号链接目标路径（UTF-8）。
    std::vector<std::uint8_t> data{}; ///< 压缩后的数据（File/Symlink 已压缩；Dir 为空）。
    std::uint32_t crc32{}; ///< CRC-32 校验和。
    std::uint64_t uncompSize{}; ///< 未压缩大小。
    std::uint64_t compSize{}; ///< 压缩后大小。
    std::uint16_t method{}; ///< 0 = STORE，8 = DEFLATE。
    std::uint64_t localHeaderOffset{}; ///< 在最终 ZIP 文件中的 local header 偏移。
    bool prepared{}; ///< 是否已完成压缩准备。
};

/// 安全打开二进制文件，跨平台支持宽字符路径。
static std::FILE* openBinaryRead(const std::filesystem::path& filePath) {
#ifdef _WIN32
    std::FILE* fp{};
    if (_wfopen_s(&fp, filePath.wstring().c_str(), L"rb") != 0) return nullptr;
    return fp;
#else
    return std::fopen(filePath.string().c_str(), "rb");
#endif
}

/// 计算 ZIP 标准 DOS 时间字段（这里固定取一个稳定值，避免每次签名结果不一致）。
static std::pair<std::uint16_t, std::uint16_t> dosTimeStamp() {
    // 2026-01-01 00:00:00。
    constexpr std::uint16_t dosDate = ((2026 - 1980) << 9) | (1 << 5) | 1;
    constexpr std::uint16_t dosTime = 0;
    return {dosTime, dosDate};
}

/// 使用 zlib raw deflate 将输入字节压缩为 ZIP 兼容的 deflate 流。
static bool deflateToBuffer(const std::uint8_t* input, std::size_t inputSize, int level,
                            std::vector<std::uint8_t>& out) {
    z_stream zs{};
    // windowBits = -15 表示 raw deflate（无 zlib header/trailer），正是 ZIP 所需。
    if (deflateInit2(&zs, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) return false;

    out.clear();
    out.reserve(inputSize / 2 + 128);

    constexpr std::size_t chunkSize = 64 * 1024;
    std::vector<std::uint8_t> buf(chunkSize);

    zs.next_in = const_cast<Bytef*>(input);
    zs.avail_in = static_cast<uInt>(inputSize);
    int ret{};
    do {
        zs.next_out = buf.data();
        zs.avail_out = static_cast<uInt>(buf.size());
        ret = deflate(&zs, Z_FINISH);
        if (ret == Z_STREAM_ERROR) {
            deflateEnd(&zs);
            return false;
        }
        auto produced = buf.size() - zs.avail_out;
        out.insert(out.end(), buf.begin(), buf.begin() + produced);
    } while (ret != Z_STREAM_END);

    deflateEnd(&zs);
    return true;
}

/// 串行写入工具：以二进制方式追加到输出流，跨平台支持宽字符路径。
class ZipWriter {
  public:
    bool open(const std::filesystem::path& outputPath) {
#ifdef _WIN32
        if (_wfopen_s(&fp_, outputPath.wstring().c_str(), L"wb") != 0) return false;
#else
        fp_ = std::fopen(outputPath.string().c_str(), "wb");
#endif
        return fp_ != nullptr;
    }

    ~ZipWriter() {
        if (fp_) std::fclose(fp_);
    }

    bool write(const void* data, std::size_t size) {
        if (size == 0) return true;
        auto written = std::fwrite(data, 1, size, fp_);
        if (written != size) return false;
        offset_ += size;
        return true;
    }

    template <typename T> bool writeLE(T value) {
        std::uint8_t buf[sizeof(T)];
        for (std::size_t i = 0; i < sizeof(T); ++i) buf[i] = static_cast<std::uint8_t>(value >> (i * 8) & 0xFF);
        return write(buf, sizeof(T));
    }

    [[nodiscard]] std::uint64_t offset() const { return offset_; }

    bool close() {
        if (!fp_) return true;
        auto ok = std::fclose(fp_) == 0;
        fp_ = nullptr;
        return ok;
    }

  private:
    std::FILE* fp_{};
    std::uint64_t offset_{};
};

constexpr std::uint32_t LOCAL_FILE_HEADER_SIG = 0x04034b50;
constexpr std::uint32_t CENTRAL_DIR_HEADER_SIG = 0x02014b50;
constexpr std::uint32_t END_OF_CENTRAL_DIR_SIG = 0x06054b50;

}

bool Zip(const std::filesystem::path& ipaDir, const std::filesystem::path& outputPath, const int compressLevel) {
    auto level = std::clamp(compressLevel, 0, 9);

    // 第 1 步：扫描所有条目，收集元信息（不读文件内容）。
    std::vector<ZipEntry> entries{};
    std::error_code ec{};
    for (auto&& entry : std::filesystem::recursive_directory_iterator(ipaDir, ec)) {
        auto relativePath = std::filesystem::relative(entry.path(), ipaDir, ec);
        if (ec) {
            Logger::error("failed to get relative path:", pathToUtf8(entry.path()), ec.message());
            return false;
        }

        // UTF-8 归档名。
        std::string entryName{};
#ifdef _WIN32
        {
            auto wname = relativePath.generic_wstring();
            if (!wname.empty()) {
                auto u8len = WideCharToMultiByte(CP_UTF8, 0, wname.data(), static_cast<int>(wname.size()), nullptr, 0,
                                                 nullptr, nullptr);
                if (u8len > 0) {
                    entryName.resize(static_cast<std::size_t>(u8len));
                    WideCharToMultiByte(CP_UTF8, 0, wname.data(), static_cast<int>(wname.size()), entryName.data(),
                                        u8len, nullptr, nullptr);
                }
            }
        }
        if (entryName.empty()) entryName = relativePath.generic_string();
#else
        entryName = relativePath.generic_string();
#endif

        ZipEntry zipEntry{};
        zipEntry.name = std::move(entryName);
        if (entry.is_symlink(ec)) {
            zipEntry.kind = ZipEntry::Kind::Symlink;
            auto target = std::filesystem::read_symlink(entry.path(), ec);
            if (ec) {
                Logger::error("failed to read symlink:", pathToUtf8(entry.path()), ec.message());
                return false;
            }
            zipEntry.symlinkTarget = pathToUtf8(target);
        } else if (entry.is_directory(ec)) {
            zipEntry.kind = ZipEntry::Kind::Dir;
            if (zipEntry.name.empty() || zipEntry.name.back() != '/') zipEntry.name += '/';
        } else if (entry.is_regular_file(ec)) {
            zipEntry.kind = ZipEntry::Kind::File;
            zipEntry.filePath = entry.path();
        } else {
            // 未知类型跳过。
            continue;
        }
        entries.push_back(std::move(zipEntry));
    }
    if (ec) {
        Logger::error("failed to iterate directory:", pathToUtf8(ipaDir), ec.message());
        return false;
    }

    // 第 2 步：多线程并行压缩文件条目。
    std::vector<std::size_t> compressIndices{};
    compressIndices.reserve(entries.size());
    for (std::size_t i = 0; i < entries.size(); ++i) {
        auto& e = entries[i];
        if (e.kind == ZipEntry::Kind::File) {
            compressIndices.push_back(i);
        } else if (e.kind == ZipEntry::Kind::Symlink) {
            // 符号链接以 STORE 形式存储，提前完成。
            auto& target = e.symlinkTarget;
            e.uncompSize = target.size();
            e.compSize = target.size();
            e.method = 0;
            e.crc32 = ::crc32(0L, reinterpret_cast<const Bytef*>(target.data()), static_cast<uInt>(target.size()));
            e.data.assign(reinterpret_cast<const std::uint8_t*>(target.data()),
                          reinterpret_cast<const std::uint8_t*>(target.data()) + target.size());
            e.prepared = true;
        } else {
            // 目录。
            e.method = 0;
            e.prepared = true;
        }
    }

    if (!compressIndices.empty()) {
        auto cpuCores = std::thread::hardware_concurrency();
        auto threadCount =
            std::max(1u, std::min(cpuCores > 0 ? cpuCores : 4u, static_cast<unsigned>(compressIndices.size())));

        std::atomic<std::size_t> nextTask{};
        std::atomic<bool> hasError{};
        std::mutex errorMutex{};
        std::string errorMsg{};

        auto worker = [&] {
            while (!hasError.load(std::memory_order_acquire)) {
                auto idx = nextTask.fetch_add(1, std::memory_order_relaxed);
                if (idx >= compressIndices.size()) break;
                auto& e = entries[compressIndices[idx]];

                // 读取整个文件到内存。
                auto fp = openBinaryRead(e.filePath);
                if (!fp) {
                    std::lock_guard lock(errorMutex);
                    errorMsg = "failed to open file: " + pathToUtf8(e.filePath);
                    hasError.store(true, std::memory_order_release);
                    return;
                }
                ScopeGuard fpGuard{[&fp] { std::fclose(fp); }};

                std::error_code fec{};
                auto fileSize = std::filesystem::file_size(e.filePath, fec);
                if (fec) {
                    std::lock_guard lock(errorMutex);
                    errorMsg = "failed to stat file: " + pathToUtf8(e.filePath) + " " + fec.message();
                    hasError.store(true, std::memory_order_release);
                    return;
                }

                std::vector<std::uint8_t> raw(static_cast<std::size_t>(fileSize));
                if (fileSize > 0) {
                    auto readBytes = std::fread(raw.data(), 1, raw.size(), fp);
                    if (readBytes != raw.size()) {
                        std::lock_guard lock(errorMutex);
                        errorMsg = "failed to read file: " + pathToUtf8(e.filePath);
                        hasError.store(true, std::memory_order_release);
                        return;
                    }
                }

                // 计算 CRC-32。
                e.crc32 = ::crc32(0L, raw.data(), static_cast<uInt>(raw.size()));
                e.uncompSize = raw.size();

                if (level == 0 || raw.empty()) {
                    e.method = 0;
                    e.data = std::move(raw);
                    e.compSize = e.data.size();
                } else {
                    e.method = 8;
                    if (!deflateToBuffer(raw.data(), raw.size(), level, e.data)) {
                        std::lock_guard lock(errorMutex);
                        errorMsg = "deflate failed: " + pathToUtf8(e.filePath);
                        hasError.store(true, std::memory_order_release);
                        return;
                    }
                    e.compSize = e.data.size();
                }
                e.prepared = true;
            }
        };

        std::vector<std::thread> threads{};
        threads.reserve(threadCount);
        for (unsigned t = 0; t < threadCount; ++t) threads.emplace_back(worker);
        for (auto& th : threads) th.join();

        if (hasError.load()) {
            Logger::error(errorMsg);
            return false;
        }
    }

    // 第 3 步：串行写入 ZIP 流（local file headers + 数据）。
    ZipWriter writer{};
    if (!writer.open(outputPath)) {
        Logger::error("failed to create zip file:", pathToUtf8(outputPath));
        return false;
    }
    ScopeGuard writerGuard{[&writer, &outputPath] {
        if (writer.offset() == 0) {
            writer.close();
            std::error_code rec{};
            std::filesystem::remove(outputPath, rec);
        }
    }};

    auto [dosTime, dosDate] = dosTimeStamp();

    auto writeEntry = [&](ZipEntry& e) -> bool {
        e.localHeaderOffset = writer.offset();

        // local file header。
        if (!writer.writeLE<std::uint32_t>(LOCAL_FILE_HEADER_SIG)) return false;
        if (!writer.writeLE<std::uint16_t>(20)) return false; // version needed
        if (!writer.writeLE<std::uint16_t>(0)) return false; // flags（不含 UTF-8 标志，保持兼容性）
        if (!writer.writeLE<std::uint16_t>(e.method)) return false;
        if (!writer.writeLE<std::uint16_t>(dosTime)) return false;
        if (!writer.writeLE<std::uint16_t>(dosDate)) return false;
        if (!writer.writeLE<std::uint32_t>(e.crc32)) return false;
        if (!writer.writeLE<std::uint32_t>(static_cast<std::uint32_t>(e.compSize))) return false;
        if (!writer.writeLE<std::uint32_t>(static_cast<std::uint32_t>(e.uncompSize))) return false;
        if (!writer.writeLE<std::uint16_t>(static_cast<std::uint16_t>(e.name.size()))) return false;
        if (!writer.writeLE<std::uint16_t>(0)) return false; // extra length
        if (!writer.write(e.name.data(), e.name.size())) return false;
        if (!e.data.empty() && !writer.write(e.data.data(), e.data.size())) return false;
        return true;
    };

    for (auto& e : entries) {
        if (!writeEntry(e)) {
            Logger::error("failed to write zip entry:", e.name);
            return false;
        }
    }

    // 第 4 步：写入 central directory。
    auto centralDirOffset = writer.offset();
    for (auto& e : entries) {
        if (!writer.writeLE<std::uint32_t>(CENTRAL_DIR_HEADER_SIG)) return false;
        // version made by: 0x031E = Unix 3.0 (与 iOS IPA 习惯一致)。
        if (!writer.writeLE<std::uint16_t>(0x031E)) return false;
        if (!writer.writeLE<std::uint16_t>(20)) return false; // version needed
        if (!writer.writeLE<std::uint16_t>(0)) return false; // flags
        if (!writer.writeLE<std::uint16_t>(e.method)) return false;
        if (!writer.writeLE<std::uint16_t>(dosTime)) return false;
        if (!writer.writeLE<std::uint16_t>(dosDate)) return false;
        if (!writer.writeLE<std::uint32_t>(e.crc32)) return false;
        if (!writer.writeLE<std::uint32_t>(static_cast<std::uint32_t>(e.compSize))) return false;
        if (!writer.writeLE<std::uint32_t>(static_cast<std::uint32_t>(e.uncompSize))) return false;
        if (!writer.writeLE<std::uint16_t>(static_cast<std::uint16_t>(e.name.size()))) return false;
        if (!writer.writeLE<std::uint16_t>(0)) return false; // extra length
        if (!writer.writeLE<std::uint16_t>(0)) return false; // comment length
        if (!writer.writeLE<std::uint16_t>(0)) return false; // disk number
        if (!writer.writeLE<std::uint16_t>(0)) return false; // internal file attrs
        // 外部属性：目录 = 0x41ED0010（drwxr-xr-x + DOS dir bit），
        // 符号链接 = 0xA1ED0000（lrwxr-xr-x），文件 = 0x81A40000（-rw-r--r--）。
        std::uint32_t extAttr = 0x81A40000u;
        if (e.kind == ZipEntry::Kind::Dir)
            extAttr = 0x41ED0010u;
        else if (e.kind == ZipEntry::Kind::Symlink)
            extAttr = 0xA1ED0000u;
        if (!writer.writeLE<std::uint32_t>(extAttr)) return false;
        if (!writer.writeLE<std::uint32_t>(static_cast<std::uint32_t>(e.localHeaderOffset))) return false;
        if (!writer.write(e.name.data(), e.name.size())) return false;
    }
    auto centralDirEnd = writer.offset();
    auto centralDirSize = centralDirEnd - centralDirOffset;

    // 第 5 步：写入 EOCD。
    if (!writer.writeLE<std::uint32_t>(END_OF_CENTRAL_DIR_SIG)) return false;
    if (!writer.writeLE<std::uint16_t>(0)) return false; // disk number
    if (!writer.writeLE<std::uint16_t>(0)) return false; // disk start
    if (!writer.writeLE<std::uint16_t>(static_cast<std::uint16_t>(entries.size()))) return false;
    if (!writer.writeLE<std::uint16_t>(static_cast<std::uint16_t>(entries.size()))) return false;
    if (!writer.writeLE<std::uint32_t>(static_cast<std::uint32_t>(centralDirSize))) return false;
    if (!writer.writeLE<std::uint32_t>(static_cast<std::uint32_t>(centralDirOffset))) return false;
    if (!writer.writeLE<std::uint16_t>(0)) return false; // comment length

    if (!writer.close()) {
        Logger::error("failed to close zip file:", pathToUtf8(outputPath));
        return false;
    }

    return true;
}

}
