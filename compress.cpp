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
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/types.h> // off_t / fseeko
#endif

#include <zip.h>
#include <zlib.h>

#include "Logger.tpp"
#include "ScopeGuard.hpp"
#include "common.hpp"
#include "compress.hpp"
#include "constants.hpp"

namespace com::gitee::ivfzhou::ipasigner {

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
/// 以 '/' 分隔的 UTF-8 路径（ZIP 条目名 / CodeResources key）。
std::string PathToUtf8Generic(const std::filesystem::path& p) {
#ifdef _WIN32
    auto wide = p.generic_wstring();
    if (wide.empty()) return {};
    auto u8len =
        WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (u8len <= 0) return p.generic_string();
    std::string utf8(static_cast<std::size_t>(u8len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(), u8len, nullptr, nullptr);
    return utf8;
#else
    return p.generic_string();
#endif
}

std::string PathToUtf8(const std::filesystem::path& p) {
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
std::filesystem::path Utf8ToPath(const std::string_view utf8) {
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

namespace {

// ZIP 外部属性（高 16 位）里的 Unix 文件类型与权限。
constexpr std::uint16_t UNIX_S_IFMT = 0xF000u;
constexpr std::uint16_t UNIX_S_IFLNK = 0xA000u;
constexpr std::uint16_t UNIX_S_IFDIR = 0x4000u;
constexpr std::uint16_t UNIX_S_IFREG = 0x8000u;
constexpr std::uint16_t UNIX_PERM_MASK = 0x0FFFu;

struct ZipEntryMeta {
    std::string symlinkTarget{}; ///< 非空表示该条目是符号链接。
    std::uint16_t unixMode{}; ///< 原始 Unix 权限位（含文件类型）。
};

std::mutex g_zipMetaMutex{};
std::map<std::string, ZipEntryMeta> g_zipMeta{};

/// 统一用「绝对 + 规范化 + UTF-8」的路径作为元数据键，避免 Windows/Linux 路径差异。
std::string zipMetaKey(const std::filesystem::path& p) {
    std::error_code ec{};
    auto abs = std::filesystem::absolute(p, ec);
    if (ec) abs = p;
    return PathToUtf8(abs.lexically_normal());
}

void recordZipEntryMeta(const std::filesystem::path& p, ZipEntryMeta meta) {
    std::lock_guard lock(g_zipMetaMutex);
    g_zipMeta[zipMetaKey(p)] = std::move(meta);
}

/// 打开 IPA 归档。Windows 下 path::string() 是系统 ANSI 编码，路径含中文时
/// libzip 会打不开；改用宽字符 source 让 libzip 直接以 UTF-16 路径打开文件。
static zip_t* openIpaArchive(const std::filesystem::path& path, const int flags, int* errCode) {
#ifdef _WIN32
    zip_error_t ze{};
    zip_error_init(&ze);
    auto wide = path.lexically_normal().wstring();
    auto src = zip_source_win32w_create(wide.c_str(), 0, ZIP_LENGTH_TO_END, &ze);
    if (src) {
        // 成功时 zip_open_from_source 接管 src；失败时仍需显式释放。
        if (auto archive = zip_open_from_source(src, flags, &ze)) {
            zip_error_fini(&ze);
            return archive;
        }
        zip_source_free(src);
    }
    if (errCode) *errCode = zip_error_code_zip(&ze);
    zip_error_fini(&ze);
    return nullptr;
#else
    return zip_open(path.string().c_str(), flags, errCode);
#endif
}

/// 拒绝路径穿越（ZipSlip）：绝对路径、反斜杠、".." 组件。
bool isSafeZipEntryName(const std::string_view name) {
    if (name.empty() || name.front() == '/' || name.find('\\') != std::string_view::npos ||
        name.find('\0') != std::string_view::npos)
        return false;
    std::size_t start{};
    while (start <= name.size()) {
        auto end = name.find('/', start);
        auto part = name.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
        if (part == "..") return false;
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return true;
}

/// 读取 ZIP 条目文本（符号链接目标），返回 false 表示读取出错。
bool readZipEntryText(zip_t* archive, const zip_uint64_t index, std::string& out) {
    auto zf = zip_fopen_index(archive, index, 0);
    if (!zf) return false;
    ScopeGuard guard{[&zf] { zip_fclose(zf); }};
    char buf[ZIP_BUFFER_SIZE];
    zip_int64_t n{};
    while ((n = zip_fread(zf, buf, ZIP_BUFFER_SIZE)) > 0) out.append(buf, static_cast<std::size_t>(n));
    return n == 0;
}

/// 规范化符号链接目标：去掉首尾空白、统一为 '/' 分隔。
std::string normalizeSymlinkTarget(std::string target) {
    while (!target.empty() &&
           (target.back() == '\r' || target.back() == '\n' || target.back() == ' ' || target.back() == '\t' ||
            target.back() == '\0'))
        target.pop_back();
    std::replace(target.begin(), target.end(), '\\', '/');
    return target;
}

} // namespace

bool IsZipSymlinkEntry(const std::filesystem::path& path, std::string& target) {
    std::error_code ec{};
    auto st = std::filesystem::symlink_status(path, ec);
    if (!ec && std::filesystem::is_symlink(st)) {
        auto link = std::filesystem::read_symlink(path, ec);
        if (!ec) {
            target = PathToUtf8(link);
            std::replace(target.begin(), target.end(), '\\', '/');
            return true;
        }
    }
    std::lock_guard lock(g_zipMetaMutex);
    auto it = g_zipMeta.find(zipMetaKey(path));
    if (it != g_zipMeta.end() && !it->second.symlinkTarget.empty()) {
        // Windows 占位文件的原内容是链接目标；若签名过程中该路径被写成真实文件，
        // 内容会变化，此时应按普通文件处理，避免把新内容当链接目标打进 IPA。
        if (auto data = ReadFile(path); data && *data != it->second.symlinkTarget) return false;
        target = it->second.symlinkTarget;
        return true;
    }
    return false;
}

std::uint16_t ZipEntryUnixPerms(const std::filesystem::path& path) {
    std::lock_guard lock(g_zipMetaMutex);
    auto it = g_zipMeta.find(zipMetaKey(path));
    return it == g_zipMeta.end() ? 0 : it->second.unixMode;
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
    {
        std::lock_guard lock(g_zipMetaMutex);
        g_zipMeta.clear();
    }

    // 打开 ZIP 归档文件，用于预扫描条目信息。
    int err{};
    auto archive = openIpaArchive(ipaPath, ZIP_RDONLY, &err);
    if (!archive) {
        Logger::error("failed to open ipa file:", ipaPath, GetZipErrors(err));
        return false;
    }
    ScopeGuard archiveDeleter{[&archive] { zip_close(archive); }};

    auto numEntries = zip_get_num_entries(archive, 0);
    if (numEntries < 0) {
        Logger::error("failed to get number of entries in ipa archive:", ipaPath);
        return false;
    }

    struct ScanEntry {
        zip_uint64_t index{};
        std::string name{};
        std::filesystem::path destPath{};
        std::uint16_t unixMode{};
        bool isDir{};
        bool isLink{};
    };

    // 第 1 步：扫描条目，读取原始 Unix 外部属性（文件类型 + 权限）。
    std::vector<ScanEntry> scanned{};
    scanned.reserve(static_cast<std::size_t>(numEntries));
    for (zip_int64_t i = 0; i < numEntries; ++i) {
        auto entryName = zip_get_name(archive, i, 0);
        if (!entryName) {
            Logger::error("failed to get archive entry name, index:", std::to_string(i));
            return false;
        }
        std::string name(entryName);
        if (!isSafeZipEntryName(name)) {
            Logger::error("illegal zip entry name (path traversal):", name);
            return false;
        }
        const bool trailingSlash = !name.empty() && name.back() == '/';
        auto relName = trailingSlash ? name.substr(0, name.size() - 1) : name;
        if (relName.empty()) continue;

        ScanEntry item{};
        item.index = static_cast<zip_uint64_t>(i);
        item.name = std::move(name);
        item.destPath = std::filesystem::path(destDir) / Utf8ToPath(relName);

        zip_uint8_t opsys{};
        zip_uint32_t attributes{};
        if (zip_file_get_external_attributes(archive, item.index, 0, &opsys, &attributes) == 0 &&
            opsys == ZIP_OPSYS_UNIX)
            item.unixMode = static_cast<std::uint16_t>(attributes >> 16 & 0xffff);
        item.isDir = trailingSlash || (item.unixMode & UNIX_S_IFMT) == UNIX_S_IFDIR;
        item.isLink = (item.unixMode & UNIX_S_IFMT) == UNIX_S_IFLNK;
        if (item.unixMode == 0)
            item.unixMode = item.isDir ? static_cast<std::uint16_t>(UNIX_S_IFDIR | 0755)
                                       : static_cast<std::uint16_t>(UNIX_S_IFREG | 0644);
        scanned.push_back(std::move(item));
    }

    std::error_code ec{};
    std::filesystem::create_directories(destDir, ec);
    if (ec) {
        Logger::error("failed to create extraction directory:", destDir.string(), ec.message());
        return false;
    }

    // 第 2 步：先建目录和符号链接，避免文件条目先把符号链接路径创造成真实目录。
    for (auto&& item : scanned) {
        if (item.isDir) {
            std::filesystem::create_directories(item.destPath, ec);
            if (ec) {
                Logger::error("failed to create directory:", item.destPath.string(), ec.message());
                return false;
            }
            recordZipEntryMeta(item.destPath, {{}, item.unixMode});
            continue;
        }
        if (!item.isLink) continue;

        std::string target{};
        if (!readZipEntryText(archive, item.index, target)) {
            Logger::error("failed to read symlink entry:", item.name);
            return false;
        }
        target = normalizeSymlinkTarget(std::move(target));
        if (target.empty() || target.front() == '/' || target.find('\0') != std::string::npos) {
            Logger::warn("skip unsafe symlink entry:", item.name);
            continue;
        }
        std::filesystem::create_directories(item.destPath.parent_path(), ec);
        if (ec) {
            Logger::error("failed to create parent of symlink:", item.destPath.string(), ec.message());
            return false;
        }
        std::filesystem::remove_all(item.destPath, ec);
        ec.clear();
        std::filesystem::create_symlink(Utf8ToPath(target), item.destPath, ec);
        if (ec) {
            // Windows 通常没有创建符号链接的权限：写成内容即链接目标的占位文件，
            // 打包与 CodeResources 依据元数据仍把它当成符号链接处理。
            Logger::debug("create symlink failed, using placeholder:", item.name, ec.message());
            ec.clear();
            std::ofstream placeholder(item.destPath, std::ios::binary | std::ios::trunc);
            if (!placeholder.is_open()) {
                Logger::error("failed to create symlink placeholder:", item.destPath.string());
                return false;
            }
            placeholder.write(target.data(), static_cast<std::streamsize>(target.size()));
        }
        recordZipEntryMeta(item.destPath, {target, item.unixMode});
    }

    // 第 3 步：收集普通文件条目（父目录可能不在归档里，这里显式创建）。
    std::vector<std::pair<zip_uint64_t, std::filesystem::path>> fileEntries{};
    for (auto&& item : scanned) {
        if (item.isDir || item.isLink) continue;
        std::filesystem::create_directories(item.destPath.parent_path(), ec);
        if (ec) {
            Logger::error("failed to create parent directory:", item.destPath.string(), ec.message());
            return false;
        }
        recordZipEntryMeta(item.destPath, {{}, item.unixMode});
        fileEntries.emplace_back(item.index, item.destPath);
    }
    if (fileEntries.empty()) return true;

    auto cpuCores = std::thread::hardware_concurrency();
    auto threadCount =
        std::max(1u, std::min(cpuCores > 0 ? cpuCores + 1 : 1u, static_cast<unsigned>(fileEntries.size())));

    std::atomic<std::size_t> nextTask{};
    std::atomic<bool> hasError{};
    std::mutex errorMutex{};
    std::string errorMsg{};

    auto worker = [&] {
        int threadErr{};
        auto threadArchive = openIpaArchive(ipaPath, ZIP_RDONLY, &threadErr);
        if (!threadArchive) {
            std::lock_guard lock(errorMutex);
            errorMsg = "failed to open ipa file: " + GetZipErrors(threadErr);
            hasError.store(true);
            return;
        }
        ScopeGuard threadArchiveDeleter{[&threadArchive] { zip_close(threadArchive); }};

        while (!hasError.load()) {
            auto taskIdx = nextTask.fetch_add(1);
            if (taskIdx >= fileEntries.size()) break;
            auto&& [entryIndex, destPath] = fileEntries[taskIdx];

            auto zipFile = zip_fopen_index(threadArchive, entryIndex, 0);
            if (!zipFile) {
                std::lock_guard lock(errorMutex);
                errorMsg = "failed to open archive entry: " + PathToUtf8(destPath);
                hasError.store(true);
                break;
            }
            ScopeGuard zipFileDeleter{[&zipFile] { zip_fclose(zipFile); }};

            std::ofstream outFile(destPath, std::ios::binary | std::ios::trunc);
            if (!outFile.is_open()) {
                std::lock_guard lock(errorMutex);
                errorMsg = "failed to create output file: " + PathToUtf8(destPath);
                hasError.store(true);
                break;
            }
            ScopeGuard outFileDeleter{[&outFile] { outFile.close(); }};

            char buf[ZIP_BUFFER_SIZE];
            zip_int64_t bytesRead{};
            while ((bytesRead = zip_fread(zipFile, buf, ZIP_BUFFER_SIZE)) > 0) {
                outFile.write(buf, bytesRead);
                if (!outFile.good()) break;
            }
            if (bytesRead < 0 || !outFile.good()) {
                std::lock_guard lock(errorMutex);
                errorMsg = "failed to extract file: " + PathToUtf8(destPath);
                hasError.store(true);
                break;
            }
        }
    };

    std::vector<std::thread> threads{};
    threads.reserve(threadCount);
    for (unsigned t{}; t < threadCount; t++) threads.emplace_back(worker);
    for (auto&& th : threads) th.join();

    if (hasError.load()) {
        Logger::error(errorMsg);
        return false;
    }
    return true;
}

// ===== ZIP 打包实现 =====
//
// 实现策略（单线程流式，内存 O(64KiB)）：
//   1. 扫描 ipaDir，把目录 / 文件 / 符号链接条目分类收集为元数据；
//   2. 逐条目用 64KiB 分块「读 -> 增量 CRC32 -> raw deflate -> 立即写盘」；
//   3. local file header 先占位，数据写完后再 seek 回填 CRC 与大小；
//   4. 写 central directory、必要时 ZIP64 EOCD + locator、经典 EOCD。
//
// 这里刻意不并行：ZIP 数据区必须按条目顺序连续写入，若并行压缩就要把各条目
// 的压缩结果全部缓存到内存（旧实现），大 IPA 会占用与包大小相当的内存。
// 代价是压缩计算只用单核，单个超大文件（如 1GB+ 主可执行）会成为耗时主体。
namespace {

/// ZIP 条目记录。数据不再缓存在内存，压缩结果直接流式写入输出文件。
struct ZipEntry {
    enum class Kind { Dir, File, Symlink };
    Kind kind{};
    std::string name{}; ///< UTF-8 格式的归档条目名（目录以 / 结尾）。
    std::filesystem::path filePath{}; ///< 文件类型：磁盘上的源路径。
    std::string symlinkTarget{}; ///< 符号链接目标路径（UTF-8）。
    std::uint32_t crc32{}; ///< CRC-32 校验和。
    std::uint64_t uncompSize{}; ///< 未压缩大小。
    std::uint64_t compSize{}; ///< 压缩后大小。
    std::uint16_t method{}; ///< 0 = STORE，8 = DEFLATE。
    std::uint16_t unixMode{}; ///< 原始 Unix 权限（含文件类型），0 表示未知。
    std::uint16_t flags{}; ///< general purpose bit flags。
    std::uint16_t versionNeeded{}; ///< version needed to extract。
    std::uint64_t localHeaderOffset{}; ///< 在最终 ZIP 文件中的 local header 偏移。
    bool zip64Sizes{}; ///< local header 是否预留了 ZIP64 size extra field。
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

/// ZIP 输出流：支持 64 位偏移定位，用于流式写完数据后回填 local header。
class ZipWriter {
  public:
    bool open(const std::filesystem::path& outputPath) {
#ifdef _WIN32
        if (_wfopen_s(&fp_, outputPath.wstring().c_str(), L"w+b") != 0) return false;
#else
        fp_ = std::fopen(outputPath.string().c_str(), "w+b");
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

    /// 定位到绝对偏移（写模式下会 flush 之前的缓冲），并同步逻辑偏移。
    bool seek(std::uint64_t pos) {
        if (!fp_) return false;
#ifdef _WIN32
        if (_fseeki64(fp_, static_cast<__int64>(pos), SEEK_SET) != 0) return false;
#else
        if (fseeko(fp_, static_cast<off_t>(pos), SEEK_SET) != 0) return false;
#endif
        offset_ = pos;
        return true;
    }

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
constexpr std::uint32_t ZIP64_EOCD_SIG = 0x06064b50;
constexpr std::uint32_t ZIP64_EOCD_LOCATOR_SIG = 0x07064b50;
constexpr std::uint16_t ZIP64_EXTRA_ID = 0x0001;
constexpr std::uint16_t ZIP64_VERSION = 45;
constexpr std::uint16_t ZIP_BASE_VERSION = 20;
constexpr std::uint32_t ZIP32_MAX = 0xFFFFFFFFu;
constexpr std::uint16_t ZIP16_MAX = 0xFFFFu;
constexpr std::size_t ZIP_IO_CHUNK = 64 * 1024;

/// STORE：分块读取并原样写入，同时增量计算 CRC-32。
static bool streamStore(ZipWriter& writer, const std::filesystem::path& filePath, ZipEntry& e) {
    auto fp = openBinaryRead(filePath);
    if (!fp) return false;
    ScopeGuard fpGuard{[&fp] { std::fclose(fp); }};

    std::vector<std::uint8_t> buf(ZIP_IO_CHUNK);
    e.crc32 = 0;
    e.uncompSize = 0;
    e.compSize = 0;
    for (;;) {
        auto n = std::fread(buf.data(), 1, buf.size(), fp);
        if (n > 0) {
            e.crc32 = static_cast<std::uint32_t>(::crc32(e.crc32, buf.data(), static_cast<uInt>(n)));
            if (!writer.write(buf.data(), n)) return false;
            e.uncompSize += n;
        }
        if (n < buf.size()) {
            if (std::ferror(fp)) return false;
            break;
        }
    }
    e.compSize = e.uncompSize;
    return true;
}

/// DEFLATE：分块读取 + 增量 raw deflate 直接写入 ZIP 流，内存恒定 O(ZIP_IO_CHUNK)。
static bool streamDeflate(ZipWriter& writer, const std::filesystem::path& filePath, int level, ZipEntry& e) {
    auto fp = openBinaryRead(filePath);
    if (!fp) return false;
    ScopeGuard fpGuard{[&fp] { std::fclose(fp); }};

    z_stream zs{};
    // windowBits = -15 表示 raw deflate（无 zlib header/trailer），正是 ZIP 所需。
    if (deflateInit2(&zs, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) return false;
    ScopeGuard zsGuard{[&zs] { deflateEnd(&zs); }};

    std::vector<std::uint8_t> in(ZIP_IO_CHUNK);
    std::vector<std::uint8_t> out(ZIP_IO_CHUNK);
    e.crc32 = 0;
    e.uncompSize = 0;
    e.compSize = 0;

    bool eof = false;
    for (;;) {
        if (zs.avail_in == 0 && !eof) {
            auto n = std::fread(in.data(), 1, in.size(), fp);
            if (n > 0) {
                e.crc32 = static_cast<std::uint32_t>(::crc32(e.crc32, in.data(), static_cast<uInt>(n)));
                e.uncompSize += n;
            }
            if (n < in.size()) {
                if (std::ferror(fp)) return false;
                eof = true;
            }
            zs.next_in = in.data();
            zs.avail_in = static_cast<uInt>(n);
        }
        zs.next_out = out.data();
        zs.avail_out = static_cast<uInt>(out.size());
        auto ret = deflate(&zs, eof ? Z_FINISH : Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR) return false;
        auto produced = out.size() - zs.avail_out;
        if (produced > 0) {
            if (!writer.write(out.data(), produced)) return false;
            e.compSize += produced;
        }
        if (ret == Z_STREAM_END) break;
    }
    return true;
}

/// 符号链接的数据区就是链接目标字节串。
static bool streamSymlink(ZipWriter& writer, const std::string& target, ZipEntry& e) {
    e.crc32 = static_cast<std::uint32_t>(
        ::crc32(0L, reinterpret_cast<const Bytef*>(target.data()), static_cast<uInt>(target.size())));
    e.uncompSize = target.size();
    e.compSize = target.size();
    return writer.write(target.data(), target.size());
}

/// 条目的 Unix 外部属性（文件类型 + 权限位）。
static std::uint32_t entryExternalAttributes(const ZipEntry& e) {
    auto perms = static_cast<std::uint16_t>(e.unixMode & UNIX_PERM_MASK);
    if (perms == 0) perms = e.kind == ZipEntry::Kind::File ? 0644 : 0755;
    std::uint16_t type = UNIX_S_IFREG;
    if (e.kind == ZipEntry::Kind::Dir)
        type = UNIX_S_IFDIR;
    else if (e.kind == ZipEntry::Kind::Symlink)
        type = UNIX_S_IFLNK;
    std::uint32_t extAttr = static_cast<std::uint32_t>(type | perms) << 16;
    if (e.kind == ZipEntry::Kind::Dir) extAttr |= 0x10u; // DOS directory bit
    return extAttr;
}

/// 写 local file header；CRC 与大小先占位，数据写完后由 patchLocalHeader 回填。
/// 不设置 bit 3（data descriptor），生成的布局与系统 zip 一致，兼容性最好。
static bool writeLocalHeader(ZipWriter& writer, ZipEntry& e, std::uint16_t dosTime, std::uint16_t dosDate) {
    if (e.name.size() > ZIP16_MAX) return false;
    e.localHeaderOffset = writer.offset();

    // 只有未压缩大小接近 4GiB 的条目才可能让 deflate 结果超出 32 位。zlib 最坏
    // 膨胀约 0.03%，这里用 1% 上界静态判定，避免写完数据后才发现需要 ZIP64
    // extra field 而 local header 布局已经固定。
    std::uint64_t srcSize = 0;
    if (e.kind == ZipEntry::Kind::File) {
        std::error_code fec{};
        srcSize = std::filesystem::file_size(e.filePath, fec);
        if (fec) return false;
    } else if (e.kind == ZipEntry::Kind::Symlink) {
        srcSize = e.symlinkTarget.size();
    }
    e.zip64Sizes = (srcSize + srcSize / 100 + 1024) >= ZIP32_MAX;

    e.versionNeeded = (e.zip64Sizes || e.localHeaderOffset >= ZIP32_MAX) ? ZIP64_VERSION : ZIP_BASE_VERSION;
    const std::uint16_t extraLen = e.zip64Sizes ? 20 : 0;

    if (!writer.writeLE<std::uint32_t>(LOCAL_FILE_HEADER_SIG)) return false;
    if (!writer.writeLE<std::uint16_t>(e.versionNeeded)) return false;
    if (!writer.writeLE<std::uint16_t>(e.flags)) return false;
    if (!writer.writeLE<std::uint16_t>(e.method)) return false;
    if (!writer.writeLE<std::uint16_t>(dosTime)) return false;
    if (!writer.writeLE<std::uint16_t>(dosDate)) return false;
    if (!writer.writeLE<std::uint32_t>(0)) return false; // crc32 占位
    if (!writer.writeLE<std::uint32_t>(0)) return false; // compSize 占位
    if (!writer.writeLE<std::uint32_t>(0)) return false; // uncompSize 占位
    if (!writer.writeLE<std::uint16_t>(static_cast<std::uint16_t>(e.name.size()))) return false;
    if (!writer.writeLE<std::uint16_t>(extraLen)) return false;
    if (!writer.write(e.name.data(), e.name.size())) return false;
    if (e.zip64Sizes) {
        if (!writer.writeLE<std::uint16_t>(ZIP64_EXTRA_ID)) return false;
        if (!writer.writeLE<std::uint16_t>(16)) return false;
        if (!writer.writeLE<std::uint64_t>(0)) return false; // uncompSize 占位
        if (!writer.writeLE<std::uint64_t>(0)) return false; // compSize 占位
    }
    return true;
}

/// 回填 local header 的 CRC / 大小字段（以及 ZIP64 extra 中的 64 位大小）。
static bool patchLocalHeader(ZipWriter& writer, const ZipEntry& e) {
    if (e.kind == ZipEntry::Kind::Dir) return true; // 全 0 占位即正确值

    const auto saved = writer.offset();
    const auto base = e.localHeaderOffset;
    if (!writer.seek(base + 14)) return false;
    if (!writer.writeLE<std::uint32_t>(e.crc32)) return false;
    if (e.zip64Sizes) {
        // 32 位字段置哨兵，真实值写在 ZIP64 extra 中。
        if (!writer.writeLE<std::uint32_t>(ZIP32_MAX)) return false;
        if (!writer.writeLE<std::uint32_t>(ZIP32_MAX)) return false;
        // extra 数据区 = 30(固定头) + nameLen + 4(extra 的 id + len)。
        if (!writer.seek(base + 30 + e.name.size() + 4)) return false;
        if (!writer.writeLE<std::uint64_t>(e.uncompSize)) return false;
        if (!writer.writeLE<std::uint64_t>(e.compSize)) return false;
    } else {
        // 静态上界判定失效时宁可失败，也不静默写出被截断的大小。
        if (e.compSize >= ZIP32_MAX || e.uncompSize >= ZIP32_MAX) return false;
        if (!writer.writeLE<std::uint32_t>(static_cast<std::uint32_t>(e.compSize))) return false;
        if (!writer.writeLE<std::uint32_t>(static_cast<std::uint32_t>(e.uncompSize))) return false;
    }
    return writer.seek(saved);
}

/// 写一条 central directory header；必要时附加 ZIP64 extra（64 位 size / offset）。
static bool writeCentralDirectoryHeader(ZipWriter& writer, const ZipEntry& e, std::uint16_t dosTime,
                                        std::uint16_t dosDate) {
    const bool zip64 =
        e.zip64Sizes || e.compSize >= ZIP32_MAX || e.uncompSize >= ZIP32_MAX || e.localHeaderOffset >= ZIP32_MAX;
    // ZIP64 extra 中字段顺序必须与 32 位哨兵字段一一对应：
    // uncompressed size -> compressed size -> local header offset。
    const std::uint16_t extraLen = zip64 ? 28 : 0;

    if (!writer.writeLE<std::uint32_t>(CENTRAL_DIR_HEADER_SIG)) return false;
    if (!writer.writeLE<std::uint16_t>(0x031E)) return false; // Unix 3.0
    if (!writer.writeLE<std::uint16_t>(zip64 ? ZIP64_VERSION : e.versionNeeded)) return false;
    if (!writer.writeLE<std::uint16_t>(e.flags)) return false;
    if (!writer.writeLE<std::uint16_t>(e.method)) return false;
    if (!writer.writeLE<std::uint16_t>(dosTime)) return false;
    if (!writer.writeLE<std::uint16_t>(dosDate)) return false;
    if (!writer.writeLE<std::uint32_t>(e.crc32)) return false;
    if (!writer.writeLE<std::uint32_t>(zip64 ? ZIP32_MAX : static_cast<std::uint32_t>(e.compSize))) return false;
    if (!writer.writeLE<std::uint32_t>(zip64 ? ZIP32_MAX : static_cast<std::uint32_t>(e.uncompSize))) return false;
    if (!writer.writeLE<std::uint16_t>(static_cast<std::uint16_t>(e.name.size()))) return false;
    if (!writer.writeLE<std::uint16_t>(extraLen)) return false;
    if (!writer.writeLE<std::uint16_t>(0)) return false; // comment length
    if (!writer.writeLE<std::uint16_t>(0)) return false; // disk number start
    if (!writer.writeLE<std::uint16_t>(0)) return false; // internal file attrs
    if (!writer.writeLE<std::uint32_t>(entryExternalAttributes(e))) return false;
    if (!writer.writeLE<std::uint32_t>(zip64 ? ZIP32_MAX : static_cast<std::uint32_t>(e.localHeaderOffset)))
        return false;
    if (!writer.write(e.name.data(), e.name.size())) return false;
    if (zip64) {
        if (!writer.writeLE<std::uint16_t>(ZIP64_EXTRA_ID)) return false;
        if (!writer.writeLE<std::uint16_t>(24)) return false;
        if (!writer.writeLE<std::uint64_t>(e.uncompSize)) return false;
        if (!writer.writeLE<std::uint64_t>(e.compSize)) return false;
        if (!writer.writeLE<std::uint64_t>(e.localHeaderOffset)) return false;
    }
    return true;
}

/// 写 EOCD；条目数 / 中心目录偏移或大小超限时追加 ZIP64 EOCD record + locator。
static bool writeEndOfCentralDirectory(ZipWriter& writer, std::uint64_t count, std::uint64_t centralDirOffset,
                                       std::uint64_t centralDirSize) {
    const bool zip64 = count > ZIP16_MAX || centralDirOffset >= ZIP32_MAX || centralDirSize >= ZIP32_MAX;
    if (zip64) {
        const auto zip64Offset = writer.offset();
        if (!writer.writeLE<std::uint32_t>(ZIP64_EOCD_SIG)) return false;
        if (!writer.writeLE<std::uint64_t>(44)) return false; // 本记录剩余字节数
        if (!writer.writeLE<std::uint16_t>(ZIP64_VERSION)) return false; // version made by
        if (!writer.writeLE<std::uint16_t>(ZIP64_VERSION)) return false; // version needed
        if (!writer.writeLE<std::uint32_t>(0)) return false; // disk number
        if (!writer.writeLE<std::uint32_t>(0)) return false; // disk with CD
        if (!writer.writeLE<std::uint64_t>(count)) return false;
        if (!writer.writeLE<std::uint64_t>(count)) return false;
        if (!writer.writeLE<std::uint64_t>(centralDirSize)) return false;
        if (!writer.writeLE<std::uint64_t>(centralDirOffset)) return false;

        if (!writer.writeLE<std::uint32_t>(ZIP64_EOCD_LOCATOR_SIG)) return false;
        if (!writer.writeLE<std::uint32_t>(0)) return false; // disk with ZIP64 EOCD
        if (!writer.writeLE<std::uint64_t>(zip64Offset)) return false;
        if (!writer.writeLE<std::uint32_t>(1)) return false; // total disks
    }

    if (!writer.writeLE<std::uint32_t>(END_OF_CENTRAL_DIR_SIG)) return false;
    if (!writer.writeLE<std::uint16_t>(0)) return false; // disk number
    if (!writer.writeLE<std::uint16_t>(0)) return false; // disk start
    // 只有真正溢出的字段才置哨兵，其余保留实际值，最大化解压器兼容性。
    auto e16 = [](std::uint64_t v) -> std::uint16_t {
        return v > ZIP16_MAX ? ZIP16_MAX : static_cast<std::uint16_t>(v);
    };
    auto e32 = [](std::uint64_t v) -> std::uint32_t {
        return v >= ZIP32_MAX ? ZIP32_MAX : static_cast<std::uint32_t>(v);
    };
    if (!writer.writeLE<std::uint16_t>(e16(count))) return false;
    if (!writer.writeLE<std::uint16_t>(e16(count))) return false;
    if (!writer.writeLE<std::uint32_t>(e32(centralDirSize))) return false;
    if (!writer.writeLE<std::uint32_t>(e32(centralDirOffset))) return false;
    if (!writer.writeLE<std::uint16_t>(0)) return false; // comment length
    return true;
}

}

/// 递归收集 ZIP 条目。
/// 必须自己累积相对路径：std::filesystem::relative() 内部用 weakly_canonical，
/// 会解析符号链接，把「链接条目」命名成它指向的目标路径，与真实文件撞名，
/// 生成重复 ZIP 条目（macOS unzip 会跳过同名项，codesign 随之报资源缺失）。
/// 纯词法拼接还能避免上万次文件系统查询。
static bool collectZipEntries(const std::filesystem::path& folder, const std::string& prefix,
                              std::vector<ZipEntry>& entries) {
    std::error_code ec{};
    auto it = std::filesystem::directory_iterator(folder, ec);
    if (ec) {
        Logger::error("failed to iterate directory:", PathToUtf8(folder), ec.message());
        return false;
    }
    for (auto&& entry : it) {
        auto name = PathToUtf8Generic(entry.path().filename());
        if (name.empty()) continue;
        const auto rel = prefix.empty() ? name : prefix + "/" + name;

        ZipEntry zipEntry{};
        zipEntry.name = rel;
        // 归档名是 UTF-8，非 ASCII 时置 bit 11，避免不同系统按本地代码页解读。
        if (std::any_of(zipEntry.name.begin(), zipEntry.name.end(),
                        [](const char c) { return static_cast<unsigned char>(c) >= 0x80; }))
            zipEntry.flags = 0x0800;
        zipEntry.unixMode = ZipEntryUnixPerms(entry.path());

        // 真实符号链接与 Windows 占位文件都按符号链接条目写回，保证跨系统一致。
        std::string symlinkTarget{};
        if (IsZipSymlinkEntry(entry.path(), symlinkTarget)) {
            zipEntry.kind = ZipEntry::Kind::Symlink;
            zipEntry.symlinkTarget = std::move(symlinkTarget);
        } else {
            // 用 symlink_status 不跟随链接，与 IsZipSymlinkEntry 的判定保持一致。
            auto st = entry.symlink_status(ec);
            if (ec) {
                ec.clear();
                continue;
            }
            if (std::filesystem::is_directory(st)) {
                zipEntry.kind = ZipEntry::Kind::Dir;
                zipEntry.name += '/';
                entries.push_back(std::move(zipEntry));
                if (!collectZipEntries(entry.path(), rel, entries)) return false;
                continue;
            }
            if (std::filesystem::is_regular_file(st)) {
                zipEntry.kind = ZipEntry::Kind::File;
                zipEntry.filePath = entry.path();
            } else {
                continue;
            }
        }
        entries.push_back(std::move(zipEntry));
    }
    return true;
}

bool Zip(const std::filesystem::path& ipaDir, const std::filesystem::path& outputPath, const int compressLevel) {
    auto level = std::clamp(compressLevel, 0, 9);

    // 第 1 步：扫描所有条目，收集元信息（不读文件内容）。
    std::vector<ZipEntry> entries{};
    if (!collectZipEntries(ipaDir, std::string{}, entries)) return false;

    // 第 2 步：打开输出，逐条目流式压缩并写出。
    // 为保证内存恒定（不随 IPA 大小增长），这里按条目串行处理：读一块、压一块、
    // 立刻写一块，写完回填 local header。ZIP 数据区必须按条目顺序写入，因此不再
    // 并行缓存所有压缩结果；代价是压缩串行，换来 O(64KiB) 的内存占用。
    ZipWriter writer{};
    if (!writer.open(outputPath)) {
        Logger::error("failed to create zip file:", PathToUtf8(outputPath));
        return false;
    }
    bool succeeded = false;
    ScopeGuard writerGuard{[&] {
        writer.close();
        if (!succeeded) {
            std::error_code rec{};
            std::filesystem::remove(outputPath, rec);
        }
    }};

    auto [dosTime, dosDate] = dosTimeStamp();

    for (auto& e : entries) {
        if (e.kind == ZipEntry::Kind::File) {
            std::error_code fec{};
            auto fileSize = std::filesystem::file_size(e.filePath, fec);
            if (fec) {
                Logger::error("failed to stat file:", PathToUtf8(e.filePath), fec.message());
                return false;
            }
            e.method = (level == 0 || fileSize == 0) ? 0 : 8;
        } else {
            e.method = 0; // 目录与符号链接用 STORE
        }

        if (!writeLocalHeader(writer, e, dosTime, dosDate)) {
            Logger::error("failed to write zip entry:", e.name);
            return false;
        }

        bool payloadOk = false;
        switch (e.kind) {
        case ZipEntry::Kind::Dir:
            payloadOk = true;
            break;
        case ZipEntry::Kind::Symlink:
            payloadOk = streamSymlink(writer, e.symlinkTarget, e);
            break;
        case ZipEntry::Kind::File:
            payloadOk =
                e.method == 8 ? streamDeflate(writer, e.filePath, level, e) : streamStore(writer, e.filePath, e);
            break;
        }
        if (!payloadOk) {
            Logger::error("failed to compress zip entry:", e.name);
            return false;
        }
        if (!patchLocalHeader(writer, e)) {
            Logger::error("failed to patch zip entry:", e.name);
            return false;
        }
    }

    // 第 3 步：写入 central directory（含必要的 ZIP64 extra）。
    auto centralDirOffset = writer.offset();
    for (auto& e : entries) {
        if (!writeCentralDirectoryHeader(writer, e, dosTime, dosDate)) {
            Logger::error("failed to write central directory entry:", e.name);
            return false;
        }
    }
    auto centralDirSize = writer.offset() - centralDirOffset;

    // 第 4 步：写入 EOCD，超限时追加 ZIP64 EOCD + locator。
    if (!writeEndOfCentralDirectory(writer, entries.size(), centralDirOffset, centralDirSize)) {
        Logger::error("failed to write end of central directory");
        return false;
    }

    if (!writer.close()) {
        Logger::error("failed to close zip file:", PathToUtf8(outputPath));
        return false;
    }

    succeeded = true;
    return true;
}

}
