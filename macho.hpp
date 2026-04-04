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
 * @file macho.hpp
 * @brief Mach-O 文件格式结构体与 CodeSignature 常量定义。
 *
 * 定义了 Mach-O 二进制文件格式中的各种结构体（Fat Binary、Load Commands 等），
 * 以及 Apple CodeSignature（代码签名）相关的 magic 常量、blob 结构体和 slot 定义。
 */

#ifndef IPASIGNER_MACHO_HPP
#define IPASIGNER_MACHO_HPP

#include <cstdint>

namespace gitee::com::ivfzhou::ipasigner {

// CPU 类型定义。
using cpu_type_t = int;
using cpu_subtype_t = int;
using vm_prot_t = int;

// Mach-O magic 常量。
constexpr std::uint32_t FAT_MAGIC_VAL = 0xcafebabe;
constexpr std::uint32_t FAT_CIGAM_VAL = 0xbebafeca;
constexpr std::uint32_t MH_MAGIC_VAL = 0xfeedface;
constexpr std::uint32_t MH_CIGAM_VAL = 0xcefaedfe;
constexpr std::uint32_t MH_MAGIC_64_VAL = 0xfeedfacf;
constexpr std::uint32_t MH_CIGAM_64_VAL = 0xcffaedfe;

// 文件类型常量。
constexpr std::uint32_t MH_EXECUTE_VAL = 0x2;
constexpr std::uint32_t MH_DYLIB_VAL = 0x6;

// Load Command 类型。
constexpr std::uint32_t LC_SEGMENT_VAL = 0x00000001;
constexpr std::uint32_t LC_SEGMENT_64_VAL = 0x00000019;
constexpr std::uint32_t LC_CODE_SIGNATURE_VAL = 0x0000001D;
constexpr std::uint32_t LC_ENCRYPTION_INFO_VAL = 0x00000021;
constexpr std::uint32_t LC_ENCRYPTION_INFO_64_VAL = 0x0000002C;
constexpr std::uint32_t LC_LOAD_DYLIB_VAL = 0x0000000c;
constexpr std::uint32_t LC_LOAD_WEAK_DYLIB_VAL = 0x80000018;

// CodeSignature magic 常量。
constexpr std::uint32_t CSMAGIC_REQUIREMENT = 0xfade0c00;
constexpr std::uint32_t CSMAGIC_REQUIREMENTS = 0xfade0c01;
constexpr std::uint32_t CSMAGIC_CODEDIRECTORY = 0xfade0c02;
constexpr std::uint32_t CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
constexpr std::uint32_t CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171;
constexpr std::uint32_t CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xfade7172;
constexpr std::uint32_t CSMAGIC_BLOBWRAPPER = 0xfade0b01;

// CodeSignature slot 类型。
constexpr std::uint32_t CSSLOT_CODEDIRECTORY = 0;
constexpr std::uint32_t CSSLOT_REQUIREMENTS = 2;
constexpr std::uint32_t CSSLOT_ENTITLEMENTS = 5;
constexpr std::uint32_t CSSLOT_DER_ENTITLEMENTS = 7;
constexpr std::uint32_t CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000;
constexpr std::uint32_t CSSLOT_SIGNATURESLOT = 0x10000;

// execSeg flags。
constexpr std::uint64_t CS_EXECSEG_MAIN_BINARY = 0x1;
constexpr std::uint64_t CS_EXECSEG_ALLOW_UNSIGNED = 0x10;

#pragma pack(push, 1)

// Fat Binary 头部。
struct FatHeader {
    std::uint32_t magic;    ///< 魔数：0xCAFEBABE（大端）或 0xBEBAFECA（小端）。
    std::uint32_t nfat_arch; ///< 包含的架构数量。
};

// Fat 架构描述。
struct FatArch {
    cpu_type_t cputype;       ///< CPU 类型（如 ARM64 = 0x0100000C）。
    cpu_subtype_t cpusubtype; ///< CPU 子类型。
    std::uint32_t offset;     ///< 该架构数据在文件中的偏移量。
    std::uint32_t size;       ///< 该架构数据的字节大小。
    std::uint32_t align;      ///< 内存对齐边界（2 的幂次）。
};

// Mach-O 32位头部。
struct MachHeader {
    std::uint32_t magic;     ///< 魔数：标识文件格式和字节序（如 0xFEEDFACE）。
    cpu_type_t cputype;       ///< CPU 类型。
    cpu_subtype_t cpusubtype; ///< CPU 子类型。
    std::uint32_t filetype;   ///< 文件类型（如 MH_EXECUTE = 0x2, MH_DYLIB = 0x6）。
    std::uint32_t ncmds;      ///< Load Commands 的数量。
    std::uint32_t sizeofcmds; ///< Load Commands 区域的总大小（字节）。
    std::uint32_t flags;      ///< 标志位（如 MH_PIE、MH_DYLDLINK 等）。
};

// Mach-O 64位头部。
struct MachHeader64 {
    std::uint32_t magic;     ///< 魔数：标识文件格式和字节序（如 0xFEEDFACF）。
    cpu_type_t cputype;       ///< CPU 类型。
    cpu_subtype_t cpusubtype; ///< CPU 子类型。
    std::uint32_t filetype;   ///< 文件类型（如 MH_EXECUTE = 0x2, MH_DYLIB = 0x6）。
    std::uint32_t ncmds;      ///< Load Commands 的数量。
    std::uint32_t sizeofcmds; ///< Load Commands 区域的总大小（字节）。
    std::uint32_t flags;      ///< 标志位（如 MH_PIE、MH_DYLDLINK 等）。
    std::uint32_t reserved;   ///< 保留字段，必须为 0。
};

// Load Command 基类。
struct LoadCommand {
    std::uint32_t cmd;     ///< 命令类型（如 LC_SEGMENT = 0x1, LC_CODE_SIGNATURE = 0x1D）。
    std::uint32_t cmdsize; ///< 该命令结构体的总大小（含额外数据）。
};

// 32位段命令（LC_SEGMENT）。
struct SegmentCommand {
    std::uint32_t cmd;       ///< LC_SEGMENT (0x1)。
    std::uint32_t cmdsize;   ///< 含 section 在内的总大小。
    char segname[16];        ///< 段名称（如 "__TEXT", "__LINKEDIT", "__DATA"）。
    std::uint32_t vmaddr;    ///< 虚拟内存起始地址。
    std::uint32_t vmsize;    ///< 虚拟内存大小。
    std::uint32_t fileoff;   ///< 文件中的偏移量。
    std::uint32_t filesize;  ///< 文件中的大小（可能小于 vmsize，如 __LINKEDIT 的零填充部分）。
    vm_prot_t maxprot;       ///< 最大内存保护权限。
    vm_prot_t initprot;      ///< 初始内存保护权限。
    std::uint32_t nsects;    ///< 包含的 section 数量。
    std::uint32_t flags;     ///< 标志位。
};

// 64位段命令（LC_SEGMENT_64）。
struct SegmentCommand64 {
    std::uint32_t cmd;       ///< LC_SEGMENT_64 (0x19)。
    std::uint32_t cmdsize;   ///< 含 section 在内的总大小。
    char segname[16];        ///< 段名称。
    std::uint64_t vmaddr;    ///< 虚拟内存起始地址（64 位）。
    std::uint64_t vmsize;    ///< 虚拟内存大小（64 位）。
    std::uint64_t fileoff;   ///< 文件中的偏移量（64 位）。
    std::uint64_t filesize;  ///< 文件中的大小（64 位）。
    vm_prot_t maxprot;       ///< 最大内存保护权限。
    vm_prot_t initprot;      ///< 初始内存保护权限。
    std::uint32_t nsects;    ///< 包含的 section 数量。
    std::uint32_t flags;     ///< 标志位。
};

// 32位 section。
struct Section {
    char sectname[16];        ///< Section 名称（如 "__text", "__stubs"）。
    char segname[16];         ///< 所属段名称（如 "__TEXT"）。
    std::uint32_t addr;       ///< 虚拟内存地址。
    std::uint32_t size;       ///< Section 大小（字节）。
    std::uint32_t offset;     ///< 在文件中的偏移量。
    std::uint32_t align;      ///< 对齐边界（2 的幂次）。
    std::uint32_t reloff;     ///< 重定位表偏移量。
    std::uint32_t nreloc;     ///< 重定位条目数量。
    std::uint32_t flags;      ///< 属性标志位（如 S_REGULAR, S_CSTRING_LITERALS 等）。
    std::uint32_t reserved1;  ///< 保留/索引（如间接符号表索引）。
    std::uint32_t reserved2;  ///< 保留字段。
};

// 64位 section。
struct Section64 {
    char sectname[16];        ///< Section 名称（如 "__text", "__stubs"）。
    char segname[16];         ///< 所属段名称（如 "__TEXT"）。
    std::uint64_t addr;       ///< 虚拟内存地址（64 位）。
    std::uint64_t size;       ///< Section 大小（字节）。
    std::uint32_t offset;     ///< 在文件中的偏移量。
    std::uint32_t align;      ///< 对齐边界（2 的幂次）。
    std::uint32_t reloff;     ///< 重定位表偏移量。
    std::uint32_t nreloc;     ///< 重定位条目数量。
    std::uint32_t flags;      ///< 属性标志位。
    std::uint32_t reserved1;  ///< 保留/索引。
    std::uint32_t reserved2;  ///< 保留字段。
    std::uint32_t reserved3;  ///< 保留字段（仅 64 位有）。
};

// 代码签名命令（LC_CODE_SIGNATURE）。
struct CodeSignatureCommand {
    std::uint32_t cmd;      ///< LC_CODE_SIGNATURE (0x1D)。
    std::uint32_t cmdsize;  ///< 结构体大小。
    std::uint32_t dataoff;  ///< CodeSignature 数据在文件中的偏移量。
    std::uint32_t datasize; ///< CodeSignature 数据区域大小。
};

// 加密信息命令（LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64）。
struct EncryptionInfoCommand {
    std::uint32_t cmd;       ///< LC_ENCRYPTION_INFO (0x21) 或 LC_ENCRYPTION_INFO_64 (0x2C)。
    std::uint32_t cmdsize;   ///< 结构体大小。
    std::uint32_t cryptoff;  ///< 加密数据在文件中的偏移量。
    std::uint32_t cryptsize; ///< 加密数据的大小。
    std::uint32_t cryptid;   ///< 加密标识符（0 = 未加密，非 0 = 已加密）。
};

// dylib 名称偏移结构体（变长字符串的起始偏移）。
union LcStr {
    std::uint32_t offset;    ///< dylib 路径字符串相对于 DylibCommand 起始位置的偏移。
};

// dylib 信息（嵌入在 DylibCommand 中）。
struct Dylib {
    LcStr name;                       ///< 动态库名称偏移（相对于 DylibCommand 起始位置）。
    std::uint32_t timestamp;          ///< 时间戳（通常为 2，表示安装时间校验）。
    std::uint32_t current_version;    ///< 当前版本号（兼容性检查时忽略）。
    std::uint32_t compatibility_version; ///< 兼容性版本号。
};

// dylib 加载命令（LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB）。
struct DylibCommand {
    std::uint32_t cmd;     ///< LC_LOAD_DYLIB (0x0C) 或 LC_LOAD_WEAK_DYLIB (0x80000018)。
    std::uint32_t cmdsize; ///< 含 dylib 路径在内的总大小。
    Dylib dylib;           ///< dylib 描述信息 + 变长的路径字符串。
};

// CodeSignature SuperBlob 头（CSMAGIC_EMBEDDED_SIGNATURE）。
struct CSSuperBlob {
    std::uint32_t magic;  ///< Magic: 0xfade0cc0。
    std::uint32_t length; ///< 整个 SuperBlob（含所有 Slot）的总长度。
    std::uint32_t count;  ///< 包含的 blob/slot 数量。
};

// CodeSignature blob 索引条目（位于 SuperBlob 头之后）。
struct CSBlobIndex {
    std::uint32_t type;   ///< Slot 类型（如 CSSLOT_CODEDIRECTORY, CSSLOT_SIGNATURESLOT 等）。
    std::uint32_t offset; ///< 该 Slot 数据相对于 SuperBlob 起始位置的偏移量。
};

// CodeDirectory 结构体（CSMAGIC_CODEDIRECTORY）。
struct CSCodeDirectory {
    std::uint32_t magic;         ///< Magic: 0xfade0c02。
    std::uint32_t length;        ///< 整个 CodeDirectory Blob 的总长度。
    std::uint32_t version;       ///< 格式版本（本项目使用 0x20400）。
    std::uint32_t flags;         ///< 标志位（通常为 0）。
    std::uint32_t hashOffset;    ///< 哈希表区域相对于本结构体起始位置的偏移。
    std::uint32_t identOffset;   ///< Bundle ID 字符串的偏移（相对于结构体起始位置）。
    std::uint32_t nSpecialSlots; ///< 特殊 Slot 数量（如 Entitlements、CodeResources 等）。
    std::uint32_t nCodeSlots;    ///< 代码页哈希 Slot 数量。
    std::uint32_t codeLimit;     ///< 需要签名的代码区长度（字节）。
    std::uint8_t hashSize;       ///< 哈希输出长度：SHA1 = 20, SHA256 = 32。
    std::uint8_t hashType;       ///< 哈希算法类型：1 = SHA1, 2 = SHA256。
    std::uint8_t spare1;         ///< 保留字段。
    std::uint8_t pageSize;       ///< 代码页大小的 log2（12 表示每页 4096 字节）。
    std::uint32_t spare2;        ///< 保留字段（版本 < 0x20100）。
    // Version 0x20100。
    std::uint32_t scatterOffset; ///< Scatter 表偏移（未使用，置零）。
    // Version 0x20200。
    std::uint32_t teamOffset;    ///< Team ID 字符串偏移（相对于结构体起始位置）。
    // Version 0x20300。
    std::uint32_t spare3;        ///< 保留字段。
    std::uint64_t codeLimit64;   ///< 64 位代码区长度（未使用，与 codeLimit 一致）。
    // Version 0x20400。
    std::uint64_t execSegBase;   ///< 可执行段基址（通常为 0）。
    std::uint64_t execSegLimit;  ///< 可执行段内存上限（__TEXT.vmsize）。
    std::uint64_t execSegFlags;  ///< 可执行段标志位（CS_EXECSEG_MAIN_BINARY 等）。
};

#pragma pack(pop)

}

#endif
