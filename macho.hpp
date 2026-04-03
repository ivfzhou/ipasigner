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
    std::uint32_t magic;
    std::uint32_t nfat_arch;
};

// Fat 架构描述。
struct FatArch {
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    std::uint32_t offset;
    std::uint32_t size;
    std::uint32_t align;
};

// Mach-O 32位头部。
struct MachHeader {
    std::uint32_t magic;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    std::uint32_t filetype;
    std::uint32_t ncmds;
    std::uint32_t sizeofcmds;
    std::uint32_t flags;
};

// Mach-O 64位头部。
struct MachHeader64 {
    std::uint32_t magic;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    std::uint32_t filetype;
    std::uint32_t ncmds;
    std::uint32_t sizeofcmds;
    std::uint32_t flags;
    std::uint32_t reserved;
};

// Load Command 基类。
struct LoadCommand {
    std::uint32_t cmd;
    std::uint32_t cmdsize;
};

// 32位段命令。
struct SegmentCommand {
    std::uint32_t cmd;
    std::uint32_t cmdsize;
    char segname[16];
    std::uint32_t vmaddr;
    std::uint32_t vmsize;
    std::uint32_t fileoff;
    std::uint32_t filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    std::uint32_t nsects;
    std::uint32_t flags;
};

// 64位段命令。
struct SegmentCommand64 {
    std::uint32_t cmd;
    std::uint32_t cmdsize;
    char segname[16];
    std::uint64_t vmaddr;
    std::uint64_t vmsize;
    std::uint64_t fileoff;
    std::uint64_t filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    std::uint32_t nsects;
    std::uint32_t flags;
};

// 32位 section。
struct Section {
    char sectname[16];
    char segname[16];
    std::uint32_t addr;
    std::uint32_t size;
    std::uint32_t offset;
    std::uint32_t align;
    std::uint32_t reloff;
    std::uint32_t nreloc;
    std::uint32_t flags;
    std::uint32_t reserved1;
    std::uint32_t reserved2;
};

// 64位 section。
struct Section64 {
    char sectname[16];
    char segname[16];
    std::uint64_t addr;
    std::uint64_t size;
    std::uint32_t offset;
    std::uint32_t align;
    std::uint32_t reloff;
    std::uint32_t nreloc;
    std::uint32_t flags;
    std::uint32_t reserved1;
    std::uint32_t reserved2;
    std::uint32_t reserved3;
};

// 代码签名命令。
struct CodeSignatureCommand {
    std::uint32_t cmd;
    std::uint32_t cmdsize;
    std::uint32_t dataoff;
    std::uint32_t datasize;
};

// 加密信息命令。
struct EncryptionInfoCommand {
    std::uint32_t cmd;
    std::uint32_t cmdsize;
    std::uint32_t cryptoff;
    std::uint32_t cryptsize;
    std::uint32_t cryptid;
};

// dylib 名称偏移。
union LcStr {
    std::uint32_t offset;
};

// dylib 信息。
struct Dylib {
    LcStr name;
    std::uint32_t timestamp;
    std::uint32_t current_version;
    std::uint32_t compatibility_version;
};

// dylib 加载命令。
struct DylibCommand {
    std::uint32_t cmd;
    std::uint32_t cmdsize;
    Dylib dylib;
};

// CodeSignature SuperBlob 头。
struct CS_SuperBlob {
    std::uint32_t magic;
    std::uint32_t length;
    std::uint32_t count;
};

// CodeSignature blob 索引。
struct CS_BlobIndex {
    std::uint32_t type;
    std::uint32_t offset;
};

// CodeDirectory 结构体。
struct CS_CodeDirectory {
    std::uint32_t magic;
    std::uint32_t length;
    std::uint32_t version;
    std::uint32_t flags;
    std::uint32_t hashOffset;
    std::uint32_t identOffset;
    std::uint32_t nSpecialSlots;
    std::uint32_t nCodeSlots;
    std::uint32_t codeLimit;
    std::uint8_t hashSize;
    std::uint8_t hashType;
    std::uint8_t spare1;
    std::uint8_t pageSize;
    std::uint32_t spare2;
    // Version 0x20100。
    std::uint32_t scatterOffset;
    // Version 0x20200。
    std::uint32_t teamOffset;
    // Version 0x20300。
    std::uint32_t spare3;
    std::uint64_t codeLimit64;
    // Version 0x20400。
    std::uint64_t execSegBase;
    std::uint64_t execSegLimit;
    std::uint64_t execSegFlags;
};

#pragma pack(pop)

}

#endif
