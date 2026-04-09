/*
 * @file test_plist.cpp
 * @brief Binary Plist 解析验证测试程序。
 *
 * 本程序用于验证 Binary Plist -> XML 转换功能的正确性。
 * 测试覆盖：
 * 1. 格式检测：XML、Binary、Unknown
 * 2. Binary Plist 解析：dict、array、string、integer、bool、data 等类型
 * 3. ReadPListAsXML 端到端测试
 * 4. 与 plist.hpp 的 GetPListString 等函数的集成测试
 *
 * 编译方式（需链接 pugixml、openssl、libzip 等项目依赖）：
 *   cl /std:c++20 /EHsc test_plist.cpp common.cpp constants.cpp plist.cpp crypto.cpp
 *      /I<依赖头文件路径> /link <依赖库>
 *
 * 也可通过 CMake 添加测试目标（见下方说明）。
 */

#include <cassert>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "common.hpp"
#include "plist.hpp"

using namespace gitee::com::ivfzhou::ipasigner;

// ============================================================================
// 辅助函数：构造 Binary Plist 测试数据
// ============================================================================

/**
 * @brief 构造一个包含简单 dict 的 Binary Plist 数据。
 *
 * 生成的 plist 等价于：
 * {
 *     "CFBundleIdentifier": "com.test.app",
 *     "CFBundleExecutable": "TestApp",
 *     "CFBundleVersion": "1.0",
 *     "CFBundleShortVersionString": "1.0"
 * }
 *
 * Binary Plist 格式：
 * - Header: "bplist00" (8 bytes)
 * - Object Table: 对象按顺序排列
 * - Offset Table: 每个对象的偏移
 * - Trailer: 32 bytes 元数据
 */
static std::string buildTestBinaryPList() {
    // 为了生成正确的 binary plist，我们手工构建。
    // 对象列表：
    //   0: string "CFBundleIdentifier"
    //   1: string "com.test.app"
    //   2: string "CFBundleExecutable"
    //   3: string "TestApp"
    //   4: string "CFBundleVersion"
    //   5: string "1.0"
    //   6: string "CFBundleShortVersionString"
    //   7: string "1.0" (same value, different object)
    //   8: dict { 0:1, 2:3, 4:5, 6:7 }

    std::string buf{};

    // Header。
    buf += "bplist00";

    // 记录每个对象的偏移。
    std::vector<std::uint64_t> offsets{};

    auto writeASCIIString = [&](const std::string& s) {
        offsets.push_back(buf.size());
        if (s.size() < 15) {
            buf += static_cast<char>(0x50 | static_cast<uint8_t>(s.size()));
        } else {
            buf += static_cast<char>(0x5F);
            // 大小用 int 对象编码：0x10 = 1 byte int。
            if (s.size() < 256) {
                buf += static_cast<char>(0x10);
                buf += static_cast<char>(s.size());
            } else {
                buf += static_cast<char>(0x11);
                buf += static_cast<char>((s.size() >> 8) & 0xFF);
                buf += static_cast<char>(s.size() & 0xFF);
            }
        }
        buf += s;
    };

    // 对象 0-7: 字符串。
    writeASCIIString("CFBundleIdentifier");                // obj 0
    writeASCIIString("com.test.app");                      // obj 1
    writeASCIIString("CFBundleExecutable");                // obj 2
    writeASCIIString("TestApp");                           // obj 3
    writeASCIIString("CFBundleVersion");                   // obj 4
    writeASCIIString("1.0");                               // obj 5
    writeASCIIString("CFBundleShortVersionString");        // obj 6
    writeASCIIString("1.0");                               // obj 7

    // 对象 8: dict with 4 key-value pairs。
    // dict marker: 0xD0 | count (count < 15 -> 0xD4)
    offsets.push_back(buf.size());
    buf += static_cast<char>(0xD4); // dict with 4 entries。

    // Keys: object refs (1 byte each)。
    buf += static_cast<char>(0); // key: obj 0
    buf += static_cast<char>(2); // key: obj 2
    buf += static_cast<char>(4); // key: obj 4
    buf += static_cast<char>(6); // key: obj 6

    // Values: object refs (1 byte each)。
    buf += static_cast<char>(1); // val: obj 1
    buf += static_cast<char>(3); // val: obj 3
    buf += static_cast<char>(5); // val: obj 5
    buf += static_cast<char>(7); // val: obj 7

    // Offset Table。
    auto offsetTableOffset = static_cast<std::uint64_t>(buf.size());
    std::uint8_t offsetIntSize = 1; // offsets fit in 1 byte。
    for (auto off : offsets) {
        buf += static_cast<char>(off & 0xFF);
    }

    // Trailer (32 bytes)。
    // [6 unused][1 sortVersion][1 offsetIntSize][1 objectRefSize]
    // wait, actually trailer is 32 bytes total:
    //   bytes 0-5: unused (6 bytes)
    //   byte 6: offset int size
    //   byte 7: object ref size
    //   bytes 8-15: num objects (8 bytes, big-endian)
    //   bytes 16-23: top object (8 bytes, big-endian)
    //   bytes 24-31: offset table offset (8 bytes, big-endian)
    std::uint64_t numObjects = offsets.size(); // 9
    std::uint64_t topObject = 8; // root is object 8 (the dict)。
    std::uint8_t objectRefSize = 1;

    // 6 unused bytes。
    buf.append(6, '\0');
    // offset int size。
    buf += static_cast<char>(offsetIntSize);
    // object ref size。
    buf += static_cast<char>(objectRefSize);
    // num objects (8 bytes big-endian)。
    for (int i = 7; i >= 0; --i)
        buf += static_cast<char>((numObjects >> (i * 8)) & 0xFF);
    // top object (8 bytes big-endian)。
    for (int i = 7; i >= 0; --i)
        buf += static_cast<char>((topObject >> (i * 8)) & 0xFF);
    // offset table offset (8 bytes big-endian)。
    for (int i = 7; i >= 0; --i)
        buf += static_cast<char>((offsetTableOffset >> (i * 8)) & 0xFF);

    return buf;
}

/**
 * @brief 构造包含 bool 和 integer 的 Binary Plist 测试数据。
 *
 * 等价于：
 * {
 *     "enabled": true,
 *     "count": 42
 * }
 */
static std::string buildBoolIntBinaryPList() {
    std::string buf{};
    buf += "bplist00";

    std::vector<std::uint64_t> offsets{};

    // obj 0: string "enabled"
    offsets.push_back(buf.size());
    buf += static_cast<char>(0x57); // ASCII string, len 7。
    buf += "enabled";

    // obj 1: true。
    offsets.push_back(buf.size());
    buf += static_cast<char>(0x09); // true。

    // obj 2: string "count"。
    offsets.push_back(buf.size());
    buf += static_cast<char>(0x55); // ASCII string, len 5。
    buf += "count";

    // obj 3: integer 42 (1-byte int: 0x10, value 42)。
    offsets.push_back(buf.size());
    buf += static_cast<char>(0x10); // int, 2^0 = 1 byte。
    buf += static_cast<char>(42);

    // obj 4: dict with 2 entries。
    offsets.push_back(buf.size());
    buf += static_cast<char>(0xD2); // dict with 2 entries。
    buf += static_cast<char>(0); // key: obj 0
    buf += static_cast<char>(2); // key: obj 2
    buf += static_cast<char>(1); // val: obj 1
    buf += static_cast<char>(3); // val: obj 3

    // Offset Table。
    auto offsetTableOffset = static_cast<std::uint64_t>(buf.size());
    for (auto off : offsets) buf += static_cast<char>(off & 0xFF);

    // Trailer。
    std::uint64_t numObjects = offsets.size();
    std::uint64_t topObject = 4;
    buf.append(6, '\0');
    buf += static_cast<char>(1); // offset int size。
    buf += static_cast<char>(1); // object ref size。
    for (int i = 7; i >= 0; --i) buf += static_cast<char>((numObjects >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) buf += static_cast<char>((topObject >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) buf += static_cast<char>((offsetTableOffset >> (i * 8)) & 0xFF);

    return buf;
}

// ============================================================================
// 测试函数
// ============================================================================

static int testCount = 0;
static int passCount = 0;

static void checkTrue(bool cond, const std::string& name) {
    testCount++;
    if (cond) {
        passCount++;
        std::cout << "  [PASS] " << name << std::endl;
    } else {
        std::cout << "  [FAIL] " << name << std::endl;
    }
}

/**
 * @brief 测试 1：格式检测。
 */
static void testDetectFormat() {
    std::cout << "== Test 1: DetectPListFormat ==" << std::endl;

    // XML 格式。
    checkTrue(DetectPListFormat("<?xml version=\"1.0\"?><plist></plist>") == PListFormat::XML,
              "detect XML plist (<?xml)");
    checkTrue(DetectPListFormat("<plist version=\"1.0\"><dict/></plist>") == PListFormat::XML,
              "detect XML plist (<plist)");
    checkTrue(DetectPListFormat("<!DOCTYPE plist PUBLIC...>") == PListFormat::XML,
              "detect XML plist (<!DOCTYPE)");
    checkTrue(DetectPListFormat("  \n  <?xml version=\"1.0\"?>") == PListFormat::XML,
              "detect XML plist with leading whitespace");

    // Binary 格式。
    checkTrue(DetectPListFormat("bplist00...........") == PListFormat::Binary,
              "detect binary plist (bplist00)");
    checkTrue(DetectPListFormat(std::string("bplist00\x00\x01\x02", 11)) == PListFormat::Binary,
              "detect binary plist with binary data");

    // Unknown 格式。
    checkTrue(DetectPListFormat("some random text") == PListFormat::Unknown,
              "detect unknown format");
    checkTrue(DetectPListFormat("") == PListFormat::Unknown,
              "detect empty data as unknown");
}

/**
 * @brief 测试 2：Binary Plist 转 XML（基本 dict + string）。
 */
static void testBPListToXML_Basic() {
    std::cout << "== Test 2: BPListToXML (dict + string) ==" << std::endl;

    auto bplist = buildTestBinaryPList();
    checkTrue(DetectPListFormat(bplist) == PListFormat::Binary,
              "test data is detected as binary");

    auto xmlOpt = BPListToXML(bplist);
    checkTrue(xmlOpt.has_value(), "BPListToXML succeeds");

    if (xmlOpt) {
        auto& xml = *xmlOpt;

        // 验证 XML 头。
        checkTrue(xml.find("<?xml") != std::string::npos, "XML declaration present");
        checkTrue(xml.find("<plist") != std::string::npos, "plist root tag present");

        // 验证可以被 GetPListString 正确解析。
        auto bundleId = GetPListString(xml, "CFBundleIdentifier");
        checkTrue(bundleId.has_value() && *bundleId == "com.test.app",
                  "CFBundleIdentifier = com.test.app");

        auto executable = GetPListString(xml, "CFBundleExecutable");
        checkTrue(executable.has_value() && *executable == "TestApp",
                  "CFBundleExecutable = TestApp");

        auto version = GetPListString(xml, "CFBundleVersion");
        checkTrue(version.has_value() && *version == "1.0",
                  "CFBundleVersion = 1.0");

        auto shortVersion = GetPListString(xml, "CFBundleShortVersionString");
        checkTrue(shortVersion.has_value() && *shortVersion == "1.0",
                  "CFBundleShortVersionString = 1.0");
    }
}

/**
 * @brief 测试 3：Binary Plist 转 XML（bool + integer）。
 */
static void testBPListToXML_BoolInt() {
    std::cout << "== Test 3: BPListToXML (bool + integer) ==" << std::endl;

    auto bplist = buildBoolIntBinaryPList();
    auto xmlOpt = BPListToXML(bplist);
    checkTrue(xmlOpt.has_value(), "BPListToXML succeeds");

    if (xmlOpt) {
        auto& xml = *xmlOpt;
        checkTrue(xml.find("<true/>") != std::string::npos, "true value present");
        checkTrue(xml.find("<integer>42</integer>") != std::string::npos, "integer 42 present");
        checkTrue(xml.find("<key>enabled</key>") != std::string::npos, "key 'enabled' present");
        checkTrue(xml.find("<key>count</key>") != std::string::npos, "key 'count' present");
    }
}

/**
 * @brief 测试 4：ReadPListAsXML 端到端测试。
 *
 * 分别写入 XML 格式和 Binary 格式的 plist 文件，然后用 ReadPListAsXML 读取，
 * 验证两者都能正确返回可解析的 XML 内容。
 */
static void testReadPListAsXML() {
    std::cout << "== Test 4: ReadPListAsXML (end-to-end) ==" << std::endl;

    auto tmpDir = std::filesystem::temp_directory_path() / "ipasigner_test_plist";
    std::filesystem::create_directories(tmpDir);

    // 写入 XML 格式 plist。
    auto xmlPlistPath = tmpDir / "test_xml.plist";
    {
        std::string xmlContent = R"(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.xml.test</string>
</dict>
</plist>)";
        std::ofstream f(xmlPlistPath, std::ios::binary);
        f.write(xmlContent.data(), static_cast<std::streamsize>(xmlContent.size()));
        f.close();
    }

    auto xmlResult = ReadPListAsXML(xmlPlistPath);
    checkTrue(xmlResult.has_value(), "ReadPListAsXML succeeds for XML plist");
    if (xmlResult) {
        auto val = GetPListString(*xmlResult, "CFBundleIdentifier");
        checkTrue(val.has_value() && *val == "com.xml.test",
                  "XML plist: CFBundleIdentifier = com.xml.test");
    }

    // 写入 Binary 格式 plist。
    auto binPlistPath = tmpDir / "test_bin.plist";
    {
        auto binContent = buildTestBinaryPList();
        std::ofstream f(binPlistPath, std::ios::binary);
        f.write(binContent.data(), static_cast<std::streamsize>(binContent.size()));
        f.close();
    }

    auto binResult = ReadPListAsXML(binPlistPath);
    checkTrue(binResult.has_value(), "ReadPListAsXML succeeds for binary plist");
    if (binResult) {
        auto val = GetPListString(*binResult, "CFBundleIdentifier");
        checkTrue(val.has_value() && *val == "com.test.app",
                  "Binary plist: CFBundleIdentifier = com.test.app");
    }

    // 清理。
    std::filesystem::remove_all(tmpDir);
}

/**
 * @brief 测试 5：XML plist 经 SetPListString 修改后回写，再读取验证。
 *
 * 验证 Binary Plist -> XML 转换后的内容可以被正常修改和写回。
 */
static void testModifyConvertedPList() {
    std::cout << "== Test 5: Modify converted plist ==" << std::endl;

    auto bplist = buildTestBinaryPList();
    auto xmlOpt = BPListToXML(bplist);
    checkTrue(xmlOpt.has_value(), "BPListToXML succeeds");

    if (xmlOpt) {
        auto xml = std::move(*xmlOpt);

        // 修改 bundleId。
        bool setOk = SetPListString(xml, "CFBundleIdentifier", "com.new.bundle");
        checkTrue(setOk, "SetPListString succeeds on converted XML");

        auto newBundleId = GetPListString(xml, "CFBundleIdentifier");
        checkTrue(newBundleId.has_value() && *newBundleId == "com.new.bundle",
                  "Modified CFBundleIdentifier = com.new.bundle");

        // 其他字段不受影响。
        auto exec = GetPListString(xml, "CFBundleExecutable");
        checkTrue(exec.has_value() && *exec == "TestApp",
                  "CFBundleExecutable unchanged = TestApp");
    }
}

/**
 * @brief 测试 6：使用用户提供的真实 Binary Plist 文件。
 *
 * 读取项目根目录下的 Info.plist（Binary 格式），验证：
 * - 格式检测为 Binary
 * - BPListToXML 转换成功
 * - ReadPListAsXML 端到端成功
 * - 转换后的 XML 能被 GetPListString 正确解析出关键字段
 * - 转换后的 XML 能被 SetPListString 正确修改
 * - 修改后写入文件再读取仍然正确
 */
static void testRealBinaryPList(const std::filesystem::path& infoPlistPath) {
    std::cout << "== Test 6: Real Binary Plist (" << infoPlistPath.string() << ") ==" << std::endl;

    // 6.1 读取原始文件。
    auto rawOpt = ReadFile(infoPlistPath);
    checkTrue(rawOpt.has_value(), "ReadFile succeeds for real Info.plist");
    if (!rawOpt) return;

    // 6.2 格式检测。
    checkTrue(DetectPListFormat(*rawOpt) == PListFormat::Binary,
              "real Info.plist detected as Binary");

    // 6.3 BPListToXML 转换。
    auto xmlOpt = BPListToXML(*rawOpt);
    checkTrue(xmlOpt.has_value(), "BPListToXML succeeds for real Info.plist");
    if (!xmlOpt) return;

    auto& xml = *xmlOpt;

    // 6.4 XML 基本结构校验。
    checkTrue(xml.find("<?xml") != std::string::npos, "converted XML has declaration");
    checkTrue(xml.find("<plist") != std::string::npos, "converted XML has plist root");
    checkTrue(xml.find("<dict>") != std::string::npos || xml.find("<dict\n") != std::string::npos,
              "converted XML has dict element");

    // 6.5 关键字段解析验证。
    auto bundleId = GetPListString(xml, "CFBundleIdentifier");
    checkTrue(bundleId.has_value() && !bundleId->empty(),
              std::string("CFBundleIdentifier exists: ") + (bundleId ? *bundleId : "<null>"));

    auto executable = GetPListString(xml, "CFBundleExecutable");
    checkTrue(executable.has_value() && !executable->empty(),
              std::string("CFBundleExecutable exists: ") + (executable ? *executable : "<null>"));

    auto version = GetPListString(xml, "CFBundleVersion");
    checkTrue(version.has_value() && !version->empty(),
              std::string("CFBundleVersion exists: ") + (version ? *version : "<null>"));

    auto shortVersion = GetPListString(xml, "CFBundleShortVersionString");
    checkTrue(shortVersion.has_value() && !shortVersion->empty(),
              std::string("CFBundleShortVersionString exists: ") + (shortVersion ? *shortVersion : "<null>"));

    auto bundleName = GetPListString(xml, "CFBundleName");
    checkTrue(bundleName.has_value(),
              std::string("CFBundleName exists: ") + (bundleName ? *bundleName : "<null>"));

    // 6.6 ReadPListAsXML 端到端验证。
    auto xmlFromFile = ReadPListAsXML(infoPlistPath);
    checkTrue(xmlFromFile.has_value(), "ReadPListAsXML succeeds for real Info.plist");
    if (xmlFromFile) {
        auto bid = GetPListString(*xmlFromFile, "CFBundleIdentifier");
        checkTrue(bid.has_value() && bid == bundleId,
                  "ReadPListAsXML result matches BPListToXML result");
    }

    // 6.7 修改验证：修改 BundleId 后确认修改生效且其他字段不受影响。
    auto xmlCopy = xml;
    bool setOk = SetPListString(xmlCopy, "CFBundleIdentifier", "com.test.modified");
    checkTrue(setOk, "SetPListString succeeds on converted real plist");

    auto newBid = GetPListString(xmlCopy, "CFBundleIdentifier");
    checkTrue(newBid.has_value() && *newBid == "com.test.modified",
              "Modified CFBundleIdentifier = com.test.modified");

    auto execAfter = GetPListString(xmlCopy, "CFBundleExecutable");
    checkTrue(execAfter.has_value() && execAfter == executable,
              "CFBundleExecutable unchanged after modification");

    // 6.8 写入文件后再读取验证。
    auto tmpDir = std::filesystem::temp_directory_path() / "ipasigner_test_real_plist";
    std::filesystem::create_directories(tmpDir);
    auto tmpPlistPath = tmpDir / "Info.plist";
    bool writeOk = WriteFile(tmpPlistPath, xmlCopy);
    checkTrue(writeOk, "WriteFile succeeds for modified plist");

    if (writeOk) {
        auto rereadOpt = ReadPListAsXML(tmpPlistPath);
        checkTrue(rereadOpt.has_value(), "re-read modified plist succeeds");
        if (rereadOpt) {
            auto rereadBid = GetPListString(*rereadOpt, "CFBundleIdentifier");
            checkTrue(rereadBid.has_value() && *rereadBid == "com.test.modified",
                      "re-read CFBundleIdentifier = com.test.modified");
        }
    }

    std::filesystem::remove_all(tmpDir);

    // 6.9 输出完整转换结果供人工检查。
    std::cout << "\n  --- Converted XML (first 2000 chars) ---" << std::endl;
    std::cout << xml.substr(0, 2000) << std::endl;
    if (xml.size() > 2000)
        std::cout << "  ... (truncated, total " << xml.size() << " chars)" << std::endl;
    std::cout << "  --- End of converted XML ---\n" << std::endl;
}

/**
 * @brief 测试 7：边界情况。
 */
static void testEdgeCases() {
    std::cout << "== Test 7: Edge cases ==" << std::endl;

    // 空数据。
    checkTrue(!BPListToXML("").has_value(), "empty data returns nullopt");

    // 太短的数据。
    checkTrue(!BPListToXML("bplist00short").has_value(), "too-short data returns nullopt");

    // 错误魔数。
    std::string badMagic(50, '\0');
    badMagic[0] = 'x';
    checkTrue(!BPListToXML(badMagic).has_value(), "bad magic returns nullopt");

    // WrapperPListXMLTag 安全性（string_view 不以 null 结尾的场景）。
    std::string base = "hello world";
    std::string_view sv(base.data(), 5); // "hello"，不以 null 结尾。
    auto wrapped = WrapperPListXMLTag(sv);
    checkTrue(wrapped == "<plist>hello</plist>", "WrapperPListXMLTag handles string_view correctly");
}

// ============================================================================
// 主函数
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "=== Binary Plist Parser Verification Tests ===" << std::endl;
    std::cout << std::endl;

    testDetectFormat();
    testBPListToXML_Basic();
    testBPListToXML_BoolInt();
    testReadPListAsXML();
    testModifyConvertedPList();

    // 真实 Binary Plist 文件测试。
    std::filesystem::path realPlistPath;
    if (argc > 1) {
        realPlistPath = argv[1];
    } else {
        // 默认尝试项目根目录下的 Info.plist。
        realPlistPath = std::filesystem::path(__FILE__).parent_path() / "Info.plist";
        if (!std::filesystem::exists(realPlistPath)) {
            realPlistPath = "Info.plist";
        }
    }
    if (std::filesystem::exists(realPlistPath)) {
        testRealBinaryPList(realPlistPath);
    } else {
        std::cout << "== Test 6: SKIPPED (no real Info.plist found at " << realPlistPath.string() << ") ==" << std::endl;
    }

    testEdgeCases();

    std::cout << std::endl;
    std::cout << "=== Results: " << passCount << "/" << testCount << " passed ===" << std::endl;

    if (passCount == testCount) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << (testCount - passCount) << " test(s) FAILED!" << std::endl;
        return 1;
    }
}
