/**
 * @file plist.hpp
 * @brief plist/XML 解析与修改接口声明。
 *
 * 提供对 Apple plist（XML 格式）文件的读取和修改操作，包括：
 * - 获取指定键的字符串值、字符串数组值、裸 XML 数据
 * - 设置指定键的字符串值、字符串数组值、XML 数据
 * - 通过点号分隔的键路径设置/删除嵌套键值
 *
 * 底层使用 pugixml 库进行 XML 解析和 DOM 操作。
 */

#ifndef IPASIGNER_PLIST_HPP
#define IPASIGNER_PLIST_HPP

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 从 plist XML 中获取指定键的字符串值。
 * @param plistXml plist XML 字符串。
 * @param key 要查找的键名。
 * @return 成功返回字符串值，未找到或失败返回 std::nullopt。
 */
std::optional<std::string> GetPListString(std::string_view plistXml, std::string_view key);

/**
 * @brief 从 plist XML 中获取指定键的字符串数组值。
 * @param plistXml plist XML 字符串。
 * @param key 要查找的键名。
 * @return 成功返回字符串数组，未找到或失败返回 std::nullopt。
 */
std::optional<std::vector<std::string>> GetPListArrayString(std::string_view plistXml, std::string_view key);

/**
 * @brief 获取 plist XML 中指定键的裸 XML 数据（包含标签）。
 * @param plistXml plist XML 字符串。
 * @param key 要查找的键名。
 * @return 成功返回值节点的 XML 字符串，未找到或失败返回 std::nullopt。
 */
std::optional<std::string> GetPListXMLValue(std::string_view plistXml, std::string_view key);

/**
 * @brief 设置 plist XML 中指定键的字符串值。
 *
 * 若键已存在则替换其值，若不存在则追加新的键值对。
 *
 * @param plistXml plist XML 字符串（原地修改）。
 * @param key 键名。
 * @param value 要设置的字符串值。
 * @return 成功返回 true，失败返回 false。
 */
bool SetPListString(std::string& plistXml, std::string_view key, std::string_view value);

/**
 * @brief 设置 plist XML 中指定键的字符串数组值。
 *
 * 若键已存在则替换其值，若不存在则追加新的键值对。
 *
 * @param plistXml plist XML 字符串（原地修改）。
 * @param key 键名。
 * @param value 要设置的字符串数组。
 * @return 成功返回 true，失败返回 false。
 */
bool SetPListArrayString(std::string& plistXml, std::string_view key, const std::vector<std::string>& value);

/**
 * @brief 设置 plist XML 中指定键的裸 XML 数据。
 *
 * 若键已存在则替换其值，若不存在则追加新的键值对。
 *
 * @param plistXml plist XML 字符串（原地修改）。
 * @param key 键名。
 * @param value 要设置的 XML 片段。
 * @return 成功返回 true，失败返回 false。
 */
bool SetPListXMLValue(std::string& plistXml, std::string_view, std::string_view value);

/**
 * @brief 通过点号分隔的键路径设置嵌套的字符串值。
 *
 * keyChain 格式示例："NSExtension.NSExtensionAttributes.WKAppBundleIdentifier"。
 * 字符串段表示 dict 的 key，数字段表示 array 的下标。
 * 若中间节点不存在则自动创建。
 *
 * @param plistXml plist XML 字符串（原地修改）。
 * @param keyChain 点号分隔的键路径。
 * @param value 要设置的字符串值。
 * @return 成功返回 true，失败返回 false。
 */
bool SetPListStringByChain(std::string& plistXml, std::string_view keyChain, std::string_view value);

/**
 * @brief 通过点号分隔的键路径删除嵌套的字符串键值。
 *
 * 若目标节点不存在则视为成功（无需删除）。
 * 若目标节点存在但不是 string 类型则返回 false。
 *
 * @param plistXml plist XML 字符串（原地修改）。
 * @param key 点号分隔的键路径。
 * @return 成功返回 true，失败返回 false。
 */
bool DeletePListStringByChain(std::string& plistXml, std::string_view key);

}

#endif
