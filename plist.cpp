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
 * @file plist.cpp
 * @brief plist/XML 解析与修改实现。
 *
 * 基于 pugixml 库实现对 Apple plist（XML 格式）文件的读取和修改操作。
 * plist 的典型结构为：
 * @code
 *   <plist>
 *     <dict>
 *       <key>键名</key>
 *       <string>值</string>
 *       <key>键名2</key>
 *       <array>
 *         <string>元素1</string>
 *         <string>元素2</string>
 *       </array>
 *     </dict>
 *   </plist>
 * @endcode
 *
 * 所有函数都在顶层 dict 节点中查找指定的 key，然后操作其后继的值节点。
 */

#include <cstdlib>
#include <format>
#include <optional>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <pugixml.hpp>

#include "Logger.tpp"
#include "common.hpp"
#include "constants.hpp"
#include "plist.hpp"

namespace gitee::com::ivfzhou::ipasigner {

/**
 * @brief 从 plist XML 中获取指定键的字符串值。
 *
 * 在顶层 dict 中查找匹配的 key 节点，返回其后继 string 节点的值。
 *
 * @param plistXml plist XML 字符串。
 * @param key 要查找的键名。
 * @return 成功返回字符串值，未找到或失败返回 std::nullopt。
 */
std::optional<std::string> GetPListString(const std::string_view plistXml, const std::string_view key) {
    // 解析 xml 数据。
    pugi::xml_document plist{};
    if (auto result = plist.load_string(
            plistXml.data(), pugi::parse_declaration | pugi::parse_doctype | pugi::parse_pi | pugi::parse_cdata);
        !result) {
        Logger::error("failed to parse plist/xml::", result.description());
        return std::nullopt;
    }

    // 获取顶层字典节点。
    auto dictNode = plist.select_node(std::format("/{}/{}", PLIST_TAG_ROOT, PLIST_TAG_DICT).c_str()).node();
    if (!dictNode) {
        Logger::error("plist dict node not found");
        return std::nullopt;
    }

    // 遍历寻找数据。
    for (auto&& it = dictNode.begin(); it != dictNode.end(); ++it) {
        if (key != it->child_value() || !StringEqualIgnoreCase(PLIST_TAG_KEY, it->name())) continue;

        ++it;
        if (it == dictNode.end() || !StringEqualIgnoreCase(PLIST_TAG_STRING, it->name())) return std::nullopt;

        return it->child_value();
    }

    return std::nullopt;
}

/**
 * @brief 从 plist XML 中获取指定键的字符串数组值。
 *
 * 在顶层 dict 中查找匹配的 key 节点，返回其后继 array 节点中所有子节点的值。
 *
 * @param plistXml plist XML 字符串。
 * @param key 要查找的键名。
 * @return 成功返回字符串数组，未找到或失败返回 std::nullopt。
 */
std::optional<std::vector<std::string>> GetPListArrayString(const std::string_view plistXml,
                                                            const std::string_view key) {
    // 解析 xml 数据。
    pugi::xml_document plist{};
    if (auto result = plist.load_string(
            plistXml.data(), pugi::parse_declaration | pugi::parse_doctype | pugi::parse_pi | pugi::parse_cdata);
        !result) {
        Logger::error("failed to parse plist/xml:", result.description());
        return std::nullopt;
    }

    // 获取顶层字典节点。
    auto dictNode = plist.select_node(std::format("/{}/{}", PLIST_TAG_ROOT, PLIST_TAG_DICT).c_str()).node();
    if (!dictNode) {
        Logger::error("plist dict node not found");
        return std::nullopt;
    }

    // 遍历寻找数据。
    for (auto&& it = dictNode.begin(); it != dictNode.end(); ++it) {
        if (key != it->child_value() || !StringEqualIgnoreCase(PLIST_TAG_KEY, it->name())) continue;

        ++it;
        if (it == dictNode.end() || !StringEqualIgnoreCase(PLIST_TAG_ARRAY, it->name())) return std::nullopt;

        std::vector<std::string> result{};
        for (auto&& child : it->children()) result.emplace_back(child.child_value());

        return result;
    }

    return std::nullopt;
}

/**
 * @brief 获取 plist XML 中指定键的裸 XML 数据。
 *
 * 在顶层 dict 中查找匹配的 key 节点，将其后继值节点序列化为 XML 字符串返回。
 *
 * @param plistXml plist XML 字符串。
 * @param key 要查找的键名。
 * @return 成功返回值节点的 XML 字符串，未找到或失败返回 std::nullopt。
 */
std::optional<std::string> GetPListXMLValue(const std::string_view plistXml, const std::string_view key) {
    // 解析 xml 数据。
    pugi::xml_document plist{};
    if (auto result = plist.load_string(
            plistXml.data(), pugi::parse_declaration | pugi::parse_doctype | pugi::parse_pi | pugi::parse_cdata);
        !result) {
        Logger::error("failed to parse plist/xml::", result.description());
        return std::nullopt;
    }

    // 获取顶层字典节点。
    auto dictNode = plist.select_node(std::format("/{}/{}", PLIST_TAG_ROOT, PLIST_TAG_DICT).c_str()).node();
    if (!dictNode) {
        Logger::error("plist dict node not found");
        return std::nullopt;
    }

    // 遍历寻找数据。
    for (auto&& it = dictNode.begin(); it != dictNode.end(); ++it) {
        if (key != it->child_value() || !StringEqualIgnoreCase(PLIST_TAG_KEY, it->name())) continue;

        ++it;
        if (it == dictNode.end()) return std::nullopt;

        std::ostringstream out{};
        it->print(out);
        return out.str();
    }

    return std::nullopt;
}

/**
 * @brief 设置 plist XML 中指定键的字符串值。
 *
 * 若键已存在则删除旧值节点并插入新的 string 节点；
 * 若键不存在则在 dict 末尾追加新的 key + string 节点对。
 *
 * @param plistXml plist XML 字符串（原地修改）。
 * @param key 键名。
 * @param value 要设置的字符串值。
 * @return 成功返回 true，失败返回 false。
 */
bool SetPListString(std::string& plistXml, const std::string_view key, const std::string_view value) {
    // 解析 xml 数据。
    pugi::xml_document plist{};
    if (auto result = plist.load_string(
            plistXml.c_str(), pugi::parse_declaration | pugi::parse_doctype | pugi::parse_pi | pugi::parse_cdata);
        !result) {
        Logger::error("failed to parse plist/xml::", result.description());
        return false;
    }

    // 获取顶层字典节点。
    auto dictNode = plist.select_node(std::format("/{}/{}", PLIST_TAG_ROOT, PLIST_TAG_DICT).c_str()).node();
    if (!dictNode) {
        Logger::error("plist dict node not found");
        return false;
    }

    // 遍历寻找数据。
    for (auto&& it = dictNode.begin(); it != dictNode.end(); ++it) {
        auto keyNode = *it;
        if (key != keyNode.child_value() || !StringEqualIgnoreCase(PLIST_TAG_KEY, keyNode.name())) continue;

        ++it;

        // 删除老的容器节点。
        if (it != dictNode.end() && !StringEqualIgnoreCase(PLIST_TAG_KEY, it->name())) {
            if (!dictNode.remove_child(*it)) {
                Logger::error("failed to remove plist node");
                return false;
            }
        }

        // 添加新节点。
        if (!dictNode.insert_child_after(PLIST_TAG_STRING, keyNode).append_child(pugi::node_pcdata).set_value(value)) {
            Logger::error("failed to create plist node");
            return false;
        }

        // 将修改后的 DOM 序列化回 plist_xml。
        std::ostringstream out{};
        plist.print(out);
        plistXml = out.str();

        return true;
    }

    // 没有找到节点，添加新节点。
    if (!dictNode.append_child(PLIST_TAG_KEY).append_child(pugi::node_pcdata).set_value(key.data())) {
        Logger::error("failed to append plist/xml key");
        return false;
    }
    if (!dictNode.append_child(PLIST_TAG_STRING).append_child(pugi::node_pcdata).set_value(value.data())) {
        Logger::error("failed to append plist/xml value");
        return false;
    }

    // 将修改后的 DOM 序列化回 plist_xml。
    std::ostringstream out{};
    plist.print(out);
    plistXml = out.str();

    return true;
}

/**
 * @brief 设置 plist XML 中指定键的字符串数组值。
 *
 * 若键已存在则删除旧值节点并插入新的 array 节点；
 * 若键不存在则在 dict 末尾追加新的 key + array 节点对。
 *
 * @param plistXml plist XML 字符串（原地修改）。
 * @param key 键名。
 * @param value 要设置的字符串数组。
 * @return 成功返回 true，失败返回 false。
 */
bool SetPListArrayString(std::string& plistXml, const std::string_view key, const std::vector<std::string>& value) {
    // 解析 xml 数据。
    pugi::xml_document plist{};
    if (auto result = plist.load_string(
            plistXml.c_str(), pugi::parse_declaration | pugi::parse_doctype | pugi::parse_pi | pugi::parse_cdata);
        !result) {
        Logger::error("failed to parse plist/xml::", result.description());
        return false;
    }

    // 获取顶层字典节点。
    auto dictNode = plist.select_node(std::format("/{}/{}", PLIST_TAG_ROOT, PLIST_TAG_DICT).c_str()).node();
    if (!dictNode) {
        Logger::error("plist dict node not found");
        return false;
    }

    // 遍历寻找数据。
    for (auto&& it = dictNode.begin(); it != dictNode.end(); ++it) {
        auto keyNode = *it;
        if (key != keyNode.child_value() || !StringEqualIgnoreCase(PLIST_TAG_KEY, keyNode.name())) continue;

        ++it;

        // 删除老节点。
        if (it != dictNode.end() && !StringEqualIgnoreCase(PLIST_TAG_KEY, it->name())) {
            if (!dictNode.remove_child(*it)) {
                Logger::error("failed to remove plist node");
                return false;
            }
        }

        // 添加节点。
        auto arrayNode = dictNode.insert_child_after(PLIST_TAG_ARRAY, keyNode);
        for (auto&& v : value) {
            if (!arrayNode.append_child(PLIST_TAG_STRING).append_child(pugi::node_pcdata).set_value(v)) {
                Logger::error("failed to append plist string value");
                return false;
            }
        }

        // 将修改后的 DOM 序列化回 plist_xml。
        std::ostringstream out{};
        plist.print(out);
        plistXml = out.str();

        return true;
    }

    // 没有找到节点，添加新节点。
    if (!dictNode.append_child(PLIST_TAG_KEY).append_child(pugi::node_pcdata).set_value(key.data())) {
        Logger::error("failed to append plist/xml key");
        return false;
    }
    auto arrayNode = dictNode.append_child(PLIST_TAG_ARRAY);
    for (auto&& v : value) {
        if (!arrayNode.append_child(PLIST_TAG_STRING).append_child(pugi::node_pcdata).set_value(v)) {
            Logger::error("failed to append plist string value");
            return false;
        }
    }

    // 将修改后的 DOM 序列化回 plist_xml。
    std::ostringstream out{};
    plist.print(out);
    plistXml = out.str();

    return true;
}

/**
 * @brief 设置 plist XML 中指定键的裸 XML 数据。
 *
 * 若键已存在则删除旧值节点并插入新的 XML 片段；
 * 若键不存在则在 dict 末尾追加新的 key + XML 片段。
 *
 * @param plistXml plist XML 字符串（原地修改）。
 * @param key 键名。
 * @param value 要设置的 XML 片段。
 * @return 成功返回 true，失败返回 false。
 */
bool SetPListXMLValue(std::string& plistXml, const std::string_view key, const std::string_view value) {
    // 解析 xml 数据。
    pugi::xml_document plist{};
    if (auto result = plist.load_string(
            plistXml.c_str(), pugi::parse_declaration | pugi::parse_doctype | pugi::parse_pi | pugi::parse_cdata);
        !result) {
        Logger::error("failed to parse plist/xml:", result.description());
        return false;
    }

    // 获取顶层字典节点。
    auto dictNode = plist.select_node(std::format("/{}/{}", PLIST_TAG_ROOT, PLIST_TAG_DICT).c_str()).node();
    if (!dictNode) {
        Logger::error("plist dict node not found");
        return false;
    }

    // 解析新值 XML 片段。
    pugi::xml_document valueDoc{};
    if (auto result = valueDoc.load_string(value.data()); !result) {
        Logger::error("failed to parse xml value:", result.description());
        return false;
    }

    // 遍历寻找数据。
    for (auto&& it = dictNode.begin(); it != dictNode.end(); ++it) {
        auto keyNode = *it;
        if (key != it->child_value() || !StringEqualIgnoreCase(PLIST_TAG_KEY, keyNode.name())) continue;

        ++it;

        // 删除旧值节点。
        if (it != dictNode.end() && !StringEqualIgnoreCase(PLIST_TAG_KEY, it->name())) {
            if (!dictNode.remove_child(*it)) {
                Logger::error("failed to remove plist node");
                return false;
            }
        }

        // 依次将新值子节点插入到 key 节点之后
        auto prev = keyNode;
        for (auto&& child = valueDoc.first_child(); child;) {
            auto next = child.next_sibling();
            prev = dictNode.insert_copy_after(child, prev);
            child = next;
        }

        // 将修改后的 DOM 序列化回 plistXml。
        std::ostringstream out{};
        plist.print(out);
        plistXml = out.str();

        return true;
    }

    // 没有对应节点，创建并添加。
    auto keyNode = dictNode.append_child(PLIST_TAG_KEY);
    if (!keyNode.append_child(pugi::node_pcdata).set_value(key)) {
        Logger::error("failed to append plist/xml key node");
        return false;
    }
    auto prev = keyNode;
    for (auto&& child = valueDoc.first_child(); child;) {
        auto next = child.next_sibling();
        prev = dictNode.insert_copy_after(child, prev);
        child = next;
    }

    // 将修改后的 DOM 序列化回 plistXml。
    std::ostringstream out{};
    plist.print(out);
    plistXml = out.str();

    return true;
}

/**
 * @brief 通过点号分隔的键路径设置嵌套的字符串值。
 *
 * 支持混合路径：字符串段表示 dict 的 key，数字段表示 array 的下标。
 * 例如 "NSExtension.0.name" 表示 dict[NSExtension] -> array[0] -> dict[name]。
 * 若中间节点不存在则自动创建。
 *
 * @param plistXml plist XML 字符串（原地修改）。
 * @param keyChain 点号分隔的键路径。
 * @param value 要设置的字符串值。
 * @return 成功返回 true，失败返回 false。
 */
bool SetPListStringByChain(std::string& plistXml, const std::string_view keyChain, const std::string_view value) {
    // 解析 keyChain 为多个段。
    std::vector<std::string> tokens{};
    std::istringstream iss(keyChain.data());
    for (std::string token{}; std::getline(iss, token, '.');) {
        if (token.empty()) return false;
        tokens.push_back(token);
    }
    if (tokens.empty()) return false;

    // 判断字符串是否为非负整数。
    auto tryParseIndex = [](const std::string& s) -> std::optional<std::size_t> {
        if (s.empty()) return std::nullopt;
        std::size_t val{};
        for (const char& c : s) {
            if (c < '0' || c > '9') return std::nullopt;
            val = val * 10 + (c - '0');
        }
        return val;
    };

    // 解析 xml 数据。
    pugi::xml_document plist{};
    if (auto result = plist.load_string(
            plistXml.c_str(), pugi::parse_declaration | pugi::parse_doctype | pugi::parse_pi | pugi::parse_cdata);
        !result) {
        Logger::error("failed to parse plist/xml::", result.description());
        return false;
    }
    auto currentNode = plist.select_node(std::format("/{}/{}", PLIST_TAG_ROOT, PLIST_TAG_DICT).c_str()).node();
    if (!currentNode) {
        Logger::error("plist dict node not found");
        return false;
    }

    // 逐层遍历 keyChain。
    for (std::size_t i{}; i < tokens.size(); ++i) {
        bool isLast = i == tokens.size() - 1;
        const auto& token = tokens[i];

        // 处理数组节点。第一个元素不能是数组下标。
        if (auto idxOpt = tryParseIndex(token); idxOpt && i != 0) {
            // 节点必须是 array 类型。
            if (!StringEqualIgnoreCase(currentNode.name(), PLIST_TAG_ARRAY)) {
                Logger::error("invalid plist/xml schema, must be array node");
                return false;
            }

            // 获取对应下标的子节点。
            auto child = currentNode.first_child();
            for (std::size_t j{}; j < *idxOpt && child; ++j) child = child.next_sibling();

            // 获取下一跳的节点类型。
            auto nextNodeType = isLast         ? PLIST_TAG_STRING
                : tryParseIndex(tokens[i + 1]) ? PLIST_TAG_ARRAY
                                               : PLIST_TAG_DICT;

            // 重新寻找下标节点。
            bool createdNode = !child;
            if (createdNode) {
                // 补齐子节点。
                std::size_t count{};
                for (auto it = currentNode.begin(); it != currentNode.end(); ++it) count++;
                auto needCreatNodeNum = *idxOpt - count + 1;
                while (needCreatNodeNum > 0) {
                    if (!currentNode.append_child(nextNodeType)) {
                        Logger::error("failed to append plist/xml array child");
                    }
                    --needCreatNodeNum;
                }

                child = currentNode.first_child();
                for (std::size_t j{}; j < *idxOpt; ++j) child = child.next_sibling();
            }

            // 最后一个 token，设置节点。
            if (isLast) {
                // 子节点类型须要是 string 类型。
                if (child && child.name() != std::string_view(PLIST_TAG_STRING)) {
                    Logger::error("plist/xml schema is invalid, want string type, got", child.name());
                    return false;
                }

                // 没有缺少节点，修改需要修改的节点。
                if (!createdNode) {
                    // 修改节点值。
                    if (!child.first_child().set_value(value)) {
                        Logger::error("failed to set plist/xml string value");
                        return false;
                    }
                } else {
                    // 添加节点值。
                    if (!child.append_child(pugi::node_pcdata).set_value(value)) {
                        Logger::error("failed to set plist/xml string value");
                        return false;
                    }
                }

                // 将修改后的 DOM 序列化回 plistXml。
                std::ostringstream out{};
                plist.print(out);
                plistXml = out.str();
                return true;
            }

            // 重新获取目标元素。
            currentNode = child;
        }

        // 处理字典节点。
        else {
            // 节点必须是 dict 类型。
            if (!StringEqualIgnoreCase(currentNode.name(), PLIST_TAG_DICT)) {
                Logger::error("invalid plist/xml schema, must be dict node");
                return false;
            }

            // 查找键。
            pugi::xml_node keyNode{};
            pugi::xml_node valueNode{};
            for (auto it = currentNode.begin(); it != currentNode.end(); ++it) {
                if (!StringEqualIgnoreCase(it->name(), PLIST_TAG_KEY) || std::string_view(it->child_value()) != token)
                    continue;

                keyNode = *it;
                valueNode = it->next_sibling();
                if (!valueNode || valueNode.name() == std::string_view(PLIST_TAG_KEY)) {
                    Logger::error("invalid plist/xml schema, no value node");
                    return false;
                }
                break;
            }

            // 是最后一个 token，进行修改操作。
            if (isLast) {
                if (keyNode) {
                    // 键已存在，容器节点必须是 string 类型。
                    if (!valueNode || !StringEqualIgnoreCase(valueNode.name(), PLIST_TAG_STRING)) return false;

                    // 修改节点值。
                    if (!valueNode.first_child().set_value(value.data(), value.size())) {
                        Logger::error("failed to update plist/xml string value");
                        return false;
                    }
                } else {
                    // 键不存在，创建 key 和 string 节点。
                    keyNode = currentNode.append_child(PLIST_TAG_KEY);
                    keyNode.append_child(pugi::node_pcdata).set_value(token.c_str());
                    auto stringNode = currentNode.append_child(PLIST_TAG_STRING);
                    stringNode.append_child(pugi::node_pcdata).set_value(value.data());
                }

                // 将修改后的 DOM 序列化回 plistXml。
                std::ostringstream out{};
                plist.print(out);
                plistXml = out.str();
                return true;
            }

            // 键不存在，创建 key 和容器节点。
            if (!keyNode) {
                keyNode = currentNode.append_child(PLIST_TAG_KEY);
                keyNode.append_child(pugi::node_pcdata).set_value(token.c_str());
                if (tryParseIndex(tokens[i + 1])) {
                    if (valueNode = currentNode.append_child(PLIST_TAG_ARRAY); !valueNode) {
                        Logger::error("failed to append plist/xml array node");
                        return false;
                    }
                } else {
                    if (valueNode = currentNode.append_child(PLIST_TAG_DICT); !valueNode) {
                        Logger::error("failed to append plist/xml dict node");
                        return false;
                    }
                }
            }

            currentNode = valueNode;
        }
    }

    return false;
}

/**
 * @brief 通过点号分隔的键路径删除嵌套的字符串键值。
 *
 * 若目标节点不存在则视为成功（无需删除）。
 * 若目标节点存在但不是 string 类型则返回 false。
 * 对于 dict 中的键，会同时删除 key 节点和值节点。
 * 对于 array 中的元素，会删除对应下标的子节点。
 *
 * @param plistXml plist XML 字符串（原地修改）。
 * @param keyChain 点号分隔的键路径。
 * @return 成功返回 true，失败返回 false。
 */
bool DeletePListStringByChain(std::string& plistXml, const std::string_view keyChain) {
    // 解析 keyChain 为多个段。
    std::vector<std::string> tokens{};
    std::istringstream iss(keyChain.data());
    for (std::string token{}; std::getline(iss, token, '.');) {
        if (token.empty()) return false;
        tokens.push_back(token);
    }
    if (tokens.empty()) return false;

    // 判断字符串是否为非负整数。
    auto tryParseIndex = [](const std::string& s) -> std::optional<std::size_t> {
        if (s.empty()) return std::nullopt;
        std::size_t val{};
        for (const char& c : s) {
            if (c < '0' || c > '9') return std::nullopt;
            val = val * 10 + (c - '0');
        }
        return val;
    };

    // 解析 xml 数据。
    pugi::xml_document plist{};
    if (auto result = plist.load_string(
            plistXml.c_str(), pugi::parse_declaration | pugi::parse_doctype | pugi::parse_pi | pugi::parse_cdata);
        !result) {
        Logger::error("failed to parse plist/xml::", result.description());
        return false;
    }
    auto currentNode = plist.select_node(std::format("/{}/{}", PLIST_TAG_ROOT, PLIST_TAG_DICT).c_str()).node();
    if (!currentNode) {
        Logger::error("plist/xml dict node not found");
        return false;
    }

    // 逐层遍历 keyChain。
    for (std::size_t i{}; i < tokens.size(); ++i) {
        bool isLast = i == tokens.size() - 1;
        const auto& token = tokens[i];

        // 处理数组节点。第一个元素不能是数组下标。
        if (auto idxOpt = tryParseIndex(token); idxOpt && i != 0) {

            // 不存在节点，返回 true。
            if (!StringEqualIgnoreCase(currentNode.name(), PLIST_TAG_ARRAY)) return true;

            // 获取对应下标的子节点。
            auto child = currentNode.first_child();
            for (std::size_t j{}; j < *idxOpt && child; ++j) child = child.next_sibling();

            // 不存在节点，返回 true。
            if (!child) return true;

            // 最后一个 token，删除该数组元素。
            if (isLast) {
                currentNode.remove_child(child);

                std::ostringstream out{};
                plist.print(out);
                plistXml = out.str();
                return true;
            }

            currentNode = child;
        }

        // 处理字典节点。
        else {
            if (!StringEqualIgnoreCase(currentNode.name(), PLIST_TAG_DICT)) {
                Logger::error("invalid plist/xml schema");
                return false;
            }

            // 查找键。
            pugi::xml_node keyNode{};
            pugi::xml_node valueNode{};
            for (auto it = currentNode.begin(); it != currentNode.end(); ++it) {
                if (!StringEqualIgnoreCase(it->name(), PLIST_TAG_KEY) || std::string_view(it->child_value()) != token)
                    continue;

                keyNode = *it;
                valueNode = it->next_sibling();
                if (!valueNode || StringEqualIgnoreCase(valueNode.name(), PLIST_TAG_KEY)) {
                    Logger::error("invalid plist/xml schema");
                    return false;
                }
                break;
            }

            // 没有节点，不必删除。
            if (!keyNode) return true;

            // 最后一个 token，删除 key 和对应的 string 值节点。
            if (isLast) {
                if (!StringEqualIgnoreCase(valueNode.name(), PLIST_TAG_STRING)) {
                    Logger::warn("value node is not string type");
                    return false;
                }

                currentNode.remove_child(keyNode);
                currentNode.remove_child(valueNode);

                std::ostringstream out{};
                plist.print(out);
                plistXml = out.str();
                return true;
            }

            currentNode = valueNode;
        }
    }

    return false;
}

}
