# Copyright (c) 2026 ivfzhou
# ipasigner is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.30)

# 项目信息。
project(ipasigner LANGUAGES CXX VERSION 1.0.1)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 依赖代码库信息。
set(ARGPARSE_URL https://github.com/p-ranav/argparse/archive/refs/tags/v3.2.zip)
set(ARGPARSE_SHA256 14c1a0e975d6877dfeaf52a1e79e54f70169a847e29c7e13aa7fe68a3d0ecbf1)
set(BZIP2_URL https://github.com/libarchive/bzip2/archive/1ea1ac188ad4b9cb662e3f8314673c63df95a589.zip)
set(BZIP2_SHA256 b803cdb2d044a53bde3b89cbbe811486035c885994e75f2879116ca7be0f613b)
set(LIBZIP_URL https://github.com/nih-at/libzip/archive/refs/tags/v1.11.4.zip)
set(LIBZIP_SHA256 3f78eaac85d98d5ac41cc640834dafba7257eb81989854aeb456ed91a177d7c2)
set(OPENSSL_URL https://github.com/openssl/openssl/archive/refs/tags/openssl-3.6.1.zip)
set(OPENSSL_SHA256 b5fb172237ed3b1b47a9f7f15d3a40f9e9563f59f544b7078780ee27279a3c0f)
set(PUGIXML_URL https://github.com/zeux/pugixml/archive/refs/tags/v1.15.zip)
set(PUGIXML_SHA256 0dd4dc16e38bbc1c889d3a59660072450127bac7d19415f3cf5d5d6b25c58b35)
set(XZ_URL https://github.com/tukaani-project/xz/archive/refs/tags/v5.8.2.zip)
set(XZ_SHA256 f31af924df81d645720eee558a00394d3f8a6c59b97c315a541a6598a9aea3d2)
set(YAML_CPP_URL https://github.com/jbeder/yaml-cpp/archive/refs/tags/yaml-cpp-0.9.0.zip)
set(YAML_CPP_SHA256 1c22709eb1fcde200c87ef4e878ce2c9477cc05eae84ebf1f72ec5b356468fee)
set(ZLIB_URL https://github.com/madler/zlib/archive/refs/tags/v1.3.2.zip)
set(ZLIB_SHA256 31fd9fee98812abcf147d0e103bc4d2f983c35a8d7a807a328a299f3a74e0050)
set(ZSTD_URL https://github.com/facebook/zstd/archive/refs/tags/v1.5.7.zip)
set(ZSTD_SHA256 7897bc5d620580d9b7cd3539c44b59d78f3657d33663fe97a145e07b4ebd69a4)

# 全局变量。
set(SOURCES)
set(HEADERS)
set(DEPENDENCIES)
set(DEFINITIONS)
set(DYNAMIC_LIBRARIES)
set(LIBRARIES)
set(INCLUDES ${CMAKE_SOURCE_DIR})

# 版本信息宏。
list(APPEND DEFINITIONS "-DPROJECT_NAME=\"${PROJECT_NAME}\"")
string(TIMESTAMP DATETIME "%Y%m%d%H%M%S")
list(APPEND DEFINITIONS "-DBUILT_TIME=\"${DATETIME}\"")
unset(DATETIME)
if (NOT DEFINED PROJECT_VERSION)
    list(APPEND DEFINITIONS "-DVERSION=\"unknown\"")
else ()
    list(APPEND DEFINITIONS "-DVERSION=\"${PROJECT_VERSION}\"")
endif ()
execute_process(
        COMMAND git rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
)
if (NOT DEFINED GIT_COMMIT_ID OR GIT_COMMIT_ID STREQUAL "")
    list(APPEND DEFINITIONS "-DGIT_COMMIT_ID=\"unknown\"")
else ()
    list(APPEND DEFINITIONS "-DGIT_COMMIT_ID=\"${GIT_COMMIT_ID}\"")
    unset(GIT_COMMIT_ID)
endif ()

# 依赖安装目录。
set(DEPENDENCIES_DIRECTORY ${CMAKE_SOURCE_DIR}/dependencies/${CMAKE_BUILD_TYPE})
file(TO_CMAKE_PATH "${DEPENDENCIES_DIRECTORY}" DEPENDENCIES_DIRECTORY)
file(MAKE_DIRECTORY ${DEPENDENCIES_DIRECTORY})

# 加载依赖代码库。
if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    include(${CMAKE_SOURCE_DIR}/cmakes/windows.cmake)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include(${CMAKE_SOURCE_DIR}/cmakes/linux.cmake)
else ()
    message(FATAL_ERROR "unsupported operating system ${CMAKE_SYSTEM_NAME}")
endif ()

# 收集源码，设置可执行程序。
file(GLOB SOURCES ${CMAKE_SOURCE_DIR}/*.cpp)
add_executable(${PROJECT_NAME} ${SOURCES})

# 包含头文件。
file(GLOB HEADERS
        ${CMAKE_SOURCE_DIR}/*.hpp
        ${CMAKE_SOURCE_DIR}/*.tpp
)
target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDES})

# 链接依赖库。
list(REVERSE LIBRARIES)
target_link_libraries(${PROJECT_NAME} ${LIBRARIES})

# 设置宏，编译属性。
target_compile_definitions(${PROJECT_NAME} PRIVATE ${DEFINITIONS})
set_target_properties(
        ${PROJECT_NAME}
        PROPERTIES
        BUILD_RPATH "\$ORIGIN"
        INSTALL_RPATH "\$ORIGIN"
)

# 添加目标依赖。
foreach (v ${DEPENDENCIES})
    add_dependencies(${PROJECT_NAME} ${v})
endforeach ()

# 设置安装可执行程序路径。
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

# 设置头文件安装路径。
foreach (v ${HEADERS})
    file(RELATIVE_PATH HEADER_RELATIVE_PATH ${CMAKE_SOURCE_DIR} ${v})
    get_filename_component(HEADER_DIR ${HEADER_RELATIVE_PATH} DIRECTORY)
    if (HEADER_DIR STREQUAL "")
        install(FILES ${v} DESTINATION include)
    else ()
        install(FILES ${v} DESTINATION include/${HEADER_DIR})
    endif ()
endforeach ()
