# Copyright (c) 2026 ivfzhou
# ipasigner is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# 设置依赖库编译参数。
set(LIBRARY_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
set(LIBRARY_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
set(LIBRARY_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
set(LIBRARY_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")

# 设置编译参数。
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /utf-8 /MTd")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /utf-8 /MT")

# 设置运行库。
set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDebug)
endif ()

# 包含依赖脚本。
include(${CMAKE_SOURCE_DIR}/cmakes/windows/argparse.cmake)
include(${CMAKE_SOURCE_DIR}/cmakes/windows/bzip2.cmake)
include(${CMAKE_SOURCE_DIR}/cmakes/windows/pugixml.cmake)
include(${CMAKE_SOURCE_DIR}/cmakes/windows/xz.cmake)
include(${CMAKE_SOURCE_DIR}/cmakes/windows/yaml-cpp.cmake)
include(${CMAKE_SOURCE_DIR}/cmakes/windows/zlib.cmake)
include(${CMAKE_SOURCE_DIR}/cmakes/windows/zstd.cmake)
include(${CMAKE_SOURCE_DIR}/cmakes/windows/openssl.cmake)
include(${CMAKE_SOURCE_DIR}/cmakes/windows/libzip.cmake)

list(APPEND DEFINITIONS "-DWINDOWS")

unset(COMPILER_CXX_FLAGS_RELEASE)
unset(COMPILER_CXX_FLAGS_DEBUG)
unset(COMPILER_C_FLAGS_RELEASE)
unset(COMPILER_C_FLAGS_DEBUG)
