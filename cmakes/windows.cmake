# Copyright (c) 2026 ivfzhou
# ipasigner is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set(COMPILER_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
set(COMPILER_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
set(COMPILER_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
set(COMPILER_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /utf-8 /MTd")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /utf-8 /MT")

set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDebug)
endif ()

include(cmakes/windows/argparse.cmake)
include(cmakes/windows/bzip2.cmake)
include(cmakes/windows/pugixml.cmake)
include(cmakes/windows/xz.cmake)
include(cmakes/windows/yaml-cpp.cmake)
include(cmakes/windows/zlib.cmake)
include(cmakes/windows/zstd.cmake)
include(cmakes/windows/openssl.cmake)
include(cmakes/windows/libzip.cmake)

add_definitions(-DWINDOWS)
