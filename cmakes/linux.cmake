# Copyright (c) 2026 ivfzhou
# ipasigner is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set(COMPILER_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
set(COMPILER_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
set(COMPILER_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
set(COMPILER_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -finput-charset=UTF-8 -fexec-charset=UTF-8 -std=c++20")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -g0")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} --all-warnings -pedantic -Winline -O0 -Wall -g3 -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-function -D_GLIBCXX_DEBUG")

include(cmakes/linux/argparse.cmake)
include(cmakes/linux/bzip2.cmake)
include(cmakes/linux/pugixml.cmake)
include(cmakes/linux/xz.cmake)
include(cmakes/linux/yaml-cpp.cmake)
include(cmakes/linux/zlib.cmake)
include(cmakes/linux/zstd.cmake)
include(cmakes/linux/openssl.cmake)
include(cmakes/linux/libzip.cmake)

add_definitions(-DLINUX)
