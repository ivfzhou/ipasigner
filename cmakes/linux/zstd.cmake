# Copyright (c) 2026 ivfzhou
# ipasigner is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set(ZSTD_VERSION v1.5.7)
set(ZSTD_HEADER_NAME zstd.h)
set(ZSTD_LIBRARY_NAME libzstd.a)
set(ZSTD_DIRECTORY ${DEPENDENCIES_DIRECTORY}/zstd)
set(ZSTD_INSTALL_DIRECTORY ${ZSTD_DIRECTORY}/install)
set(ZSTD_LIBRARY_DIRECTORY ${ZSTD_INSTALL_DIRECTORY}/lib)
set(ZSTD_HEADERS_DIRECTORY ${ZSTD_INSTALL_DIRECTORY}/include)

find_library(
        ZSTD_LIBRARY
        NAMES ${ZSTD_LIBRARY_NAME}
        PATHS ${ZSTD_LIBRARY_DIRECTORY}
        NO_DEFAULT_PATH
)

find_path(
        ZSTD_INCLUDE_DIRECTORY
        NAMES ${ZSTD_HEADER_NAME}
        PATHS ${ZSTD_HEADERS_DIRECTORY}
        NO_DEFAULT_PATH
)

if (ZSTD_LIBRARY AND ZSTD_INCLUDE_DIRECTORY)
    message(STATUS "found zstd library ${ZSTD_LIBRARY}")
    message(STATUS "found zstd include directory ${ZSTD_INCLUDE_DIRECTORY}")
else ()
    include(ExternalProject)
    set(ZSTD_BUILD_DIRECTORY ${ZSTD_DIRECTORY}/build)
    set(ZSTD_SOURCE_DIRECTORY ${ZSTD_DIRECTORY}/source)
    ExternalProject_Add(
            zstd
            PREFIX ${ZSTD_DIRECTORY}
            URL https://github.com/facebook/zstd/archive/refs/tags/${ZSTD_VERSION}.zip
            SOURCE_DIR ${ZSTD_SOURCE_DIRECTORY}
            BINARY_DIR ${ZSTD_BUILD_DIRECTORY}
            CONFIGURE_COMMAND ${CMAKE_COMMAND} --fresh -S ${ZSTD_SOURCE_DIRECTORY}/build/cmake -B ${ZSTD_BUILD_DIRECTORY}
            -DCMAKE_INSTALL_PREFIX=${ZSTD_INSTALL_DIRECTORY}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DZSTD_BUILD_TESTS=OFF
            BUILD_COMMAND ${CMAKE_COMMAND} --build ${ZSTD_BUILD_DIRECTORY} --config ${CMAKE_BUILD_TYPE} --parallel --clean-first
            INSTALL_COMMAND ${CMAKE_COMMAND} --build ${ZSTD_BUILD_DIRECTORY} --config ${CMAKE_BUILD_TYPE} --target install
    )
    set(ZSTD_LIBRARY ${ZSTD_LIBRARY_DIRECTORY}/${ZSTD_LIBRARY_NAME})
    set(ZSTD_INCLUDE_DIRECTORY ${ZSTD_HEADERS_DIRECTORY})
    list(APPEND DEPENDENCIES ${ZSTD_NAME})
endif ()

include_directories(${ZSTD_INCLUDE_DIRECTORY})
list(APPEND LIBRARIES ${ZSTD_LIBRARY})
