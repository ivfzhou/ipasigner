# Copyright (c) 2026 ivfzhou
# ipasigner is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

# 设置版本号、头文件名、依赖库名称。
set(OPENSSL_NAME openssl)
set(OPENSSL_HEADER_NAME openssl)
set(OPENSSL_LIBRARY_NAME libssl.a)
set(CRYPTO_LIBRARY_NAME libcrypto.a)
set(OPENSSL_DIRECTORY ${DEPENDENCIES_DIRECTORY}/openssl)
set(OPENSSL_INSTALL_DIRECTORY ${OPENSSL_DIRECTORY}/install)
set(OPENSSL_LIBRARY_DIRECTORY ${OPENSSL_INSTALL_DIRECTORY}/lib)
set(OPENSSL_HEADERS_DIRECTORY ${OPENSSL_INSTALL_DIRECTORY}/include)
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(OPENSSL_LIBRARY_DIRECTORY ${OPENSSL_INSTALL_DIRECTORY}/lib64)
endif ()

find_library(
        OPENSSL_LIBRARY
        NAMES ${OPENSSL_LIBRARY_NAME}
        PATHS ${OPENSSL_LIBRARY_DIRECTORY}
        NO_DEFAULT_PATH
)
find_library(
        CRYPTO_LIBRARY
        NAMES ${CRYPTO_LIBRARY_NAME}
        PATHS ${OPENSSL_LIBRARY_DIRECTORY}
        NO_DEFAULT_PATH
)

# 设置依赖头文件路径。
find_path(
        OPENSSL_INCLUDE_DIRECTORY
        NAMES ${OPENSSL_HEADER_NAME}
        PATHS ${OPENSSL_HEADERS_DIRECTORY}
        NO_DEFAULT_PATH
)

if (OPENSSL_LIBRARY AND OPENSSL_INCLUDE_DIRECTORY AND CRYPTO_LIBRARY)
    message(STATUS "found openssl library ${OPENSSL_LIBRARY}")
    message(STATUS "found crypto library ${CRYPTO_LIBRARY}")
    message(STATUS "found openssl include directory ${OPENSSL_INCLUDE_DIRECTORY}")
else ()
    include(ExternalProject)
    set(OPENSSL_BUILD_DIRECTORY ${OPENSSL_DIRECTORY}/build)
    set(OPENSSL_SOURCE_DIRECTORY ${OPENSSL_DIRECTORY}/source)
    get_filename_component(ZLIB_LIBRARY_DIRECTORY ${ZLIB_LIBRARY} DIRECTORY)
    get_filename_component(ZSTD_LIBRARY_DIRECTORY ${ZSTD_LIBRARY} DIRECTORY)
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(OPENSSL_BUILD_TYPE --debug)
    endif ()
    ExternalProject_Add(
            ${OPENSSL_NAME}
            PREFIX ${OPENSSL_DIRECTORY}
            URL ${OPENSSL_URL}
            URL_HASH SHA256=${OPENSSL_SHA256}
            SOURCE_DIR ${OPENSSL_SOURCE_DIRECTORY}
            BINARY_DIR ${OPENSSL_BUILD_DIRECTORY}
            CONFIGURE_COMMAND perl ${OPENSSL_SOURCE_DIRECTORY}/Configure
                --prefix=${OPENSSL_INSTALL_DIRECTORY}
                --openssldir=${OPENSSL_INSTALL_DIRECTORY}
                --with-zlib-include=${ZLIB_INCLUDE_DIRECTORY}
                --with-zlib-lib=${ZLIB_LIBRARY_DIRECTORY}
                --with-zstd-include=${ZSTD_INCLUDE_DIRECTORY}
                --with-zstd-lib=${ZSTD_LIBRARY_DIRECTORY}
                ${OPENSSL_BUILD_TYPE}
                no-docs
                no-shared
                enable-legacy
                no-module
                no-tests
                zlib
                enable-zstd
            BUILD_COMMAND make
            INSTALL_COMMAND make install
    )
    set(OPENSSL_LIBRARY ${OPENSSL_LIBRARY_DIRECTORY}/${OPENSSL_LIBRARY_NAME})
    set(CRYPTO_LIBRARY ${OPENSSL_LIBRARY_DIRECTORY}/${CRYPTO_LIBRARY_NAME})
    set(OPENSSL_INCLUDE_DIRECTORY ${OPENSSL_HEADERS_DIRECTORY})
    list(APPEND DEPENDENCIES ${OPENSSL_NAME})
    if (TARGET ${ZSTD_NAME})
        add_dependencies(${OPENSSL_NAME} ${ZSTD_NAME})
    endif ()
    if (TARGET ${ZLIB_NAME})
        add_dependencies(${OPENSSL_NAME} ${ZLIB_NAME})
    endif ()
    unset(OPENSSL_BUILD_DIRECTORY)
    unset(OPENSSL_SOURCE_DIRECTORY)
endif ()

list(APPEND INCLUDES ${OPENSSL_INCLUDE_DIRECTORY})
list(APPEND LIBRARIES ${CRYPTO_LIBRARY} ${OPENSSL_LIBRARY})

unset(OPENSSL_HEADER_NAME)
unset(OPENSSL_LIBRARY_NAME)
unset(CRYPTO_LIBRARY_NAME)
unset(OPENSSL_DIRECTORY)
unset(OPENSSL_INSTALL_DIRECTORY)
unset(OPENSSL_LIBRARY_DIRECTORY)
unset(OPENSSL_HEADERS_DIRECTORY)
