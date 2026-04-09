# Copyright (c) 2026 ivfzhou
# ipasigner is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set(ZLIB_VERSION v1.3.2)
set(ZLIB_NAME zlib)
set(ZLIB_HEADER_NAME zlib.h)
set(ZLIB_LIBRARY_NAME zs.lib)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(ZLIB_LIBRARY_NAME zsd.lib)
endif ()
set(ZLIB_DIRECTORY ${DEPENDENCIES_DIRECTORY}/zlib)
set(ZLIB_INSTALL_DIRECTORY ${ZLIB_DIRECTORY}/install)
set(ZLIB_HEADERS_DIRECTORY ${ZLIB_INSTALL_DIRECTORY}/include)
set(ZLIB_LIBRARY_DIRECTORY ${ZLIB_INSTALL_DIRECTORY}/lib)

find_path(
        ZLIB_INCLUDE_DIRECTORY
        NAMES ${ZLIB_HEADER_NAME}
        PATHS ${ZLIB_HEADERS_DIRECTORY}
        NO_DEFAULT_PATH
)

find_library(
        ZLIB_LIBRARY
        NAMES ${ZLIB_LIBRARY_NAME}
        PATHS ${ZLIB_LIBRARY_DIRECTORY}
        NO_DEFAULT_PATH
)

if (ZLIB_INCLUDE_DIRECTORY AND ZLIB_LIBRARY)
    message(STATUS "found zlib include directory: ${ZLIB_INCLUDE_DIRECTORY}")
    message(STATUS "found zlib library: ${ZLIB_LIBRARY}")
else ()
    include(ExternalProject)
    set(ZLIB_BUILD_DIRECTORY ${ZLIB_DIRECTORY}/build)
    set(ZLIB_SOURCE_DIRECTORY ${ZLIB_DIRECTORY}/source)
    ExternalProject_Add(
            ${ZLIB_NAME}
            PREFIX ${ZLIB_DIRECTORY}
            URL https://github.com/madler/zlib/archive/refs/tags/${ZLIB_VERSION}.zip
            SOURCE_DIR ${ZLIB_SOURCE_DIRECTORY}
            BINARY_DIR ${ZLIB_BUILD_DIRECTORY}
            CONFIGURE_COMMAND ${CMAKE_COMMAND} --fresh -S ${ZLIB_SOURCE_DIRECTORY} -B ${ZLIB_BUILD_DIRECTORY}
            -DCMAKE_INSTALL_PREFIX=${ZLIB_INSTALL_DIRECTORY}
            -DCMAKE_CONFIGURATION_TYPES=${CMAKE_BUILD_TYPE}
            -DCMAKE_MSVC_RUNTIME_LIBRARY=${CMAKE_MSVC_RUNTIME_LIBRARY}
            -DCMAKE_C_FLAGS_RELEASE=${COMPILER_C_FLAGS_RELEASE}
            -DCMAKE_C_FLAGS_DEBUG=${COMPILER_C_FLAGS_DEBUG}
            -DZLIB_BUILD_TESTING=OFF
            -DZLIB_BUILD_SHARED=OFF
            -DZLIB_BUILD_MINIZIP=OFF
            BUILD_COMMAND ${CMAKE_COMMAND} --build ${ZLIB_BUILD_DIRECTORY} --config ${CMAKE_BUILD_TYPE} --parallel --clean-first
            INSTALL_COMMAND ${CMAKE_COMMAND} --build ${ZLIB_BUILD_DIRECTORY} --config ${CMAKE_BUILD_TYPE} --target install
    )
    set(ZLIB_INCLUDE_DIRECTORY ${ZLIB_HEADERS_DIRECTORY})
    set(ZLIB_LIBRARY ${ZLIB_LIBRARY_DIRECTORY}/${ZLIB_LIBRARY_NAME})
    list(APPEND DEPENDENCIES ${ZLIB_NAME})
endif ()

include_directories(${ZLIB_INCLUDE_DIRECTORY})
list(APPEND LIBRARIES ${ZLIB_LIBRARY})
