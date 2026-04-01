# Copyright (c) 2026 ivfzhou
# ipasigner is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set(BZIP2_VERSION 1ea1ac188ad4b9cb662e3f8314673c63df95a589)
set(BZIP2_HEADER_NAME bzlib.h)
set(BZIP2_LIBRARY_NAME libbz2_static.a)
set(BZIP2_DIRECTORY ${DEPENDENCIES_DIRECTORY}/bzip2)
set(BZIP2_INSTALL_DIRECTORY ${BZIP2_DIRECTORY}/install)
set(BZIP2_LIBRARY_DIRECTORY ${BZIP2_INSTALL_DIRECTORY}/lib)
set(BZIP2_HEADERS_DIRECTORY ${BZIP2_INSTALL_DIRECTORY}/include)

find_library(
        BZIP2_LIBRARY
        NAMES ${BZIP2_LIBRARY_NAME}
        PATHS ${BZIP2_LIBRARY_DIRECTORY}
        NO_DEFAULT_PATH
)

find_path(
        BZIP2_INCLUDE_DIRECTORY
        NAMES ${BZIP2_HEADER_NAME}
        PATHS ${BZIP2_HEADERS_DIRECTORY}
        NO_DEFAULT_PATH
)

if (BZIP2_LIBRARY AND BZIP2_INCLUDE_DIRECTORY)
    message(STATUS "found bzip2 library ${BZIP2_LIBRARY}")
    message(STATUS "found bzip2 include directory ${BZIP2_INCLUDE_DIRECTORY}")
else ()
    include(ExternalProject)
    set(BZIP2_BUILD_DIRECTORY ${BZIP2_DIRECTORY}/build)
    set(BZIP2_SOURCE_DIRECTORY ${BZIP2_DIRECTORY}/source)
    ExternalProject_Add(
            bzip2
            PREFIX ${BZIP2_DIRECTORY}
            URL https://github.com/libarchive/bzip2/archive/${BZIP2_VERSION}.zip
            SOURCE_DIR ${BZIP2_SOURCE_DIRECTORY}
            BINARY_DIR ${BZIP2_BUILD_DIRECTORY}
            CONFIGURE_COMMAND ${CMAKE_COMMAND} --fresh -S ${BZIP2_SOURCE_DIRECTORY} -B ${BZIP2_BUILD_DIRECTORY}
            -DCMAKE_INSTALL_PREFIX=${BZIP2_INSTALL_DIRECTORY}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DENABLE_EXAMPLES=OFF
            -DENABLE_SHARED_LIB=OFF
            -DENABLE_DOCS=OFF
            -DENABLE_STATIC_LIB=ON
            BUILD_COMMAND ${CMAKE_COMMAND} --build ${BZIP2_BUILD_DIRECTORY} --config ${CMAKE_BUILD_TYPE} --parallel --clean-first
            INSTALL_COMMAND ${CMAKE_COMMAND} --build ${BZIP2_BUILD_DIRECTORY} --config ${CMAKE_BUILD_TYPE} --target install
    )
    set(BZIP2_LIBRARY ${BZIP2_LIBRARY_DIRECTORY}/${BZIP2_LIBRARY_NAME})
    set(BZIP2_INCLUDE_DIRECTORY ${BZIP2_HEADERS_DIRECTORY})
    list(APPEND DEPENDENCIES ${BZIP2_NAME})
endif ()

include_directories(${BZIP2_INCLUDE_DIRECTORY})
list(APPEND LIBRARIES ${BZIP2_LIBRARY})
