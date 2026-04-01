# Copyright (c) 2026 ivfzhou
# ipasigner is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set(XZ_VERSION v5.8.2)
set(XZ_HEADER_NAME lzma.h)
set(XZ_LIBRARY_NAME liblzma.a)
set(XZ_DIRECTORY ${DEPENDENCIES_DIRECTORY}/xz)
set(XZ_INSTALL_DIRECTORY ${XZ_DIRECTORY}/install)
set(XZ_LIBRARY_DIRECTORY ${XZ_INSTALL_DIRECTORY}/lib)
set(XZ_HEADERS_DIRECTORY ${XZ_INSTALL_DIRECTORY}/include)

find_library(
        XZ_LIBRARY
        NAMES ${XZ_LIBRARY_NAME}
        PATHS ${XZ_LIBRARY_DIRECTORY}
        NO_DEFAULT_PATH
)

find_path(
        XZ_INCLUDE_DIRECTORY
        NAMES ${XZ_HEADER_NAME}
        PATHS ${XZ_HEADERS_DIRECTORY}
        NO_DEFAULT_PATH
)

if (XZ_LIBRARY AND XZ_INCLUDE_DIRECTORY)
    message(STATUS "found xz library ${XZ_LIBRARY}")
    message(STATUS "found xz include directory ${XZ_INCLUDE_DIRECTORY}")
else ()
    include(ExternalProject)
    set(XZ_BUILD_DIRECTORY ${XZ_DIRECTORY}/build)
    set(XZ_SOURCE_DIRECTORY ${XZ_DIRECTORY}/source)
    ExternalProject_Add(
            xz
            PREFIX ${XZ_DIRECTORY}
            URL https://github.com/tukaani-project/xz/archive/refs/tags/${XZ_VERSION}.zip
            SOURCE_DIR ${XZ_SOURCE_DIRECTORY}
            BINARY_DIR ${XZ_BUILD_DIRECTORY}
            CONFIGURE_COMMAND ${CMAKE_COMMAND} --fresh -S ${XZ_SOURCE_DIRECTORY} -B ${XZ_BUILD_DIRECTORY}
            -DCMAKE_INSTALL_PREFIX=${XZ_INSTALL_DIRECTORY}
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
            -DXZ_DOC=OFF
            BUILD_COMMAND ${CMAKE_COMMAND} --build ${XZ_BUILD_DIRECTORY} --config ${CMAKE_BUILD_TYPE} --parallel --clean-first
            INSTALL_COMMAND ${CMAKE_COMMAND} --build ${XZ_BUILD_DIRECTORY} --config ${CMAKE_BUILD_TYPE} --target install
    )
    set(XZ_LIBRARY ${XZ_LIBRARY_DIRECTORY}/${XZ_LIBRARY_NAME})
    set(XZ_INCLUDE_DIRECTORY ${XZ_HEADERS_DIRECTORY})
    list(APPEND DEPENDENCIES ${XZ_NAME})
endif ()

include_directories(${XZ_INCLUDE_DIRECTORY})
list(APPEND LIBRARIES ${XZ_LIBRARY})
