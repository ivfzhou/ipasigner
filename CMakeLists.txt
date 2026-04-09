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

set(VERSION "1.0.1")
project(ipasigner LANGUAGES CXX VERSION ${VERSION})

execute_process(
        COMMAND git rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

string(TIMESTAMP BUILT_TIME "%Y/%m/%d %H:%M:%S")
add_definitions(-DVERSION="${VERSION}" -DBUILT_TIME="${BUILT_TIME}" -DGIT_COMMIT_ID="${GIT_COMMIT_ID}" -DPROJECT_NAME="${PROJECT_NAME}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT DEFINED CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
elseif ((NOT CMAKE_BUILD_TYPE STREQUAL "Debug") AND (NOT CMAKE_BUILD_TYPE STREQUAL "Release"))
    set(CMAKE_BUILD_TYPE "Release")
endif ()

set(DEPENDENCIES_DIRECTORY ${CMAKE_SOURCE_DIR}/dependencies/${CMAKE_BUILD_TYPE})
file(MAKE_DIRECTORY ${DEPENDENCIES_DIRECTORY})

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    include(cmakes/windows.cmake)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include(cmakes/linux.cmake)
else ()
    message(FATAL_ERROR "unsupported operating system ${CMAKE_SYSTEM_NAME}")
endif ()

file(GLOB SOURCES ${CMAKE_SOURCE_DIR}/*.cpp)
list(FILTER SOURCES EXCLUDE REGEX "test_.*\\.cpp$")
include_directories(${CMAKE_SOURCE_DIR})
add_executable(${PROJECT_NAME} ${SOURCES})
list(REVERSE LIBRARIES)
target_link_libraries(${PROJECT_NAME} ${LIBRARIES})

foreach (v ${DEPENDENCIES})
    add_dependencies(${PROJECT_NAME} ${v})
endforeach ()

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

# 测试目标：Binary Plist 解析验证。
file(GLOB TEST_SOURCES ${CMAKE_SOURCE_DIR}/*.cpp)
list(FILTER TEST_SOURCES EXCLUDE REGEX "main\\.cpp$")
add_executable(test_plist ${TEST_SOURCES})
target_link_libraries(test_plist ${LIBRARIES})
foreach (v ${DEPENDENCIES})
    add_dependencies(test_plist ${v})
endforeach ()
