# 修补 libzip 的 src/CMakeLists.txt，以确保所有工具正确链接 zlib 并正确设置头文件包含路径。
# 背景：libzip 的 zip 库以 PRIVATE 方式链接 ZLIB::ZLIB（见 lib/CMakeLists.txt），
#      zlib 依赖不会传递给链接 zip 库的工具；且本项目使用自定义构建的静态 zlib，
#      需要显式指定库路径与头文件路径。

message(STATUS "applying libzip zlib patch...")

# 读取 libzip 的 cmake 脚本。
file(READ "${LIBZIP_SOURCE_DIR}/src/CMakeLists.txt" ORIGINAL_CONTENT)
set(CONTENT "${ORIGINAL_CONTENT}")

# 1. 将 zipcmp 链接的 ZLIB::ZLIB 替换为 ${ZLIB_LIBRARY}（绝对路径静态库）。
set(CONTENT_BEFORE "${CONTENT}")
string(REGEX REPLACE
        "target_link_libraries\\(zipcmp \\$\\{FTS_LIB\\} ZLIB::ZLIB\\)"
        "target_link_libraries(zipcmp \${FTS_LIB} \${ZLIB_LIBRARY})"
        CONTENT
        "${CONTENT}"
)
if (CONTENT STREQUAL CONTENT_BEFORE)
    message(FATAL_ERROR "libzip patch failed: zipcmp ZLIB::ZLIB link not found in src/CMakeLists.txt")
endif ()

# 2. 确保 ziptool、zipmerge 链接 zlib（它们在 foreach 循环里只链接了 zip 库，而 zip 库以 PRIVATE 链接 zlib）。
foreach (TOOL ziptool zipmerge)
    if (NOT CONTENT MATCHES "target_link_libraries\\(${TOOL}[^)]*ZLIB")
        string(APPEND CONTENT "\ntarget_link_libraries(${TOOL} \${ZLIB_LIBRARY})")
    endif ()
endforeach ()

# 3. 为所有工具（zipcmp、zipmerge、ziptool）添加 zlib 的头文件包含目录。
foreach (TOOL zipcmp zipmerge ziptool)
    if (NOT CONTENT MATCHES "target_include_directories\\(${TOOL}[^)]*ZLIB_INCLUDE_DIR")
        string(APPEND CONTENT "\ntarget_include_directories(${TOOL} PRIVATE \${ZLIB_INCLUDE_DIR})")
    endif ()
endforeach ()

file(WRITE "${LIBZIP_SOURCE_DIR}/src/CMakeLists.txt" "${CONTENT}")

# 修复 HAVE_UNISTD_H 重复定义的警告：
# zlib 的 zconf.h 定义了 "#define HAVE_UNISTD_H 1"（带值），
# 而 libzip 的 config.h.in 使用 "#cmakedefine HAVE_UNISTD_H"，会生成 "#define HAVE_UNISTD_H"（不带值）。
# 这种不一致会导致 -Wmacro-redefined 警告。将其改为 "#cmakedefine HAVE_UNISTD_H 1"，使两处定义保持一致。
file(READ "${LIBZIP_SOURCE_DIR}/config.h.in" CONFIG_H_CONTENT)
string(REPLACE "#cmakedefine HAVE_UNISTD_H" "#cmakedefine HAVE_UNISTD_H 1" CONFIG_H_CONTENT "${CONFIG_H_CONTENT}")
file(WRITE "${LIBZIP_SOURCE_DIR}/config.h.in" "${CONFIG_H_CONTENT}")

message(STATUS "libzip zlib patch applied successfully")
