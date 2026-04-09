# Patch libzip src/CMakeLists.txt to ensure proper zlib linking and include paths for all tools

file(READ "${LIBZIP_SOURCE_DIR}/src/CMakeLists.txt" ORIGINAL_CONTENT)
set(CONTENT "${ORIGINAL_CONTENT}")

message(STATUS "Applying libzip zlib patch...")

# Ensure ziptool links zlib
if (NOT CONTENT MATCHES "target_link_libraries\\(ziptool.*ZLIB")
    string(REGEX REPLACE
            "(endforeach\\(\\)[^#]*# End foreach Tools)"
            "endforeach()  # End foreach Tools\n\n# Ensure ziptool links zlib after zlib patch\ntarget_link_libraries(ziptool PUBLIC \${ZLIB_LIBRARY})"
            CONTENT
            "${CONTENT}"
    )
endif ()

# Ensure zipmerge links zlib  
if (NOT CONTENT MATCHES "target_link_libraries\\(zipmerge.*ZLIB")
    string(REGEX REPLACE
            "(target_link_libraries\\(ziptool PUBLIC.*ZLIB_LIBRARY\\))"
            "\\1\ntarget_link_libraries(zipmerge PUBLIC \${ZLIB_LIBRARY})"
            CONTENT
            "${CONTENT}"
    )
endif ()

# Move ZLIB::ZLIB to the end of zipcmp's link libraries to ensure proper linking order
string(REGEX REPLACE
        "target_link_libraries\\(zipcmp \\$\\{FTS_LIB\\} ZLIB::ZLIB\\)"
        "target_link_libraries(zipcmp \${FTS_LIB})\ntarget_link_libraries(zipcmp \${ZLIB_LIBRARY})"
        CONTENT
        "${CONTENT}"
)

# Add zlib include directories for all tools (zipcmp, zipmerge, ziptool)
# This is needed because replacing ZLIB::ZLIB with ${ZLIB_LIBRARY} loses the include path propagation
foreach(TOOL zipcmp zipmerge ziptool)
    if (NOT CONTENT MATCHES "target_include_directories\\(${TOOL}.*ZLIB_INCLUDE_DIRS")
        string(APPEND CONTENT "\ntarget_include_directories(${TOOL} PRIVATE \${ZLIB_INCLUDE_DIRS})")
    endif ()
endforeach()

file(WRITE "${LIBZIP_SOURCE_DIR}/src/CMakeLists.txt" "${CONTENT}")

# Fix HAVE_UNISTD_H redefined warning:
# zlib's zconf.h defines "#define HAVE_UNISTD_H 1" (with value),
# but libzip's config.h.in uses "#cmakedefine HAVE_UNISTD_H" which generates "#define HAVE_UNISTD_H" (without value).
# The mismatch causes a -Wmacro-redefined warning. Change it to "#cmakedefine HAVE_UNISTD_H 1" so both definitions are consistent.
file(READ "${LIBZIP_SOURCE_DIR}/config.h.in" CONFIG_H_CONTENT)
string(REPLACE "#cmakedefine HAVE_UNISTD_H" "#cmakedefine HAVE_UNISTD_H 1" CONFIG_H_CONTENT "${CONFIG_H_CONTENT}")
file(WRITE "${LIBZIP_SOURCE_DIR}/config.h.in" "${CONFIG_H_CONTENT}")

message(STATUS "Libzip zlib patch applied successfully")
