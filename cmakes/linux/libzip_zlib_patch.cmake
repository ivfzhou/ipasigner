# Patch libzip src/CMakeLists.txt to ensure proper zlib linking for all tools

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

file(WRITE "${LIBZIP_SOURCE_DIR}/src/CMakeLists.txt" "${CONTENT}")
message(STATUS "Libzip zlib patch applied successfully")

