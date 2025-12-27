cmake_minimum_required(VERSION 3.25)
project(APC_Project_MINIDRIVE LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Use C++23 standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Make GCC very pedantic and disable extensions
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wlogical-op
        -Wmissing-include-dirs
        -Wredundant-decls
        -Wstrict-overflow
        -Wundef
        -Wnull-dereference
        -Walloca
        -Werror=vla
)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/external")
include(Dependencies)


# Subprojects
add_subdirectory(common)
add_subdirectory(server)
add_subdirectory(client)