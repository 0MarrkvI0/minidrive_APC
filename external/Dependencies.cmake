include(FetchContent)




# ASIO (header-only)
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-36-0
)

FetchContent_MakeAvailable(asio)

# Create interface target for ASIO
add_library(asio INTERFACE)
target_include_directories(asio INTERFACE 
    ${asio_SOURCE_DIR}/asio/include
)
target_compile_definitions(asio INTERFACE ASIO_STANDALONE)
add_library(asio::asio ALIAS asio)


# nlohmann::json (header-only)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.12.0
)
set(JSON_SystemInclude ON CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)


set(SODIUM_DISABLE_TESTS ON)
# libsodium
FetchContent_Declare(
    libsodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG 260622e5b69bce9b955603a98e46354125a932a4 # libsodium version 1.0.20-RELEASE
)
FetchContent_MakeAvailable(libsodium)
if(NOT TARGET libsodium::libsodium)
    add_library(libsodium::libsodium ALIAS sodium)
    # Mark sodium includes as system to suppress warnings
    get_target_property(sodium_include_dirs sodium INTERFACE_INCLUDE_DIRECTORIES)
    if(sodium_include_dirs)
        set_target_properties(sodium PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${sodium_include_dirs}")
    endif()
endif()

# spdlog 
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.14.1
)

set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_BENCH OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(spdlog)
