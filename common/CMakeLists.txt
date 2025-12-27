add_library(minidrive_common INTERFACE)

target_include_directories(minidrive_common INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(minidrive_common INTERFACE
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
)
