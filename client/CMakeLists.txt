add_executable(client
    src/main.cpp
)

target_link_libraries(client
    PRIVATE
        asio::asio
        nlohmann_json::nlohmann_json
        minidrive_common
        spdlog::spdlog_header_only
)
