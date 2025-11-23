add_executable(server
    src/main.cpp
)

target_link_libraries(server
    PRIVATE
        asio::asio
        nlohmann_json::nlohmann_json
        libsodium::libsodium
        minidrive_common
        
)
