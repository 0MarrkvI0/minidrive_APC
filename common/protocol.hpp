#pragma once
#include <iostream>
#include <string>
#include <optional>
#include <nlohmann/json.hpp>
#include <asio.hpp>
#include <filesystem>
#include <fstream>
#include <array>
#include <algorithm>
#include <cstdint>
#include <stdexcept>

struct Request 
{
    std::string cmd;       // napr. "LIST", "UPLOAD", ...
    nlohmann::json args;   // ďalšie polia (path, size, ... )
};

struct Response 
{
    std::string status;    // "OK" alebo "ERROR"
    int code;              // error code (0 = success)
    std::string message;   // human readable message
    nlohmann::json data;   // voliteľné dáta (zoznam súborov, atď.)
};

inline void to_json(nlohmann::json& j, const Request& r) 
{
    j = nlohmann::json
    {
        {"cmd",  r.cmd},
        {"args", r.args}
    };
}

inline void from_json(const nlohmann::json& j, Request& r) 
{
    j.at("cmd").get_to(r.cmd);
    if (j.contains("args"))
        r.args = j.at("args");
    else
        r.args = nlohmann::json::object();
}

inline void to_json(nlohmann::json& j, const Response& r) {
    j = nlohmann::json{
        {"status",  r.status},
        {"code",    r.code},
        {"message", r.message},
        {"data",    r.data}
    };
}

inline void from_json(const nlohmann::json& j, Response& r) {
    j.at("status").get_to(r.status);
    j.at("code").get_to(r.code);
    j.at("message").get_to(r.message);
    if (j.contains("data"))
        r.data = j.at("data");
    else
        r.data = nlohmann::json::object();
}

inline void read_line_trim(std::string& out) {
    std::getline(std::cin, out);
    if (!out.empty() && out.back() == '\r')
        out.pop_back();
}

constexpr std::size_t CHUNK = 64 * 1024;

inline void send_message(asio::ip::tcp::socket& s, const std::string& message,std::uint64_t& size, bool is_file)
{
    if (is_file) 
    {
        std::filesystem::path path = message;
        std::ifstream f(path, std::ios::binary);
        if (!f) throw std::runtime_error("Cannot open file: " + path.string());

        std::array<char, CHUNK> buf;
        std::uint64_t remaining = size;

        while (remaining > 0) 
        {
            std::size_t want = (std::size_t)std::min<std::uint64_t>(remaining, buf.size());
            f.read(buf.data(), (std::streamsize)want);
            std::size_t have = (std::size_t)f.gcount();
            if (have == 0) throw std::runtime_error("File read failed: " + path.string());
            asio::write(s, asio::buffer(buf.data(), have));
            remaining -= have;
        }
    } 
    else 
    {
        std::uint64_t remaining = size;
        std::size_t offset = 0;

        while (remaining > 0) 
        {
            std::size_t want = (std::size_t)std::min<std::uint64_t>(remaining, (std::uint64_t)CHUNK);
            asio::write(s, asio::buffer(message.data() + offset, want));
            offset += want;
            remaining -= want;
        }
    }
}

inline std::optional<std::string> receive_message(asio::ip::tcp::socket& s,const std::filesystem::path& out_path,std::uint64_t size,bool is_file)
{
    if (is_file) 
    {
        std::ofstream out(out_path, std::ios::binary);
        if (!out)
            throw std::runtime_error("Cannot open output file: " + out_path.string());

        std::array<char, CHUNK> buf;
        std::uint64_t remaining = size;

        while (remaining > 0) 
        {
            std::size_t want = (std::size_t)std::min<std::uint64_t>(remaining, buf.size());
            asio::read(s, asio::buffer(buf.data(), want));
            out.write(buf.data(), (std::streamsize)want);
            if (!out)
                throw std::runtime_error("Write failed: " + out_path.string());
            remaining -= want;
        }

        return std::nullopt;
    } 
    else 
    {
        std::string result;
        result.resize((std::size_t)size);

        std::uint64_t remaining = size;
        std::size_t offset = 0;

        while (remaining > 0) 
        {
            std::size_t want = (std::size_t)std::min<std::uint64_t>(remaining, (std::uint64_t)CHUNK);
            asio::read(s, asio::buffer(result.data() + offset, want));
            offset += want;
            remaining -= want;
        }

        return result;
    }
}
