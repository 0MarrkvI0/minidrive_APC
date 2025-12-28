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
#include <openssl/evp.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>


#include "meta.hpp"


inline std::string sha256_file(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("Cannot open file for hashing");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("EVP_DigestUpdate failed");
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < hash_len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(hash[i]);

    return oss.str();
}

struct Request 
{
    std::string cmd;       // napr. "LIST", "UPLOAD", ...
    nlohmann::json args;   // ďalšie polia (path, size, ... )

    void clear() 
    {
        cmd.clear();
        args.clear();
    }
};

struct Response 
{
    std::string status;    // "OK" alebo "ERROR"
    int code;              // error code (0 = success)
    std::string message;   // human readable message
    nlohmann::json data;   // voliteľné dáta (zoznam súborov, atď.)

    void clear() 
    {
        status.clear();
        code = 0;
        message.clear();
        data.clear();
    }
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
    if (j.contains("args") && !j.at("args").is_null())
        r.args = j.at("args");
    else
        r.args = nlohmann::json::object();
}

inline void to_json(nlohmann::json& j, const Response& r) 
{
    j = nlohmann::json{
        {"status",  r.status},
        {"code",    r.code},
        {"message", r.message},
        {"data",    r.data}
    };
}

inline void from_json(const nlohmann::json& j, Response& r) 
{
    j.at("status").get_to(r.status);
    j.at("code").get_to(r.code);
    j.at("message").get_to(r.message);
    if (j.contains("data") && !j.at("data").is_null())
        r.data = j.at("data");
    else
        r.data = nlohmann::json::object();
}

inline void read_line_trim(std::string& out) 
{
    std::getline(std::cin, out);
    if (!out.empty() && out.back() == '\r')
        out.pop_back();
}

constexpr std::size_t CHUNK = 64 * 1024;

inline void send_message
(
    asio::ip::tcp::socket& s,
    // message alebo filepath
    const std::string& message,
    std::uint64_t total_size,
    std::uint64_t offset,
    bool is_file
)
{
    if (offset > total_size)
    {
        throw std::runtime_error("Offset is larger than total size");
    }

    std::uint64_t remaining = total_size - offset;

    if (is_file)
    {
        std::filesystem::path path = message;
        std::ifstream f(path, std::ios::binary);
        if (!f)
        {
            throw std::runtime_error("Cannot open file: " + path.string());
        }
     
        f.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!f)
        {
            throw std::runtime_error("seekg failed: " + path.string());
        }    
        std::array<char, CHUNK> buf;

        while (remaining > 0)
        {
            const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, buf.size()));

            f.read(buf.data(), static_cast<std::streamsize>(want));
            const std::size_t have = static_cast<std::size_t>(f.gcount());

            // keď remaining > 0 a have == 0, tak je to problém (EOF alebo error)
            if (have == 0)
            {
                throw std::runtime_error("File read failed/EOF before expected: " + path.string());
            }
            asio::write(s, asio::buffer(buf.data(), have));
            remaining -= have;
        }
    }
    else
    {
        std::uint64_t pos = offset;

        while (remaining > 0)
        {
            const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, CHUNK));

            asio::write(s, asio::buffer(message.data() + pos, want));
            pos += want;
            remaining -= want;
        }
    }
}



inline std::filesystem::path get_meta_file_path(
    const FileTransferMeta& meta,
    const std::string& meta_path
)
{
    return std::filesystem::path(meta_path) / (meta.file_hash + ".meta");
}

inline bool write_meta_file(const FileTransferMeta& meta, const std::string& meta_path)
{
    std::error_code ec;
    std::filesystem::create_directories(meta_path, ec);
    if (ec) return false;

    auto p = get_meta_file_path(meta, meta_path);

    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) return false;

    nlohmann::json j = meta;
    out << j.dump(2);
    return (bool)out;
}

inline void remove_meta_file(const FileTransferMeta& meta, const std::string& meta_path)
{
    std::error_code ec;
    std::filesystem::remove(get_meta_file_path(meta, meta_path), ec);
}

inline bool ends_with(std::string_view s, std::string_view suf)
{
    return s.size() >= suf.size() && s.substr(s.size() - suf.size()) == suf;
}


inline std::optional<std::string> receive_message
(
    asio::ip::tcp::socket& s,
    FileTransferMeta& meta,
    std::string meta_path,
    const bool is_public,
    const bool is_file
)
{
    if (is_file)
    {
        // cesta k suboru s ktorou budeme pracovat
        std::filesystem::path p = meta.remote_path;
        std::error_code ec;
        // kontrola existencie suboru, error si zapiseme do ec
        bool exists = false;

        if (std::filesystem::exists(p, ec)) 
        {
            if (!ec && std::filesystem::is_regular_file(p, ec)) 
            {
                exists = true;
            }
        }

        if (ec) 
        {
            throw std::runtime_error(ec.message());
        }

        // klient poslal .part
        if (ends_with(meta.remote_path, ".part"))
        {
            if (!exists)
            {
                // .part neexistuje = nový upload
                meta.offset = 0;
            }
            // inak offset zostava rovnaky
        }
        //klient poslal original file bez .part
        else
        {
            // finálny neexistuje = budeme zapisovať do .part
            // uz by bol inak zachyteny (ak by bol rovnaky)
            meta.remote_path += ".part";
            p = meta.remote_path;  
            meta.offset = 0;
        }
     
        std::filesystem::path out_path(meta.remote_path);
        // otvor / vytvor cieľový súbor
        std::fstream out(out_path, std::ios::in | std::ios::out | std::ios::binary);
        if (!out)
        {
            std::ofstream create(out_path, std::ios::binary | std::ios::app);
            if (!create)
            {
                throw std::runtime_error("Failed to create file.");
            }
            create.close();
            out.clear();
            out.open(out_path, std::ios::in | std::ios::out | std::ios::binary);
        }
        if (!out)
        {
            throw std::runtime_error("Failed to open file.");
        } 


        auto size = std::filesystem::file_size(out_path);
        if (meta.offset > size)
        {
            throw std::runtime_error("Offset larger than file size.");
        }

        // resume seek (nastavenie offsetu pri resume)
        out.seekp(static_cast<std::streamoff>(meta.offset), std::ios::beg);
        if (!out)
        {
            throw std::runtime_error("Failed to seek in file.");
        } 

        std::array<char, CHUNK> buf;
        std::uint64_t remaining = meta.file_size - meta.offset;
        std::uint64_t bytes_since_meta_write = 0;
        // meta file sa bude ukladat do samostatneho transfer priecinka
        std::filesystem::path tr_p(meta_path);
        tr_p /= "transfer";
        meta_path = tr_p.string();


        while (remaining > 0)
        {
            std::size_t want = std::min<std::uint64_t>(remaining, buf.size());

            std::size_t got = asio::read(s, asio::buffer(buf.data(), want), ec);
            if (ec || got == 0) 
            {
                throw std::runtime_error("Socket read failed: " + ec.message());
            }
        
            out.write(buf.data(), (std::streamsize)got);
            if (!out) 
            {
                throw std::runtime_error("File write failed.");
            }

            remaining -= got;

            if (!is_public)
            {
                // update metadat
                meta.offset += got;
                meta.last_update = (std::int64_t)std::time(nullptr);

                bytes_since_meta_write += got;
                if (bytes_since_meta_write >= 256 * 1024 || remaining == 0)
                {
                    // zapis do metafilu aktualne info
                    if (!write_meta_file(meta, meta_path))
                    {
                        throw std::runtime_error("MetaFile write failed.");
                    }
                    bytes_since_meta_write = 0;
                }
            }
        }

        // po dokonceni sa zmaze meta 
        if (!is_public && meta.offset == meta.file_size)
        {
            remove_meta_file(meta, meta_path);
        }
        
        out.flush();
        out.close();   
        //odstrani sa .path ext
        std::filesystem::path final_filepath = p;   
        final_filepath.replace_extension("");             
        std::filesystem::rename(p, final_filepath, ec);
        if (ec) 
        {
            throw std::runtime_error("Rename failed: " + ec.message());
        }

        // skontrolujeme integritu suboru ak je zla zmazeme subor
        const std::string computed_hash = "sha256_" + sha256_file(final_filepath);

        if (computed_hash != meta.file_hash)
        {
            std::error_code ec;
            std::filesystem::remove(final_filepath, ec);

            throw std::runtime_error(
                "Corrupted transfer: hash mismatch (expected " +
                meta.file_hash + ", got " + computed_hash + ")"
            );
        }
        return std::nullopt;
    }
    else
    {
        // správa / LIST output
        std::string result(meta.file_size, '\0');

        std::uint64_t remaining = meta.file_size;
        std::size_t off = 0;

        while (remaining > 0)
        {
            std::size_t want = std::min<std::uint64_t>(remaining, (std::uint64_t)CHUNK);

            std::error_code ec;
            std::size_t got = asio::read(s, asio::buffer(result.data() + off, want), ec);
            if (ec || got == 0)
            {
                throw std::runtime_error(ec.message());
            }

            off += got;
            remaining -= got;
        }

        return result;
    }
}








inline std::optional<std::filesystem::path>find_meta_by_hash
(
    const std::filesystem::path& root,
    const std::string& hash
)
{
    const std::string meta_name = hash + ".meta";

    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(root))
    {
        if (!entry.is_regular_file())
            continue;

        if (entry.path().filename() == meta_name)
            return entry.path();
    }

    return std::nullopt;
}


// inline nlohmann::json get_file_info
// (
//     const std::filesystem::path& filepath,
//     const std::filesystem::path& root // aby som vedel kde hladat meta
// )
// {
//     const std::uint64_t size = std::filesystem::file_size(filepath);
//     const std::string hash = "sha256_" + sha256_file(filepath);
//     std::uint64_t offset = 0;

//     if (auto meta_path = find_meta_by_hash(root, hash))
//     {
//         try
//         {
//             md::FileTransferMeta f = md::load_meta(*meta_path);
//             offset = f.offset;
//         }
//         catch (const std::exception&)
//         {
//             offset = 0;
//         }
//     }

//     if (offset > size)
//         throw std::runtime_error("Offset larger than file size");

//     nlohmann::json j;
//     j["size"] = size;
//     j["hash"] = hash;
//     j["offset"] = offset;

//     return j;
// }
