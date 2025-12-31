#pragma once
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <cstdint>
#include <string>
#include <nlohmann/json.hpp>


using json = nlohmann::json;


struct FileTransferMeta
{
    std::string cmd;           // "upload" / "download"
    std::string remote_path;
    std::string local_path;
    std::uint64_t file_size = 0;
    std::string file_hash;
    std::uint64_t offset = 0;
    std::int64_t last_update = 0;
};

inline void apply_filename_to_remote_path(FileTransferMeta& meta)
{
    std::filesystem::path local(meta.local_path);

    // zober len názov súboru (napr. file.txt)
    std::string filename = local.filename().string();

    // pripoj k remote_path
    std::filesystem::path remote(meta.remote_path);
    remote /= filename;

    meta.remote_path = remote.string();
}


inline void to_json(json& j, const FileTransferMeta& m)
{
    j = json{
        {"type", m.cmd},
        {"remote_path", m.remote_path},
        {"local_path", m.local_path},
        {"file_size", m.file_size},
        {"file_hash", m.file_hash},
        {"offset", m.offset},
        {"last_update", m.last_update}
    };
}

inline void from_json(const json& j, FileTransferMeta& m)
{
    m.cmd = j.at("type").get<std::string>();
    m.remote_path = j.at("remote_path").get<std::string>();
    m.local_path = j.value("local_path", "");
    m.file_size = j.at("file_size").get<std::uint64_t>();
    m.file_hash = j.at("file_hash").get<std::string>();
    m.offset = j.at("offset").get<std::uint64_t>();
    m.last_update = j.at("last_update").get<std::int64_t>();
}

inline void save_meta_atomic(const std::filesystem::path& meta_path, const FileTransferMeta& m)
{
    const auto tmp = meta_path.string() + ".meta";

    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        throw std::runtime_error("Cannot write meta tmp: " + tmp);
    }

    json j = m;
    out << j.dump(2);
    out.flush();
    if (!out) throw std::runtime_error("Failed writing meta tmp: " + tmp);
    out.close();

    std::error_code ec;
    std::filesystem::rename(tmp, meta_path, ec);
    if (ec) {
        std::filesystem::remove(meta_path, ec);
        ec.clear();
        std::filesystem::rename(tmp, meta_path, ec);
        if (ec) throw std::runtime_error("Cannot rename meta tmp -> meta: " + ec.message());
    }
}

inline FileTransferMeta load_meta(const std::filesystem::path& meta_path)
{
    std::ifstream in(meta_path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open meta: " + meta_path.string());

    json j;
    in >> j;
    return j.get<FileTransferMeta>();
}

inline void update_meta_offset(const std::filesystem::path& meta_path,
                              std::uint64_t new_offset,
                              std::int64_t now_ts)
{
    FileTransferMeta m = load_meta(meta_path);
    m.offset = new_offset;
    m.last_update = now_ts;
    save_meta_atomic(meta_path, m);
}

inline nlohmann::json load_transfer_meta(const std::string& transfer_dir)
{
    nlohmann::json result = nlohmann::json::array();

    std::error_code ec;
    if (!std::filesystem::exists(transfer_dir, ec) || !std::filesystem::is_directory(transfer_dir, ec))
    {
        return result; // prázdne pole
    }

    for (const auto& entry : std::filesystem::directory_iterator(transfer_dir, ec))
    {
        if (ec) break;

        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".meta") continue;

        try
        {
            std::ifstream in(entry.path());
            if (!in) continue;

            nlohmann::json j;
            in >> j;

            FileTransferMeta meta = j.get<FileTransferMeta>();
            if (!std::filesystem::exists(meta.remote_path))
            {
                // súbor už neexistuje, zacneme od zaciatku
                meta.offset = 0;
            }
            result.push_back(meta); // použije to_json
        }
        catch (...)
        {
            // poškodený / nečitateľný meta súbor
            continue;
        }
    }

    return result;
}
