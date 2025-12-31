#include "protocol.hpp"
#include "meta.hpp"

#include <asio.hpp>
#include <iostream>
#include <filesystem>
#include <string>
#include <fstream>
#include <sodium.h>

const std::string USER_DB_FILEPATH = "/users.json";

struct config 
{
    int port;
    std::string root_dir;
};

struct profile 
{
    std::string username;
    std::string user_directory;
    std::string working_directory;
};

std::optional<nlohmann::json> find_user(const nlohmann::json& db, const std::string& username) {
    for (const auto& u : db["users"]) {
        if (u["username"] == username) {
            return u;
        }
    }
    return std::nullopt;
}

void save_user_db(const nlohmann::json& user_db, const std::string& root_dir)
{
    std::ofstream out(root_dir + USER_DB_FILEPATH);
    out << user_db.dump(4);
}
    
Request receive_request(asio::ip::tcp::socket& socket)
{
    asio::streambuf buf;
    asio::read_until(socket, buf, '\n');

    std::istream is(&buf);
    std::string line;
    std::getline(is, line);

    nlohmann::json j = nlohmann::json::parse(line);
    Request req = j.get<Request>();
    std::cout << "[server] Recieved request: " << req.cmd << "\n";
    std::cout << "[server] Args: " << req.args.dump() << "\n";
    return req;   
}

bool send_response(asio::ip::tcp::socket& socket, const Response& resp)
{
    try {
        nlohmann::json j = resp;
        std::string serialized = j.dump();

        serialized += '\n';

        asio::write(socket, asio::buffer(serialized));
        std::cout << "[server] Send response: " << resp.status << " " << resp.code << " " << resp.message << "\n";
        std::cout << "[server] Data: " << (resp.data.is_null() ? "none" : resp.data.dump())<< "\n";
        return true;

    } catch (std::exception& e) {
        std::cerr << "[error] Failed to send response: " << e.what() << "\n";
        return false;
    }
}

#include <filesystem>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

static bool is_subpath(const std::filesystem::path& root,const std::filesystem::path& p)
{
    // porovná po komponentoch, root musí byť prefix p
    auto r_it = root.begin();
    auto r_end = root.end();
    auto p_it = p.begin();
    auto p_end = p.end();

    for (; r_it != r_end; ++r_it, ++p_it)
    {
        if (p_it == p_end) return false;
        if (*r_it != *p_it) return false;
    }
    return true;
}

// ak je spravna tak path, inak nullopt
std::optional<std::filesystem::path> check_path
(
    const std::filesystem::path& root_dir,
    const std::filesystem::path& work_dir,
    const std::filesystem::path& input_path,
    const std::string& type, // "dir" | "file" | "new"
    asio::ip::tcp::socket& socket
)
{
    std::cout << "[debug] check_path root_dir: " << root_dir << " work_dir: " << work_dir << " input_path: " << input_path << " type: " << type << "\n";


    std::filesystem::path root;
    try {
        root = std::filesystem::canonical(root_dir);
    } catch (...) {
        send_response(socket, {"ERROR", 400, "INVALID_ROOT", {}});
        return std::nullopt;
    }

    // work_dir musí byť v root (a ideálne už canonical)
    std::filesystem::path work;
    try {
        work = std::filesystem::weakly_canonical(work_dir);
    } catch (...) {
        send_response(socket, {"ERROR", 400, "INVALID_WORKDIR", {}});
        return std::nullopt;
    }

    if (!is_subpath(root, work))
    {
        send_response(socket, {"ERROR", 403, "WORKDIR_OUTSIDE_ROOT", {}});
        return std::nullopt;
    }

    std::filesystem::path requested;

    // Ak klient pošle "/a/b", ber to ako cestu v rámci root: root/a/b
    if (input_path.is_absolute())
        requested = root / input_path.relative_path();
    else
        requested = work / input_path;

    std::filesystem::path resolved;
    try {
        resolved = std::filesystem::weakly_canonical(requested);
    } catch (...) {
        send_response(socket, {"ERROR", 400, "INVALID_PATH", {}});
        return std::nullopt;
    }

    std::cout << requested << " -> " << resolved << "\n";

    // ochrana proti escape mimo root
    if (!is_subpath(root, resolved))
    {
        send_response(socket, {"ERROR", 403, "PATH_OUTSIDE_ROOT", {}});
        return std::nullopt;
    }

    // kontrola typu (new = nemusí existovať)
    if (type != "new")
    {
        std::error_code ec;

        if (!std::filesystem::exists(resolved, ec) || ec)
        {
            send_response(socket, {"ERROR", 404, "PATH_DOES_NOT_EXIST", {}});
            return std::nullopt;
        }

        if (type == "dir" && !std::filesystem::is_directory(resolved, ec))
        {
            send_response(socket, {"ERROR", 405, "PATH_IS_NOT_DIRECTORY", {}});
            return std::nullopt;
        }

        if (type == "file" && !std::filesystem::is_regular_file(resolved, ec))
        {
            send_response(socket, {"ERROR", 405, "PATH_IS_NOT_FILE", {}});
            return std::nullopt;
        }
    }

    return resolved;
}

config set_up_config(int argc, char* argv[], config& cfg) 
{

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--port") cfg.port = std::stoi(argv[++i]);
        else if (arg == "--root") cfg.root_dir = argv[++i];
    }

    if (!cfg.root_dir.empty()) {
    if (!std::filesystem::exists(cfg.root_dir)) {
        std::cerr << "[error] log file does not exist: " << cfg.root_dir << "\n";
        exit(1);
     }
    }

    std::cout << "Port: " << cfg.port << std::endl;
    std::cout << "Root directory: " << cfg.root_dir << std::endl;

    if (cfg.root_dir.empty()) {
        std::cerr << "[error] Root directory not specified\n";
        exit(1);
    }

    if (cfg.port <= 0 || cfg.port > 65535) {
        std::cerr << "[error] Invalid port number: " << cfg.port << "\n";
        exit(1);
    }

    return cfg;
}

bool delete_server_file(asio::ip::tcp::socket& socket, const std::string& local_path, const bool is_file)
{
    std::filesystem::path p(local_path);

    // local_path je file
    if (is_file)
    {
        // vymazeme subor         
        return std::filesystem::remove(p);
    }
    // local_path je dir
    else
    {
        // zmaže všetko rekurzívne aj root folder
        return std::filesystem::remove_all(p);
    }
}

bool copy_server_file(const std::filesystem::path& source_path,const std::filesystem::path& dest_path)
{

    // SOURCE = FILE
    if (std::filesystem::is_regular_file(source_path))
    {
        std::filesystem::path final_dest = dest_path;

        // ak dest je priecinok pridáme filename
        if (std::filesystem::is_directory(dest_path))
        {
            final_dest /= source_path.filename();
        }
        // mozeme prepisat file
        std::filesystem::copy_file(
            source_path,
            final_dest,
            std::filesystem::copy_options::overwrite_existing
        );

        // success
        return true;
    }

    // SOURCE = DIRECTORY
    if (std::filesystem::is_directory(source_path))
    {
        // rekurzivne skopírujeme celý priečinok
        std::filesystem::copy(
            source_path,
            dest_path,
            std::filesystem::copy_options::recursive |
            std::filesystem::copy_options::overwrite_existing
        );

        //success
        return true;
    }

    // iný typ alebo DIR do FILE
    return false;
}


bool handle_upload(asio::ip::tcp::socket& socket, Request& req, profile& user_profile)
{
    // tu mame metafile pre ukladanie pri resume
    FileTransferMeta metafile;

    if (!req.args.contains("resume"))
    {
        // kontrola spravnej remote_path pri init uploade
        if (req.args.contains("remote_path") && !req.args["remote_path"].is_null())
        {
            std::optional<std::filesystem::path> remote_path_r = 
                check_path
                (
                    user_profile.user_directory,
                    user_profile.user_directory,
                    req.args["remote_path"].get<std::string>(),
                    "dir",
                    socket
                );
                if(!remote_path_r.has_value()){return 1;} 
                metafile.remote_path = remote_path_r.value(); 
        }
        else
        {
            // ak nebola definovana remote_path v cmd
            metafile.remote_path = user_profile.working_directory;
        }
    }
    else
    {
        // ak je resume remote_path ju automaticky poslana
        metafile.remote_path = req.args["remote_path"].get<std::string>();
    }
            
    // inicilizacia
    metafile.local_path = req.args["local_path"].get<std::string>();
    metafile.cmd = req.cmd;
    metafile.file_hash = req.args["hash"].get<std::string>();
    metafile.offset = req.args["offset"].get<std::uint64_t>();
    metafile.file_size = req.args["size"].get<std::uint64_t>();

    // kontrola suboru v remote_path
    // .ext.part = resume
    // .ext = init
    if (!ends_with(metafile.remote_path, ".part"))
    {
        // pridame meno suboru na koniec remote_path
        apply_filename_to_remote_path(metafile);
        std::filesystem::path p = metafile.remote_path;
        std::error_code ec;
        // zistime ci uz existuje
        if (std::filesystem::exists(p, ec) && !req.args.contains("force"))
        {
            send_response(socket,Response{"ERROR", 500, "UPLOAD_DUPLICATE", {"message", "File already exists."}});
            return 1;
        }
        ec.clear();
        if (req.args.contains("force"))
        {
            std::filesystem::remove(p, ec);
            if(ec)
            {
                send_response(socket,Response{"ERROR", 500, "UPLOAD_FAILED", {"message", "Cannot open a file."}});
                return 1;
            }
        }
    }
            
    // odpoved na req
    send_response(socket, Response{"OK", 1, "UPLOAD_START", {}});
    try
        {
            // prenos suboru
            receive_message
            (
                socket,
                metafile,
                user_profile.user_directory,
                (user_profile.username == "public"),
                true
            );
        }
        catch(const std::exception& e)
        {
            send_response(socket, {"ERROR",500,"UPLOAD_FAILED",{ {"message", e.what()} }});
            return 1;
        }
        // ukoncenie req
        send_response(socket, Response{"OK", 0, "UPLOAD_END", {}}); 
        return 0;   
}



int main(int argc, char* argv[]) 
{

    if (argc != 5) 
    {
        std::cout << "Usage: ./server --port <PORT> --root <ROOT_DIR>\n";
        return 1;
    }

    config server_config;
    profile user_profile;
    asio::io_context io;
    // server configuration
    server_config = set_up_config(argc, argv, server_config);

    // server user database
    nlohmann::json user_db;
    std::optional<nlohmann::json> user;

    std::ifstream f(server_config.root_dir + USER_DB_FILEPATH);
    // ak user db uz existuje nacitame data
    if (f.is_open()) 
    {
        f >> user_db;
    } 
    else 
    {
        // inak vytvorime prazdnu db
        user_db["users"] = nlohmann::json::array();
    }

    if (sodium_init() < 0) 
    {
        std::cerr << "[error] Failed to initialize libsodium" << std::endl;
        return 1;
    }
    
       
    try
    {
        // server socket setup
        asio::ip::tcp::acceptor acceptor(io,asio::ip::tcp::endpoint(asio::ip::tcp::v4(), server_config.port));
        
        std::cout << "[server] Running on port " << server_config.port << "\n";
        std::cout << "[server] Root directory: " << server_config.root_dir<< "\n";

        asio::ip::tcp::socket socket(io);

        try 
        {
            std::cout << "[server] Waiting for client...\n";
            acceptor.accept(socket);

            std::cout << "[server] Client connected: " << socket.remote_endpoint() << "\n";
            
            while (true) 
            {
                try
                {
                    std::cout << "ALOHA" << std::endl;
                    Request req = receive_request(socket);
                

                    if (req.cmd == "AUTH") 
                    {
                        std::string username = req.args.value("username", "");
                        if (username == "public") 
                        {
                            send_response(socket, {"OK", 0, "PUBLIC_USER", {}});
                            user_profile.username = "public";
                            user_profile.user_directory = server_config.root_dir + "/public";
                            user_profile.working_directory = user_profile.user_directory;
                            if (!std::filesystem::exists(user_profile.user_directory)) 
                            {
                                std::filesystem::create_directories(user_profile.user_directory);     
                            }
                            continue;
                        }
                        
                        user = find_user(user_db, username);

                        if (user != std::nullopt) {
                            // need password verification
                            Response resp{"OK", 0, "USER_EXISTS", {}};
                            send_response(socket, resp);
                        } else {
                            // register error response
                            Response resp{"ERROR", 1001, "USER_NOT_FOUND", {}};
                            send_response(socket, resp);
                        }
                    }

                    if (req.cmd == "REGS") 
                    {

                        std::string username = req.args.value("username", "");
                        std::string password = req.args.value("password", "");

                        if (password.empty()) {
                            send_response(socket, {"ERROR", 400, "MISSING_FIELDS", {}});
                            continue;
                        }

                        user = find_user(user_db, username);
                        if (user != std::nullopt) {
                            send_response(socket, {"ERROR", 1002, "USERNAME_TAKEN", {}});
                            continue;
                        }

                        // Create sodium password hash (includes its own salt internally)
                        char hash_str[crypto_pwhash_STRBYTES];

                        if (crypto_pwhash_str(
                                hash_str,
                                password.c_str(),
                                password.size(),
                                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                crypto_pwhash_MEMLIMIT_INTERACTIVE
                            ) != 0)
                        {
                            send_response(socket, {"ERROR", 401, "HASHING_FAILED", {}});
                            continue;
                        }

                        // Store user in DB
                        nlohmann::json new_user = 
                        {
                            {"username", username},
                            {"password_hash", hash_str}   // store hash as string with salt
                        };

                        user_db["users"].push_back(new_user);

                        // Save DB
                        save_user_db(user_db, server_config.root_dir);

                        // Create user's private directory
                        std::string user_dir = server_config.root_dir + "/" + username;
                        std::filesystem::create_directory(user_dir);

                        // Respond to client
                        send_response(socket, {"OK", 0, "USER_REGISTERED", {}});
                        user_profile.username = username;
                        user_profile.user_directory = user_dir;

                        continue;
                    }

                    if (req.cmd == "LOGN") 
                    {
                        std::string username = req.args.value("username", "");
                        std::string password = req.args.value("password", "");

                        if (password.empty()) {
                            send_response(socket, {"ERROR", 400, "MISSING_FIELDS", {}});
                            continue;
                        }

                        user = find_user(user_db, username);
                        if (user == std::nullopt) {
                            send_response(socket, {"ERROR", 1001, "USER_NOT_FOUND", {}});
                            continue;
                        }

                        // nlohmann::json user = *user_opt;
                        std::string stored_hash = (*user).value("password_hash", "");
                        if (stored_hash.empty()) {
                            send_response(socket, {"ERROR", 401, "NO_PASSWORD_HASH", {}});
                            continue;
                        }

                        // Verify password
                        if (crypto_pwhash_str_verify(
                                stored_hash.c_str(),
                                password.c_str(),
                                password.size()
                            ) != 0)
                        {
                            send_response(socket, {"ERROR", 1003, "INVALID_PASSWORD", {}});
                            continue;
                        }

                        // Successful login
                        std::cout << "Successful login for user: " << username << "\n";
                        user_profile.username = username;
                        user_profile.user_directory = server_config.root_dir + "/" + username;
                        user_profile.working_directory = user_profile.user_directory;

                        std::filesystem::path transfer_dir = user_profile.user_directory;
                        transfer_dir /= "transfer";
                        send_response(socket,{"OK",0,"LOGIN_SUCCESSFUL",{{"resumed_transfers", load_transfer_meta(transfer_dir.string())}}});
                        continue;
                    }

                    if (req.cmd == "LIST")
                    {
                        std::filesystem::path remote_path;

                        // ak mame argument path
                        if (req.args.contains("path"))
                        {
                            std::optional<std::filesystem::path> remote_path_r = 
                                check_path(user_profile.user_directory,user_profile.working_directory,req.args["path"].get<std::string>(),"dir",socket);
                            if(!remote_path_r.has_value()){continue;} 
                            remote_path = remote_path_r.value(); 
                        }
                        else
                        {
                            // ak nie je path tak je current user dir na serveri
                            remote_path = user_profile.working_directory;
                        }

                        // rekurentne prehladame remote_path a ukladame do stringu msg
                        std::string msg;
                        for (const auto& entry : std::filesystem::recursive_directory_iterator(remote_path))
                        {
                            std::filesystem::path rel =
                                std::filesystem::relative(entry.path(), remote_path);

                            msg += rel.string();
                            if (entry.is_directory()) msg += "/";
                            msg += "\n";
                        }

                        //zisakme velkost listu
                        std::uint64_t size = msg.size();
                        // ak je prazdny
                        if (msg.empty())
                        {
                            size = 0;
                        }
                        send_response(socket, Response{"OK", 1, "START_LIST", {{"size", size}}});
                        //zacneme posielat v chunkoch
                        if(!size == 0){send_message(socket, msg, size,0,false);}
                        send_response(socket, Response{"OK", 0, "END_LIST", {}});
                    }

                    if (req.cmd == "UPLOAD")
                    {
                        handle_upload(socket,req,user_profile);
                        continue;
                    }

                    if (req.cmd == "DOWNLOAD")
                    {
                        std::filesystem::path remote_path;
                        
                        // kontrola ci existuje file v server repo inak ERROR
                        std::optional<std::filesystem::path> remote_path_r = 
                            check_path
                            (
                                user_profile.user_directory,
                                user_profile.user_directory,
                                req.args["remote_path"].get<std::string>(),
                                "file",
                                socket
                            );
                        if(!remote_path_r.has_value()){continue;} 
                        remote_path = remote_path_r.value(); 

                        const std::uint64_t size = std::filesystem::file_size(remote_path);
                        const std::string hash = "sha256_" + sha256_file(remote_path);
                        std::uint64_t offset = 0;

                        if (req.args.contains("resume"))
                        {
                            offset = req.args["offset"].get<std::uint64_t>();
                            if (size != req.args["size"].get<std::uint64_t>() || hash != req.args["hash"].get<std::string>())
                            {
                                // pravdeopdobne sa zmenil obsah suboru takze treba odznova
                                offset = 0;
                            }
                        }
                        
                        send_response(socket, Response{"OK",1,"DOWNLOAD_START",{{"offset", offset},{"size", size},{"hash", hash}}});

                        try
                        {
                            send_message
                            (
                                socket,
                                remote_path.string(),
                                size,
                                offset,
                                true
                            );
                        }
                        catch(std::exception& e)
                        {
                            send_response(socket, {"ERROR",500,"DOWNLOAD_FAILED",{ {"message", e.what()} }});
                            continue;
                        }
                        send_response(socket, Response{"OK", 0, "DOWNLOAD_END", {}});
                        continue;

                    }
                    
                    if (req.cmd == "SYNC")
                    {
                        //zistime ci existuje dir na serveri, automaticky odosle ERRORS
                        std::optional<std::filesystem::path> remote_path_r = 
                                check_path
                                (
                                    user_profile.user_directory,
                                    user_profile.user_directory,
                                    req.args["remote_path"].get<std::string>(),
                                    "dir",
                                    socket
                                );
                        if(!remote_path_r.has_value()){continue;} 
                        std::filesystem::path remote_path = remote_path_r.value(); 

                        // ziskame json s vsetkymi info
                        // skip (netreba nic)
                        // delete (remote_path - server)
                        // upload (local_path - klient, remote_path - server)
                        // counts (pocty jednotlivych suborov upload,skip,delete)
                        //TODO ak pojde treba aj ked neni remote teda asi nie
                        nlohmann::json compared = compare_repos
                        (
                            build_directory_file_list_recursive(remote_path),
                            req.args["files"],
                            req.args["remote_path"].get<std::string>(),
                            req.args["local_path"].get<std::string>()
                        );

                        // vymazeme subory na servery ktore neboli v lokalnom repo klienta
                        for (const auto& item : compared["delete"])
                        {
                            const std::string remote_path = item["remote_path"].get<std::string>();
                            try
                            {
                                delete_server_file(socket, remote_path, true);
                            }
                            catch (...)
                            {
                                // v pripade ze nastane error pri delete urobime skip
                                compared["counts"]["skip"] = compared["counts"]["skip"].get<uint64_t>() + 1;
                                compared["counts"]["delete"] = compared["counts"]["delete"].get<uint64_t>() - 1;
                            }
                        }

                        // ak mame files na upload
                        if (compared["counts"]["upload"].get<std::uint64_t>() != 0)
                        {
                            std::uint64_t successful_uploads = 0;
                            // inicializacia SYNC 
                            send_response(socket, Response{"OK", 1, "SYNC_START", {"files", compared["upload"]}});
                            for (const auto& item : compared["upload"])
                            {
                                // cakame na UPLOAD cmd
                                req = receive_request(socket);
                                // ak je ERROR tak sa spracuje automaticky a vrati 1
                                if(!handle_upload(socket,req,user_profile))
                                {
                                    successful_uploads++;
                                }
                            }
                            std::cout <<"sc:" << successful_uploads << "/n";
                            const auto failed_uploads = compared["counts"]["upload"].get<std::uint64_t>() - successful_uploads;

                            // ak sme mali neuspesne uploady budu skip
                            if (failed_uploads != 0)
                            {
                                compared["counts"]["skip"] = compared["counts"]["skip"].get<std::uint64_t>() + failed_uploads;
                                compared["counts"]["upload"] = compared["counts"]["upload"].get<std::uint64_t>() - failed_uploads;
                            }
                        }

                        // uspesny sync (posielame aj vykonane zmeny)
                        send_response(socket, Response{"OK", 0, "SYNC_END", {"status", compared["counts"]}}); 
                    }

                    if (req.cmd == "DELETE")
                    {
                        // ziskame remote_path od klienta
                        std::filesystem::path remote_path = std::filesystem::path(req.args["path"].get<std::string>());

                        std::string format = "file";
                        if (!remote_path.has_extension())
                        {
                            format = "dir";
                        }

                        std::optional<std::filesystem::path> remote_path_r = 
                            check_path(user_profile.user_directory,user_profile.working_directory,remote_path.string(),format,socket);

                        if (!remote_path_r.has_value()) {continue;}
                        remote_path = remote_path_r.value();
                    
                        try
                        {
                            // odstranime folder alebo file
                            delete_server_file(socket,remote_path.string(),!std::filesystem::is_directory(remote_path));
                        }
                        catch (std::exception& e)
                        {
                            send_response(socket, Response{"ERROR", 0, "DELETE_FAILED", {"message", e.what()}}); 
                            continue;
                        }
                        send_response(socket, Response{"OK", 0, "DELETE_SUCCESS", {}}); 
                        continue;
                    }
                
                    if (req.cmd == "EXIT")
                    {
                        //opdoved na EXIT a vypnutie
                        send_response(socket, Response{"OK", 0, "GOODBYE", {}});
                        std::cout << "[server] Client disconnected.\n";
                        // zakazmeme dalsie zapisy a citania
                        socket.shutdown(asio::ip::tcp::socket::shutdown_both);
                        break;
                    }
                
                    if (req.cmd == "CD")
                    {
                        std::filesystem::path remote_path = std::filesystem::path(req.args["path"].get<std::string>());
                        // skontrolujeme ci je validny dir (automaticky posle ERRORS)
                        std::optional<std::filesystem::path> remote_path_r = 
                            check_path(user_profile.user_directory,user_profile.working_directory,remote_path.string(),"dir",socket);
                        if (!remote_path_r.has_value()) {continue;}
                        remote_path = remote_path_r.value();
                        // nastavime novy work dir
                        user_profile.working_directory = remote_path.string();
                        send_response(socket, Response{"OK", 0, "CD_SUCCESS", {}});
                    }

                    if (req.cmd == "MKDIR")
                    {
                        std::filesystem::path remote_path = std::filesystem::path(req.args["path"].get<std::string>());
                        // skontrolujeme ci je validny dir (automaticky posle ERRORS) root cesta ci sedi
                        std::optional<std::filesystem::path> remote_path_r =
                            check_path(user_profile.user_directory,user_profile.working_directory,remote_path.string(),"new",socket);
                        if (!remote_path_r.has_value()) {continue;}
                        remote_path = remote_path_r.value();
                        std::error_code ec;
                        // pokusime sa vytvorit aj rekursivne dir
                        std::filesystem::create_directories(remote_path,ec);
                        if(ec)
                        {
                            send_response(socket, Response{"ERROR", 0, "MKDIR_FAILED", {"message", ec.message()}});
                            continue;
                        }
                        send_response(socket, Response{"OK", 0, "MKDIR_SUCCESS", {}});
                        continue;
                    }

                    if (req.cmd == "RMDIR")
                    {
                        std::filesystem::path remote_path = std::filesystem::path(req.args["path"].get<std::string>());
                        // skontrolujeme ci je validny dir (automaticky posle ERRORS)
                        std::optional<std::filesystem::path> remote_path_r =
                            check_path(user_profile.user_directory,user_profile.working_directory,remote_path.string(),"dir",socket);
                        if (!remote_path_r.has_value()) {continue;}
                        remote_path = remote_path_r.value();

                        if(remote_path == user_profile.user_directory || remote_path == user_profile.working_directory)
                        {
                            send_response(socket, Response{"ERROR", 0, "RMDIR_FAILED", {"message", "Cannot remove user root directory."}});
                            continue;
                        }
                        try
                        {
                            // odstranime dir
                            delete_server_file(socket,remote_path.string(),false);
                        }
                        catch (std::exception& e)
                        {
                            send_response(socket, Response{"ERROR", 0, "RMDIR_FAILED", {"message", e.what()}});
                            continue;
                        }
                        send_response(socket, Response{"OK", 0, "RMDIR_SUCCESS", {}});
                        continue;
                    }

                    if (req.cmd == "MOVE" || req.cmd == "COPY")
                    {
                        std::filesystem::path source_path = std::filesystem::path(req.args["src"].get<std::string>());
                        std::filesystem::path dest_path = std::filesystem::path(req.args["dst"].get<std::string>());

                        std::string format_src;
                        std::string format_dst;

                        // potrebujeme vediet ci je file alebi dir pre kontrolu
                        if (source_path.has_extension())
                        {
                            format_src = "file";
                        }
                        else
                        {
                            format_src = "dir";
                        }


                        if (dest_path.has_extension())
                        {
                            format_dst = "file";
                        }
                        else
                        {
                            format_dst = "dir";
                        }

                        // skontrolujeme ci je validny source path (automaticky posle ERRORS)
                        std::optional<std::filesystem::path> source_path_r = 
                            check_path(user_profile.user_directory,user_profile.working_directory,source_path.string(),format_src,socket);
                        if (!source_path_r.has_value()) {continue;}
                        source_path = source_path_r.value();
                        // skontrolujeme ci je validny dest path (automaticky posle ERRORS)
                        std::optional<std::filesystem::path> dest_path_r = 
                            check_path(user_profile.user_directory,user_profile.working_directory,dest_path.string(),format_dst,socket);
                        if (!dest_path_r.has_value()) {continue;}
                        dest_path = dest_path_r.value();

                        try
                        {

                            if(req.cmd == "MOVE")
                            {
                                // pridame priponu na dest priecinok ak treba
                                std::filesystem::path final_dst = dest_path;
                                if (std::filesystem::is_directory(final_dst))
                                {
                                    final_dst /= source_path.filename();
                                }
                                std::filesystem::rename(source_path, final_dst);
                            }
                            else // COPY
                            {
                                if(!copy_server_file(source_path, dest_path))
                                {
                                    send_response(socket, Response{"ERROR", 0, "COPY_FAILED", {"message", "Destination path is in wrong format."}});
                                    continue;
                                }
                            }
                        }
                        catch (std::exception& e)
                        {
                            // ak nastane chyba pri move alebo copy hned hlasime a koncime
                            send_response(socket, Response{"ERROR", 0, req.cmd + "_FAILED", {"message", e.what()}});
                            continue;
                        }
                        // success
                        send_response(socket, Response{"OK", 0, req.cmd + "_SUCCESS", {}});
                        continue;
                    }

                // Vynimky pri spracovani cmds
                }
                catch(std::exception& e)
                {
                    std::cerr << "[server] Exception: " << e.what() << "\n";
                    std::cerr << "Emergency shutdown.\n";
                    break;
                }   
            }

            
            // vypneme socket
            socket.close();
        }
        // Vynimky pri core praci so soketmi
        catch (std::exception& e) 
        {
            std::cerr << "[error] " << e.what() << "\n";
            // socket.close();
            // return 1;
        }
    }
    // zachytavame chyby pri inicilizacii
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }

    return 0;
}