#include "protocol.hpp"
#include "meta.hpp"

#include <asio.hpp>
#include <iostream>
#include <filesystem>
#include <string>
#include <fstream>
#include <sodium.h>

const std::string USER_DB_FILEPATH = "/users.json";

struct config {
    int port;
    std::string root_dir;
};

struct profile {
    std::string username;
    std::string user_directory;
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
    return req;   
}

bool send_response(asio::ip::tcp::socket& socket, const Response& resp)
{
    try {
        nlohmann::json j = resp;
        std::string serialized = j.dump();

        serialized += '\n';

        asio::write(socket, asio::buffer(serialized));
        return true;

    } catch (std::exception& e) {
        std::cerr << "[error] Failed to send response: " << e.what() << "\n";
        return false;
    }
}

//TODO: overrvriten file not
bool check_path 
(    
    const std::filesystem::path& root_dir,
    const std::filesystem::path& input_path,
    const std::string& type, // "dir" or "file"
    asio::ip::tcp::socket& socket
)
{
    std::filesystem::path root;
    try {
        root = std::filesystem::canonical(root_dir);
    } catch (...) {
        send_response(socket, {"ERROR", 400, "INVALID_ROOT", {}});
        return false;
    }

    std::filesystem::path requested = root / input_path;

    std::filesystem::path resolved;
    try {
        resolved = std::filesystem::weakly_canonical(requested);
    } catch (...) {
        send_response(socket, {"ERROR", 400, "INVALID_PATH", {}});
        return false;
    }

    if (resolved.native().rfind(root.native(), 0) != 0)
    {
        send_response(socket, {"ERROR", 403, "PATH_OUTSIDE_ROOT", {}});
        return false;
    }

    if (!std::filesystem::exists(resolved))
    {
        send_response(socket, {"ERROR", 404, "PATH_DOES_NOT_EXIST", {}});
        return false;
    }

    if (type == "dir" && !std::filesystem::is_directory(resolved))
    {
        send_response(socket, {"ERROR", 405, "PATH_IS_NOT_DIRECTORY", {}});
        return false;
    }

    if (type == "file" && !std::filesystem::is_regular_file(resolved))
    {
        send_response(socket, {"ERROR", 405, "PATH_IS_NOT_FILE", {}});
        return false;
    }

    return true;
}



config set_up_config(int argc, char* argv[], config& cfg) {

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

int main(int argc, char* argv[]) 
{

    if (argc != 5) 
    {
        std::cout << "Usage: ./server --port <PORT> --root <ROOT_DIR>\n";
        return 1;
    }

    try {

        config server_config;
        profile user_profie;
        asio::io_context io;
        // server configuration
        server_config = set_up_config(argc, argv, server_config);

        // server user database
        nlohmann::json user_db;
        std::optional<nlohmann::json> user;

        std::ifstream f(server_config.root_dir + USER_DB_FILEPATH);
        if (f.is_open()) 
        {
            f >> user_db;
        } 
        else 
        {
            user_db["users"] = nlohmann::json::array();
        }

        if (sodium_init() < 0) 
        {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    
        // server socket setup
        asio::ip::tcp::acceptor acceptor(io,asio::ip::tcp::endpoint(asio::ip::tcp::v4(), server_config.port));

        std::cout << "[server] Running on port " << server_config.port << "\n";
        std::cout << "[server] Root directory: " << server_config.root_dir<< "\n";

        asio::ip::tcp::socket socket(io);
        std::cout << "[server] Waiting for client...\n";
        acceptor.accept(socket);

        std::cout << "[server] Client connected: " << socket.remote_endpoint() << "\n";
        
        while (true) 
        {
            std::cout << "ALOHA" << std::endl;
            Request req = receive_request(socket);
            std::cout << "[server] Received request: " << req.cmd << "\n";
            std::cout << "[server] Args: " << req.args.dump() << "\n";

            if (req.cmd == "AUTH") 
            {
                std::string username = req.args.value("username", "");
                if (username == "public") 
                {
                    send_response(socket, {"OK", 0, "PUBLIC_USER", {}});
                    user_profie.username = "public";
                    user_profie.user_directory = server_config.root_dir + "/public";
                    if (!std::filesystem::exists(user_profie.user_directory)) 
                    {
                        std::filesystem::create_directories(user_profie.user_directory);     
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
                user_profie.username = username;
                user_profie.user_directory = user_dir;

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
                send_response(socket, {"OK", 0, "LOGIN_SUCCESSFUL", {}});
                user_profie.username = username;
                user_profie.user_directory = server_config.root_dir + "/" + username;
                continue;
            }

            if (req.cmd == "LIST")
            {
                std::filesystem::path root = std::filesystem::canonical(user_profie.user_directory);

                std::filesystem::path requested = root;
                if (req.args.contains("path") && req.args["path"].is_string())
                    requested /= req.args["path"].get<std::string>();

                std::filesystem::path resolved;
                try {
                    resolved = std::filesystem::weakly_canonical(requested);
                } catch (...) {
                    send_response(socket, {"ERROR", 400, "INVALID_PATH", {}});
                    continue;
                }

                if (resolved.native().rfind(root.native(), 0) != 0)
                {
                    send_response(socket, {"ERROR", 403, "PATH_OUTSIDE_ROOT", {}});
                    continue;
                }

                if (!std::filesystem::exists(resolved))
                {
                    send_response(socket, {"ERROR", 404, "PATH_DOES_NOT_EXIST", {}});
                    continue;
                }
                if (!std::filesystem::is_directory(resolved))
                {
                    send_response(socket, {"ERROR", 405, "PATH_IS_NOT_DIRECTORY", {}});
                    continue;
                }

                std::string msg;
                for (const auto& entry : std::filesystem::directory_iterator(resolved))
                {
                    msg += entry.path().filename().string();
                    if (entry.is_directory()) msg += "/";
                    msg += "\n";
                }

                std::uint64_t size = msg.size();
                send_response(socket, Response{"OK", 1, "START_LIST", {{"size", size}}});
                // send_message(socket, msg, size, false);
                send_response(socket, Response{"OK", 0, "END_LIST", {}});
            }

        if (req.cmd == "UPLOAD")
        {
            FileTransferMeta metafile;

            if (req.args.contains("remote_path") && !req.args["remote_path"].is_null())
            {
                if (!check_path(
                        user_profie.user_directory,
                        req.args["remote_path"].get<std::string>(),
                        "dir",
                        socket))
                {
                    continue;
                }

                metafile.remote_path = req.args["remote_path"].get<std::string>();
            }
            else
            {
                metafile.remote_path = user_profie.user_directory;
            }

            metafile.local_path = req.args["local_path"].get<std::string>();
            metafile.cmd = req.cmd;
            metafile.file_hash = req.args["hash"].get<std::string>();
            metafile.offset = req.args["offset"].get<std::uint64_t>();
            metafile.file_size = req.args["size"].get<std::uint64_t>();
            send_response(socket, Response{"OK", 1, "START_UPLOAD", {}});
            while (1)
            {
                // Receive message
                asio::streambuf buffer;
                asio::read_until(socket, buffer, '\n');

                std::string msg((std::istreambuf_iterator<char>(&buffer)), {});
                std::cout << "[server] Received: " << msg << "\n";
            }
           
        }



            

        }




            
            // // Receive message
            // asio::streambuf buffer;
            // asio::read_until(socket, buffer, '\n');

            // std::string msg((std::istreambuf_iterator<char>(&buffer)), {});
            // std::cout << "[server] Received: " << msg << "\n";

            // // Respond
            // std::string response = "OK\n";
            // asio::write(socket, asio::buffer(response));

            // std::cout << "[server] Sent response\n";
        

    } catch (std::exception& e) {
        std::cerr << "[server] Exception: " << e.what() << "\n";
    }

    return 0;
}
