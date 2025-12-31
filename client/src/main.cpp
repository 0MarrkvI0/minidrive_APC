#include "protocol.hpp"


#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>


#include <asio.hpp>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>

using asio::ip::tcp;

// const std::string TRANSFERS_PATH = "client/transfers";

//TODO multithread

// int main(int argc, char** argv) {
//     config base = set_up_config(argc, argv, config{});

//     int N = 5; // koľko klientov chceš
//     std::vector<std::thread> threads;
//     threads.reserve(N);

//     for (int i = 0; i < N; i++) {
//         config cfg = base;
//         cfg.username = base.username + std::to_string(i);    
//         cfg.log_file = "client_" + std::to_string(i) + ".log"; 

//         threads.emplace_back([cfg, i] { run_client_instance(cfg, i); });
//     }

//     for (auto& t : threads) t.join();
// }

struct config {
    std::string username;
    std::string server_ip;
    std::string port;
    std::string log_file;
};

struct cmd_spec {
    std::vector<std::string> args;
    std::size_t min_args;
    std::size_t max_args;
};

// list of avialable commands for input parsing 
// NAME : {MIN,MAX of args}
const std::unordered_map<std::string, cmd_spec> CMD_LIST = 
{
    {"LIST",{ {"path"},0, 1}},
    {"SYNC",{{"local_path","remote_path"},2,2}},
    {"UPLOAD",{{"local_path","remote_path"},1,2}},
    {"DOWNLOAD",{{"remote_path","local_path"},1,2}},
    {"DELETE",{{"path"},1,1}},
   
    {"CD",{{"path"},1,1}},
    {"MKDIR",{{"path"},1,1}},
    {"RMDIR",{{"path"},1,1}},
    {"MOVE",{{"src","dst"},2,2}},
    {"COPY",{{"src","dst"},2,2}},
    {"HELP",{{},0,0}},
    {"EXIT",{{},0,0}}
};


// pomocna funkcia na vypis CMD LISTU
void print_help(const std::unordered_map<std::string, cmd_spec>& cmds)
{
    constexpr int CMD_W  = 12;
    constexpr int ARGS_W = 32;
    constexpr int CNT_W  = 8;

    std::cout
        << std::left
        << std::setw(CMD_W)  << "COMMAND"
        << std::setw(ARGS_W) << "ARGS"
        << std::setw(CNT_W)  << "COUNT\n"
        << std::string(CMD_W + ARGS_W + CNT_W, '-') << "\n";

    for (const auto& [name, spec] : cmds)
    {
        std::ostringstream args;

        for (std::size_t i = 0; i < spec.args.size(); ++i)
        {
            bool required = i < spec.min_args;

            if (required)
                args << "<" << spec.args[i] << ">";
            else
                args << " [" << spec.args[i] << "]";

            if (i + 1 < spec.args.size())
                args << " ";
        }

        std::string count;
        if (spec.min_args == spec.max_args)
            count = std::to_string(spec.min_args);
        else
            count = std::to_string(spec.min_args) + "-" +
                    std::to_string(spec.max_args);

        std::cout
            << std::left
            << std::setw(CMD_W)  << name
            << std::setw(ARGS_W) << args.str()
            << std::setw(CNT_W)  << count
            << "\n";
    }
}

bool send_request(asio::ip::tcp::socket& socket, const Request& req)
{
    try {
        nlohmann::json j = req;
        std::string serialized = j.dump();

        serialized += '\n';

        asio::write(socket, asio::buffer(serialized));
        std::cout << "[client] Send request: " << req.cmd << "\n";
        std::cout << "[client] Args: " << req.args.dump() << "\n";
        return true;
    } catch (std::exception& e) {
        std::cerr << "[error] Failed to send request: " << e.what() << "\n";
        return false;
    }
}

Response receive_response(asio::ip::tcp::socket& socket)
{
    asio::streambuf buf;
    asio::read_until(socket, buf, '\n');

    std::istream is(&buf);
    std::string line;
    std::getline(is, line);

    nlohmann::json j = nlohmann::json::parse(line);
    Response resp = j.get<Response>();
    std::cout << "[client] Received response: " << resp.status << " " << resp.code << " " << resp.message << "\n";
    std::cout << "[client] Data: " << (resp.data.is_null() ? "none" : resp.data.dump())<< "\n";
    return resp;
}

config set_up_config(int argc, char* argv[], config& cfg) 
{
    std::string server_arg = argv[1];
    size_t at_pos = server_arg.find('@');
    size_t colon_pos = server_arg.find(':');

    if (at_pos != std::string::npos) {
        cfg.username = server_arg.substr(0, at_pos);
        cfg.server_ip = server_arg.substr(at_pos + 1, colon_pos - at_pos - 1);
    } else {
        cfg.server_ip = server_arg.substr(0, colon_pos);
    }

    cfg.port = server_arg.substr(colon_pos + 1);

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--log" && i + 1 < argc) {
            cfg.log_file = argv[++i];
        }
    }

    if (cfg.username == "public") {
        std::cout <<"[error] 'public' is a reserved username. Please choose another username.\n";
        exit(0);
    }


    if (!cfg.log_file.empty()) {
        std::filesystem::path p(cfg.log_file);

        if (!std::filesystem::exists(p)) {
            std::cerr << "[warn] log file does not exist: " << cfg.log_file << "\n";
            std::cerr << "Do you want to create it? [y/N]: ";

            char ans = 'n';
            std::cin >> ans;

            if (ans == 'y' || ans == 'Y') {
                // vytvor adresár ak treba
                if (!p.parent_path().empty()) {
                    std::error_code ec;
                    std::filesystem::create_directories(p.parent_path(), ec);
                    if (ec) {
                        std::cerr << "[error] cannot create log directory: " << p.parent_path()
                                << " (" << ec.message() << ")\n";
                        std::exit(1);
                    }
                }

                // vytvor samotný súbor
                std::ofstream ofs(p);
                if (!ofs) {
                    std::cerr << "[error] cannot create log file: " << cfg.log_file << "\n";
                    std::exit(1);
                }
            } else {
                std::cerr << "[error] log file does not exist: " << cfg.log_file << "\n";
                std::exit(1);
            }
        }
    }

    if (cfg.username.empty())
    {
        cfg.username = "public";
    }

    std::cout << "Username: " << cfg.username << std::endl;
    std::cout << "Server IP: " << cfg.server_ip << std::endl;
    std::cout << "Port: " << cfg.port << std::endl;
    std::cout << "Log file: " << (cfg.log_file.empty() ? "(none)" : cfg.log_file) << std::endl;

    return cfg;
}


void check_path(Request& req)
{
    if (req.args.contains("local_path"))
    {
        if (req.args["local_path"].is_string() == false)
        {
                throw std::runtime_error("Invalid local_path argument");
        }
        std::filesystem::path loc_path = req.args["local_path"].get<std::string>();
        if (!std::filesystem::exists(loc_path)) 
        {
                throw std::runtime_error("Local path does not exist: " + loc_path.string());
        }

        if (req.cmd == "DOWNLOAD" || req.cmd == "SYNC")
        {
            if (!std::filesystem::is_directory(loc_path))
            {
                throw std::runtime_error("Local path is a file, expected dir: " + loc_path.string());
            }
        }
        else
        {
            if (!std::filesystem::is_regular_file(loc_path))
            {
                throw std::runtime_error("Local path is a dir, expected file: " + loc_path.string());
            }
        }      
    }
}

void parse_command(const std::string& line, Request& req) 
{
    std::istringstream iss(line);

    iss >> req.cmd;
    if (req.cmd.empty())
        throw std::runtime_error("Empty command");

    std::vector<std::string> argument_list;
    std::string curr_arg;
    while (iss >> curr_arg) argument_list.push_back(curr_arg);

    auto curr_cmd = CMD_LIST.find(req.cmd);
    if (curr_cmd == CMD_LIST.end())
        throw std::runtime_error("Unknown command: " + req.cmd);

    const auto& cmd_info = curr_cmd->second;
    if (argument_list.size() < cmd_info.min_args ||
        argument_list.size() > cmd_info.max_args)
        throw std::runtime_error("Invalid arg count for " + req.cmd);

    req.args = nlohmann::json::object();

    for (size_t i = 0; i < argument_list.size(); ++i) 
    {
        req.args[cmd_info.args[i]] = argument_list[i];
    }

    check_path(req);
}

// 0-OK 1-ERROR
bool handle_duplicate(asio::ip::tcp::socket& socket,Request& req)
{
    std::cout << "Delete existing file [d] or choose other destination [c] or nothing [other keys]: ";

    char choice = 0;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    // delete file
    if (choice == 'd' || choice == 'D')
    {
        // pôvodné args 
        // +
        req.args["force"] = true; //mozeme zmazat subor
        req.args["offset"] = 0;
    }
    else if (choice == 'c' || choice == 'C')
    {
        std::string new_path;
        std::cout << "Enter new local path: ";
        std::getline(std::cin, new_path);

        // pôvodné args 
        // +
        check_path(req);
        req.args["local_path"] = new_path;    
        
        req.args["offset"] = 0;
    }
    else
    {
        std::cout << "[client] Upload cancelled by user\n";
        return 1;
    }

    if (req.cmd == "UPLOAD")
    {
        if (!send_request(socket, req))
        {
            std::cerr << "[client] Failed to resend upload request\n";
            return 1;
        }
    }
    return 0;
}


void handle_upload(asio::ip::tcp::socket& socket, Request& req)
{
    std::filesystem::path local_path = req.args["local_path"].get<std::string>();
    
    if (!req.args.contains("resume"))
    {
        req.args["offset"] = 0; 
        req.args["size"]   = std::filesystem::file_size(local_path);
        req.args["hash"]   = "sha256_" + sha256_file(local_path);
    }

    if (!send_request(socket, req)) 
    {
        throw std::runtime_error("Failed to send request");
    }

    for (;;)
    {
        Response resp = receive_response(socket);

        if (resp.status == "OK")
        {
            if (resp.code == 1)
            {
                // zaciname posielat v loope (bytestream)
                send_message(
                    socket,
                    req.args["local_path"].get<std::string>(),
                    req.args["size"].get<std::uint64_t>(),
                    req.args["offset"].get<std::uint64_t>(),
                    true
                ); 
            }
            // koniec success upload
            if (resp.code == 0) 
            {
                spdlog::info("Upload completed: {}", local_path.string());
                return;
            }

        }
        // ak subor uz je vytvoreny
        else if (resp.message == "UPLOAD_DUPLICATE")
        {
            std::cout << "[client] " << resp.message << "\n";
            if(handle_duplicate(socket,req)){return;}
        }
        else
        {
            // ked resp.status = ERROR
            std::string err =
                "Server error: " + resp.status +
                " "+ std::to_string(resp.code) +
                " " + resp.message +
                " " + resp.data.dump();
            throw std::runtime_error(err);
        }
    }
}

void handle_download(asio::ip::tcp::socket& socket, Request& req, const bool is_public)
{
    std::filesystem::path local_path;
    std::filesystem::path remote_path = std::filesystem::path(req.args["remote_path"].get<std::string>());
    std::string filename = remote_path.filename().string();

    if (!req.args.contains("resume"))
    {
        if (!req.args.contains("local_path"))
        {
            // current directory + filename z remote_path
            local_path = std::filesystem::current_path() / filename;
        }
        else
        {
            local_path = std::filesystem::path(req.args["local_path"].get<std::string>()) / filename;
        }
    }
    else
    {
        local_path = std::filesystem::path(req.args["local_path"].get<std::string>());
        if (!std::filesystem::exists(local_path))
        {
            //ak part subor neexistuje, musime znova stiahnut od zaciatku
            req.args["offset"] = 0;
        }
    }

    std::error_code ec;

    if (std::filesystem::exists(local_path, ec) && !req.args.contains("resume"))
    {
        // ak existuje uz rovnaky file
        // ak neda nic tak sa zrusi cely cmd
        if (handle_duplicate(socket,req)){return;}
        // vymazeme subor ak si user zela
        if (req.args.contains("force"))
        {
            std::filesystem::remove(local_path,ec);
            if(ec){throw std::runtime_error("Cannot delete file");}
        }
        else
        {
            // upadte path ak si user zela
            local_path = std::filesystem::path(req.args["local_path"].get<std::string>()) / filename;
        }     
    }
    if(ec){throw std::runtime_error("Cannot access file");}
    
  
    if (!send_request(socket, req)) 
    {
        throw std::runtime_error("Failed to send request");
    }

    FileTransferMeta metafile;

    for (;;)
    {
        Response resp = receive_response(socket);

        if (resp.status == "OK")
        {
            if (resp.code == 1)
            {
                metafile.cmd = req.cmd;
                // uz sme si definovali spravnu local_path (aj pre resume)
                // je to prehodene lebo robene pre server (remote je teraz local)
                metafile.remote_path = local_path.string();
                // zostava remote_path lebo by sa nemala menit (inak ERROR)
                metafile.local_path = req.args["remote_path"].get<std::string>();
                // server nam overi / posle spravne metadata o subore
                metafile.file_hash = resp.data["hash"].get<std::string>();
                metafile.offset = resp.data["offset"].get<std::uint64_t>();
                metafile.file_size = resp.data["size"].get<std::uint64_t>();
                
                // zaciname prijimat v loope
                receive_message
                (
                    socket,
                    metafile,
                    (std::filesystem::current_path()).string(),
                    is_public,
                    true
                );

            }
            // koniec success 
            if (resp.code == 0) 
            {
                spdlog::info("Download completed: {}", local_path.string());
                return;
            }

        }
        else
        {
            // ked resp.status = ERROR
            std::string err =
                "Server error: " + resp.status +
                " "+ std::to_string(resp.code) +
                " " + resp.message +
                " " + resp.data.dump();
            throw std::runtime_error(err);
        }
    }
}

void handle_sync(asio::ip::tcp::socket& socket, Request& req)
{
    std::filesystem::path local_path = req.args["local_path"].get<std::string>();
    std::filesystem::path remote_path = req.args["remote_path"].get<std::string>();

    req.args["files"] = build_directory_file_list_recursive(local_path);

    if(req.args["files"].empty())
    {
        std::cout << "No files in dir: " << local_path << "/n";
        return;
    }

    if (!send_request(socket, req)) 
    {
        std::cerr << "[error] Failed to send SYNC request\n";
        spdlog::error("Failed to send SYNC request");
        return;
    }
    while(1)
    {
        Response resp = receive_response(socket);
        if (resp.message == "SYNC_START")
        {
            
            // if (!resp.data.contains("files"))
            // {
            //     return;
            // }
            
           const auto uploads = resp.data.at(1);   

            for (const auto& file : uploads)
            {
                req.clear();
                req.cmd = "UPLOAD";
                req.args["local_path"]  = file["local_path"].get<std::string>();

                // remote_path je optional
                if (file.contains("remote_path"))
                {
                    req.args["remote_path"] = file["remote_path"].get<std::string>();
                }
                else
                {
                    req.args["remote_path"] = remote_path;    
                }
                
                try
                {
                    handle_upload(socket,req);
                }
                catch(const std::exception& e)
                {
                    std::cerr << "[client] Exception: " << e.what() << "\n";
                    continue;
                }
            }
            continue;   
        }
        if (resp.message == "SYNC_END")
        {
            std::cout << resp.data.at(1).dump(2) << "\n";
            spdlog::info("SYNC completed: {}", resp.data.at(1).dump());
            return; 
        }
        else
        {
            // ked resp.status = ERROR
            std::string err =
                "Server error: " + resp.status +
                " "+ std::to_string(resp.code) +
                " " + resp.message +
                " " + resp.data.dump();
            throw std::runtime_error(err);
        }
    }
}



int main(int argc, char* argv[]) {

    std::cout << argc << std::endl;
    if (argc < 2 || argc > 4) 
    {
        std::cerr << "Usage: ./client [username@]<server_ip>:<port> [--log <log_file>]\n";
        return 1;
    }
    
    
        asio::io_context io_context;
        config client_config;

        // client configuration
        client_config = set_up_config(argc, argv, client_config);

        // logger setup
        if (!client_config.log_file.empty()) 
        {
            auto logger = spdlog::basic_logger_mt(
                "client_logger",
                client_config.log_file
            );

            spdlog::set_default_logger(logger);
            spdlog::set_level(spdlog::level::debug); 
            spdlog::flush_on(spdlog::level::info);
            spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");

            spdlog::info("Logger initialized");
        }

        tcp::resolver resolver(io_context);
        asio::error_code ec;
        auto endpoints = resolver.resolve(client_config.server_ip, client_config.port,ec);

        if (ec) 
        {
            std::cerr << "Resolve failed: " << ec.message() << "\n";
            return 1;
        }

        // bind and connect socket
        tcp::socket socket(io_context);

    try {
        // https://think-async.com/Asio/asio-1.36.0/doc/asio/reference/connect/overload8.html
        asio::connect(socket, endpoints);

        std::cout << "Connected to server. Type messages (Ctrl+C to quit):\n";
        spdlog::info("Connected to server {}:{}", client_config.server_ip, client_config.port);

        bool logged_in = false;
        Request req;
        // init request
        req.cmd = "AUTH";
        req.args["username"] = client_config.username;

        if (!send_request(socket, req)) {
            std::cerr << "[error] Failed to send AUTH request\n";
            spdlog::error("Failed to send AUTH request");
            return 1;
        }
        Response resp;

        // authentication loop
        while (!logged_in) 
        {
            resp = receive_response(socket);


            if (resp.status == "ERROR") 
            {
                bool ask_for_password = false;
                switch (resp.code)
                {
                case 400:
                    std::cerr << "[error] Missing fields in request. Please provide correct username:";
                    spdlog::error("Missing fields in AUTH request");
                    read_line_trim(client_config.username);
                    req.args["username"] = client_config.username;
                    req.cmd = "AUTH";
                    break;

                case 401:
                    std::cerr << "[error] No password hash found for user. Please register first.\nEnter username:\n";
                    spdlog::error("No password hash found for user {}", client_config.username);
                    read_line_trim(client_config.username);
                    req.args["username"] = client_config.username;
                    req.cmd = "REGS";
                    ask_for_password = true;
                    break;

                case 1001:
                    std::cerr << "[error] User not found. Please register first.\nEnter username:";
                    spdlog::error("User not found {}", client_config.username);
                    read_line_trim(client_config.username);
                    req.args["username"] = client_config.username;
                    req.cmd = "REGS";
                    ask_for_password = true;
                    break;

                case 1002:
                    std::cerr << "[error] Username already taken. Please choose another username:";
                    spdlog::error("Username already taken: {}", client_config.username);
                    read_line_trim(client_config.username);
                    req.args["username"] = client_config.username;
                    req.cmd = "REGS";
                    ask_for_password = true;
                    break;
                
                case 1003:
                    std::cerr << "[error] Invalid password. Please try again.\n";
                    spdlog::error("Invalid password for user: {}", client_config.username);
                    req.cmd = "LOGN";
                    req.args["username"] = client_config.username;
                    ask_for_password = true;
                    break;

                default:
                    std::cerr << "[error] Unknown error.\n";
                    spdlog::error("Unknown error during authentication: {} {}", resp.code, resp.message);
                    return 1;
                
                }
                if (ask_for_password)
                {
                    std::string password;
                    std::cout << "Enter your password " << client_config.username << ": ";
                    read_line_trim(password);
                    req.args["password"] = password;
                }
                std::cout << "Loggining ...\n";
                if (!send_request(socket, req)) 
                {
                    std::cerr << "[error] Failed to send request\n";
                    return 1;
                }
            }

            if (resp.code == 0)  
            {
                // uspesne prihlasenie
                if (resp.message == "LOGIN_SUCCESSFUL" || resp.message == "USER_REGISTERED" || resp.message == "PUBLIC_USER") 
                {
                    // uloazenie mena usera do configu
                    client_config.username = req.args["username"];
                    logged_in = true;
                    spdlog::info("Logged in successfully as '{}'", client_config.username);
                    
                    // ak su resume uploads tak nam pridu v jsone ako data["resumed_transfers"]
                    // ak su resume downloads najdeme metafiles v pwd/transfer
                    // pridam ich do 1 json array a sortnem podla last_update (od najstarsieho)

                    nlohmann::json server_resumed = nlohmann::json::array();

                    if 
                    (
                        resp.data.contains("resumed_transfers") &&
                        resp.data["resumed_transfers"].is_array() &&
                        !resp.data["resumed_transfers"].empty() 
                    )
                    {
                        // upload meta
                        for (const auto& upload_meta : resp.data["resumed_transfers"])
                        {
                            server_resumed.push_back(upload_meta);
                        }
                    }

                    // download meta
                    std::filesystem::path download_path = std::filesystem::current_path() / "transfer";
                
                    nlohmann::json resumed_downloads = load_transfer_meta(download_path.string());
                    for (const auto& download_meta : resumed_downloads)
                    {
                        server_resumed.push_back(download_meta);
                    }

                    if (server_resumed.empty()){break;}

                    std::vector<nlohmann::json> vector = server_resumed.get<std::vector<nlohmann::json>>();

                    // ziskame timestamp
                    auto get_timestamp = [](const nlohmann::json& metafile) -> std::int64_t {return metafile.value("last_update", 0);};

                    std::sort(vector.begin(), vector.end(), [&](const auto& a, const auto& b)
                    {
                        return get_timestamp(a) < get_timestamp(b); // najstrsie pojdu prve
                    });

                    // finalny list
                    server_resumed = nlohmann::json::array();
                    for (auto& meta : vector)
                    {
                        server_resumed.push_back(std::move(meta));
                    }

                    if (!server_resumed.empty())
                
                    {
                        std::cout << "Incomplete upload/downloads detected, resume? (y/n):\n";
                        std::string ans; std::getline(std::cin, ans);
 
                        if (!ans.empty() && (ans[0] == 'y' || ans[0] == 'Y'))
                        {
                            // postupne sa obnovia resumed uploads/uploads
                            for (const auto& meta : server_resumed)
                            {
                                req.clear();
                                req.cmd = meta.at("type").get<std::string>();
                                req.args["hash"] = meta.at("file_hash");
                                req.args["size"] = meta.at("file_size");
                                req.args["offset"] = meta.at("offset");
                                req.args["resume"] = true;

                                std::cout << "[resume] " << req.cmd << " from offset=" << req.args["offset"] << "\n";

                                if(req.cmd == "UPLOAD")
                                {
                                    req.args["remote_path"] = meta.at("remote_path");
                                    req.args["local_path"] = meta.at("local_path");
                                    try
                                    {
                                        handle_upload(socket,req);
                                    }
                                    catch(const std::exception& e)
                                    {
                                        std::cerr << "[error] " << e.what() << "\n";
                                        spdlog::error("{}", e.what());
                                        continue;
                                    }

                                }
                                if (req.cmd == "DOWNLOAD")
                                {
                                    req.args["remote_path"] = meta.at("local_path");
                                    req.args["local_path"] = meta.at("remote_path");
                                    try
                                    {
                                        handle_download(socket,req,(client_config.username == "public"));
                                    }
                                    catch (const std::exception& e)
                                    {
                                        std::cerr << "[error] " << e.what() << "\n";
                                        spdlog::error("{}", e.what());
                                        continue;
                                    }

                                }
      
                            }
            
                        }
                    }
                }
                else
                {
                    req.cmd = "LOGN";
                    req.args["username"] = client_config.username;
                    std::string password;
                    std::cout << "Enter your password " << client_config.username << ": ";
                    std::getline(std::cin, password);
                    req.args["password"] = password;
                    std::cout << "Loggining user...\n";
                    if (!send_request(socket, req)) 
                    {
                        std::cerr << "[error] Failed to send request\n";
                        spdlog::error("Failed to send request");
                        return 1;
                    }
                }
            }
        }
        std::cout << "Welcome, " << client_config.username << "!\n";
        while (true) 
        {
            req.clear();
            std::string message;
            read_line_trim(message);
            if (message.empty()) continue;
            
            try 
            {
                parse_command(message, req);
            } catch (const std::exception& e) 
            {
                std::cerr << "[error] " << e.what() << "\n";
                spdlog::error("{}", e.what());
                continue;
            }

            try
            {
                if (req.cmd == "UPLOAD")
                {
                    handle_upload(socket,req);
                    continue;
                }

                if (req.cmd == "DOWNLOAD")
                {
                    handle_download(socket,req,client_config.username == "public");
                    continue;
                }
                
                if (req.cmd == "SYNC")
                {
                    handle_sync(socket,req);
                    continue;
                }

                if (req.cmd == "DELETE")
                {
                    send_request(socket,req);
                    resp = receive_response(socket);
                    spdlog::info("DELETE path:{} response: {} {} {}", req.args["path"].get<std::string>(), resp.status, resp.code, resp.message);
                    continue;
                }

                if (req.cmd == "LIST")
                {
                    send_request(socket, req);

                    while (true)
                    {
                        resp = receive_response(socket);

                        if (resp.status != "OK") break;

                        if (resp.code == 1) // START_LIST
                        {
                            FileTransferMeta meta;
                            meta.file_size = resp.data["size"].get<uint64_t>();

                            if (meta.file_size == 0)
                            {
                                std::cout << "directory is empty\n";
                                continue;
                            }

                            auto msg = receive_message(socket, meta, " ", false, false);
                            if (msg) std::cout << *msg << "\n";
                        }
                        else
                        {
                            break; // END_LIST
                        }
                    }
                    continue;
                }

            
                if (req.cmd == "EXIT")
                {
                    // posleme na server EXIT req
                    send_request(socket,req);
                    //cakame na odopoved
                    resp = receive_response(socket);
                    // ak je ok tak uzarieme spojenie
                    if (resp.status == "OK" && resp.code == 0)
                    {
                        std::cout << "Goodbye!\n";
                        spdlog::info("Client exited {}", client_config.username);
                        // zakazmeme dalsie zapisy a citania
                        socket.shutdown(asio::ip::tcp::socket::shutdown_both);
                        break;
                    }
                    continue;                   
                }   
            
                if (req.cmd == "HELP")
                {
                    //vypise zoznam cmd s parametrami a min-max argumentami
                    print_help(CMD_LIST);
                    continue;
                }
              
                if (req.cmd == "CD" || req.cmd == "MKDIR" || req.cmd == "RMDIR" || req.cmd == "MOVE" || req.cmd == "COPY")
                {
                    send_request(socket,req);
                    resp = receive_response(socket);
                    spdlog::info("{} args:{} response: {} {} {}", req.cmd, req.args.dump(), resp.status, resp.code, resp.message);
                    continue;
                }
            }
            catch(const std::exception& e)
            {
                std::cerr << "[error] " << e.what() << "\n";
                spdlog::error("{}", e.what());
                // continue;
                std::cerr << "Emergency shutdown.\n";
                break;
            }
        }

        
        // vypneme socket
        socket.close();
    }
    catch (std::exception& e) 
    {
        std::cerr << "[error] " << e.what() << "\n";
        spdlog::error("{}", e.what());
        socket.close();
        return 1;
    }

    return 0;
}