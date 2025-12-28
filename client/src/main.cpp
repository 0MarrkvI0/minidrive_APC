#include "protocol.hpp"


#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>


#include <asio.hpp>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>

using asio::ip::tcp;

const std::string TRANSFERS_PATH = "client/transfers";


#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

//TODO: logovanie do suboru aj na konzolu
void init_logging(const std::string& log_file)
{
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink    = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                            log_file, true); // append

    console_sink->set_level(spdlog::level::info);   // CMD
    file_sink->set_level(spdlog::level::debug);    // FILE

    std::vector<spdlog::sink_ptr> sinks { console_sink, file_sink };

    auto logger = std::make_shared<spdlog::logger>(
        "client_logger",
        sinks.begin(),
        sinks.end()
    );

    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::debug);
    spdlog::flush_on(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
}


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

        if (req.cmd == "DOWNLOAD")
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

void handle_upload(asio::ip::tcp::socket& socket, Request& req)
{
    std::filesystem::path local_path = req.args["local_path"].get<std::string>();
    
    if (!req.args.contains("resume"))
    {
        req.args["offset"] = 0; // alebo načítaj z meta ak robíš resume
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
                // zaciname posielat v loope
                send_message(
                    socket,
                    req.args["local_path"].get<std::string>(),
                    req.args["size"].get<std::uint64_t>(),
                    req.args["offset"].get<std::uint64_t>(),
                    true
                ); 
            }
            // koniec success upload
            if (resp.code == 0) {return;}

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

void handle_download(asio::ip::tcp::socket& socket, Request& req)
{
    std::filesystem::path local_path;

    if (!req.args.contains("local_path"))
    {
        std::filesystem::path remote_path = std::filesystem::path(req.args["remote_path"].get<std::string>());
        std::string filename = remote_path.filename().string();
        // current directory + filename z remote_path
        local_path = std::filesystem::current_path() / filename;
    }
    else
    {
        local_path = std::filesystem::path(req.args["local_path"].get<std::string>());
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
                // zaciname posielat v loope
                send_message(
                    socket,
                    req.args["local_path"].get<std::string>(),
                    req.args["size"].get<std::uint64_t>(),
                    req.args["offset"].get<std::uint64_t>(),
                    true
                ); 
            }
            // koniec success upload
            if (resp.code == 0) {return;}

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
    
    try {
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
        auto endpoints = resolver.resolve(client_config.server_ip, client_config.port);

        // bind and connect socket
        tcp::socket socket(io_context);
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

            //TODO: handle different error codes
            if (resp.status == "ERROR") 
            {
                bool ask_for_password = false;
                switch (resp.code)
                {
                case 400:
                    std::cerr << "[error] Missing fields in request. Please provide correct username:";
                    read_line_trim(client_config.username);
                    req.args["username"] = client_config.username;
                    req.cmd = "AUTH";
                    break;

                case 401:
                    std::cerr << "[error] No password hash found for user. Please register first.\nEnter username:\n";
                    read_line_trim(client_config.username);
                    req.args["username"] = client_config.username;
                    req.cmd = "REGS";
                    ask_for_password = true;
                    break;

                case 1001:
                    std::cerr << "[error] User not found. Please register first.\nEnter username:";
                    read_line_trim(client_config.username);
                    req.args["username"] = client_config.username;
                    req.cmd = "REGS";
                    ask_for_password = true;
                    break;

                case 1002:
                    std::cerr << "[error] Username already taken. Please choose another username:";
                    read_line_trim(client_config.username);
                    req.args["username"] = client_config.username;
                    req.cmd = "REGS";
                    ask_for_password = true;
                    break;
                
                case 1003:
                    std::cerr << "[error] Invalid password. Please try again.\n";
                    req.cmd = "LOGN";
                    req.args["username"] = client_config.username;
                    ask_for_password = true;
                    break;

                default:
                    std::cerr << "[error] Unknown error.\n";
                    return 1;
                
                }
                if (ask_for_password)
                {
                    std::string password;
                    std::cout << "Enter your password:" << client_config.username << ": ";
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
                    if 
                    (
                        resp.data.contains("resumed_transfers") &&
                        !resp.data["resumed_transfers"].is_null() &&
                        !resp.data["resumed_transfers"].empty()
                    )
                    {
                        std::cout << "Incomplete upload/downloads detected, resume? (y/n):\n";
                        std::string ans; std::getline(std::cin, ans);

                        if (!ans.empty() && (ans[0] == 'y' || ans[0] == 'Y'))
                        {
                            // postupne sa obnovia resumed uploads
                            for (size_t i = 0; i < resp.data["resumed_transfers"].size(); ++i)
                            {
                                req.clear();                            
                                const auto& t = resp.data["resumed_transfers"][i]; 

                                // type je "UPLOAD" / "DOWNLOAD"
                                req.cmd = t.at("type").get<std::string>();

                                // args naplníme z JSONu
                                req.args["hash"] = t.at("file_hash");
                                req.args["size"] = t.at("file_size");
                                req.args["offset"] = t.at("offset");
                                req.args["remote_path"] = t.at("remote_path");
                                req.args["local_path"] = t.at("local_path");
                                req.args["resume"] = true;

                                std::cout << "[resume] " << req.cmd << " from offset=" 
                                        << req.args["offset"] << "\n";

                                try
                                {
                                    handle_upload(socket,req);
                                }
                                catch(const std::exception& e)
                                {
                                    std::cerr << "[error] " << e.what() << "\n";
                                    spdlog::error("{}", e.what());
                                }
                            }
                            std::cout << resp.data["resumed_transfers"] << std::endl;
                        }
                    }
                }
                else
                {
                    req.cmd = "LOGN";
                    req.args["username"] = client_config.username;
                    std::string password;
                    std::cout << "Enter your password:" << client_config.username << "': ";
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
        //TODO: init transfer dir
        while (true) 
        {
            req.clear();
            std::string message;
            read_line_trim(message);
            if (message.empty()) continue;

            // std::optional<std::string> src_path_opt;
            
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
                }
                if (req.cmd == "DOWNLOAD")
                {

                }
            }
            catch(const std::exception& e)
            {
                std::cerr << "[error] " << e.what() << "\n";
                spdlog::error("{}", e.what());
                continue;
            }
            

            // if (req.cmd == "UPLOAD")
            // {
            //     std::filesystem::path local_path = req.args["local_path"].get<std::string>();
            //     req.args["offset"] = 0;
            //     // req.args["offset"] = 3;
            //     req.args["size"] = std::filesystem::file_size(local_path);
            //     req.args["hash"] = "sha256_" + sha256_file(local_path);
            // }

            // if (req.cmd == "DOWNLOAD")
            // {

            // }
             

            // if (!send_request(socket, req)) 
            // {
            //     std::cerr << "[error] Failed to send request\n";
            //     spdlog::error("Failed to send request");
            //     continue;
            // }

            // while (true)
            // { 
            //     resp = receive_response(socket);
            //     if(resp.status == "OK" && resp.code == 1)
            //     {
            //         // std::uint64_t size = resp.data.at("size").get<std::uint64_t>();
            //         // if (req.cmd == "LIST")
            //         // {
            //         //     auto msg = receive_message(socket, "", size, false);
            //         //     if (msg) {
            //         //         std::cout << *msg << "\n";
            //         //     } else {
            //         //         std::cout << "[client] no message\n";
            //         //     }
            //         //     continue; 
            //         // }
            //         if (req.cmd == "UPLOAD")
            //         {
            //             std::cout << "somtu?" << std::endl;
            //             send_message
            //             (
            //                 socket,
            //                 req.args["local_path"].get<std::string>(),
            //                 req.args["size"].get<std::uint64_t>(),
            //                 req.args["offset"].get<std::uint64_t>(),
            //                 true
            //             );

            //         }
            //     }
            //     else
            //     {
            //         break;
            //     }
            // }
            
          
            // asio::write(socket, asio::buffer(message));


            // std::size_t sent = 0;
            // while (sent < len) {
            //     auto n = ::send(fd, buf + sent, len - sent, 0);
            //     if (n <= 0) { /* error/closed */ }
            //     sent += static_cast<std::size_t>(n);
            // }


         
            // do {
            //     Response resp = receive_response(socket);
            //     std::cout << "[server] Response: " << resp.status
            //             << " (" << resp.code << "): " << resp.message << "\n";
            // } while (socket.available() > 0);

            // Receive echo
            // char reply[1024];
            // size_t reply_length = socket.read_some(asio::buffer(reply));
            // std::cout << "Echo: " << std::string(reply, reply_length) << std::endl;
        }
    }
    catch (std::exception& e) {
        std::cerr << "[error] " << e.what() << "\n";
        spdlog::error("{}", e.what());
    }

    return 0;
}