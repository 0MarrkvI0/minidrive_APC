#include "protocol.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>


#include <asio.hpp>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>

using asio::ip::tcp;


bool send_request(asio::ip::tcp::socket& socket, const Request& req)
{
    try {
        nlohmann::json j = req;
        std::string serialized = j.dump();

        serialized += '\n';

        asio::write(socket, asio::buffer(serialized));
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
    return resp;
}

auto read_line_trim = [](std::string& out){
    std::getline(std::cin, out);
    if (!out.empty() && out.back() == '\r') out.pop_back(); // ak by bol CRLF
};


struct config {
    std::string username;
    std::string server_ip;
    std::string port;
    std::string log_file;
};

config set_up_config(int argc, char* argv[], config& cfg) {

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


// optimal std::string create_request(const std::string& cmd, Request& req, uint64_t& byte_count)
// {
//     std::istringstream iss(cmd);
//     std::string token;

//     // prvé slovo = command
//     if (!(iss >> token)) {
//         return; // prázdny input
//     }

//     req.cmd = token;
//     req.args = nlohmann::json::object();


//     if (req.cmd == "UPLOAD") 
//     {
//         if (iss >> token) 
//         {
//             req.args["byte_count"] = std::stoull(token);
//         }
//         if (iss >> token) 
//         {
//             req.args["filename"] = token;
//         }
//         return;
//     }
//     else
//     {
//         // zvyšok = argumenty
//         int index = 0;
//         while (iss >> token) {
//         req.args["arg" + std::to_string(index++)] = token;
//     }
//     }
// }  




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

        // authentication loop
        while (!logged_in) 
        {
            Response resp = receive_response(socket);
            std::cout << "[server] Response: " << resp.status
                    << " (" << resp.code << "): " << resp.message << "\n";
            

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
                if (resp.message == "LOGIN_SUCCESSFUL" || resp.message == "USER_REGISTERED" || resp.message == "PUBLIC_USER") 
                {
                    client_config.username = req.args["username"];
                    logged_in = true;
                    std::cout << "Logged in successfully as '" << client_config.username << "'\n";
                    spdlog::info("Logged in successfully as '{}'", client_config.username);
                    break;
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
        std::cout << "Wellcome, " << client_config.username << "!\n";
        while (true) {
            std::string message;
            read_line_trim(message);
            if (message.empty()) continue;
            
            std::array<char, 64*1024> buf;
            uint64_t remaining = 0;

            // message parsing
            // create_request(message, req,remaining);

            if (!send_request(socket, req)) {
                std::cerr << "[error] Failed to send request\n";
                spdlog::error("Failed to send request");
                continue;
            }
            asio::write(socket, asio::buffer(message));


         
            do {
                Response resp = receive_response(socket);
                std::cout << "[server] Response: " << resp.status
                        << " (" << resp.code << "): " << resp.message << "\n";
            } while (socket.available() > 0);

            // Receive echo
            char reply[1024];
            size_t reply_length = socket.read_some(asio::buffer(reply));
            std::cout << "Echo: " << std::string(reply, reply_length) << std::endl;
        }
        }
    }
    catch (std::exception& e) {
        std::cerr << "[error] " << e.what() << "\n";
        spdlog::error("{}", e.what());
    }

    return 0;
}