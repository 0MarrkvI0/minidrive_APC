#include "protocol.hpp"

#include <asio.hpp>
#include <iostream>
#include <string>

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

    if (!cfg.log_file.empty()) {
    if (!std::filesystem::exists(cfg.log_file)) {
        std::cerr << "[error] log file does not exist: " << cfg.log_file << "\n";
        exit(1);
     }
    }


    std::cout << "Username: " << (cfg.username.empty() ? "(none)" : cfg.username) << std::endl;
    std::cout << "Server IP: " << cfg.server_ip << std::endl;
    std::cout << "Port: " << cfg.port << std::endl;
    std::cout << "Log file: " << (cfg.log_file.empty() ? "(none)" : cfg.log_file) << std::endl;

    return cfg;
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
        client_config = set_up_config(argc, argv, client_config);

        tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(client_config.server_ip, client_config.port);

        tcp::socket socket(io_context);
        // https://think-async.com/Asio/asio-1.36.0/doc/asio/reference/connect/overload8.html
        asio::connect(socket, endpoints);

        std::cout << "Connected to server. Type messages (Ctrl+C to quit):\n";

        //TODO: handle public profile
        bool logged_in = false;
        Request req;
        req.cmd = "AUTH";
        req.args["username"] = client_config.username;

        if (!send_request(socket, req)) {
            std::cerr << "[error] Failed to send AUTH request\n";
            return 1;
        }

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
                    std::cin >> client_config.username;
                    req.args["username"] = client_config.username;
                    req.cmd = "AUTH";
                    break;

                case 401:
                    std::cerr << "[error] No password hash found for user. Please register first.\nEnter username:\n";
                    std::cin >> client_config.username;
                    req.args["username"] = client_config.username;
                    req.cmd = "REGS";
                    ask_for_password = true;
                    break;

                case 1001:
                    std::cerr << "[error] User not found. Please register first:\nEnter username:";
                    std::cin >> client_config.username;
                    req.args["username"] = client_config.username;
                    req.cmd = "REGS";
                    ask_for_password = true;
                    break;

                case 1002:
                    std::cerr << "[error] Username already taken. Please choose another username:";
                    std::cin >> client_config.username;
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
                    std::cout << "Enter your password:" << client_config.username << "': ";
                    std::getline(std::cin, password);
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
                        return 1;
                    }
                }
            }
        // while (true) {
        //     std::string message;
        //     std::cout << "> ";
        //     std::getline(std::cin, message);

        //     if (message.empty()) continue;


        //     // append new line as delimiter
        //     message += '\n';

        //     // Send message
        //     asio::write(socket, asio::buffer(message));

        //     // Receive echo
        //     char reply[1024];
        //     size_t reply_length = socket.read_some(asio::buffer(reply));
        //     std::cout << "Echo: " << std::string(reply, reply_length) << std::endl;
        // }
        }
    }
    catch (std::exception& e) {
        std::cerr << "[error] " << e.what() << "\n";
    }

    return 0;
}