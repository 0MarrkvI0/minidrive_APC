#pragma once
#include <string>
#include <optional>
#include <nlohmann/json.hpp>

struct Request {
    std::string cmd;       // napr. "LIST", "UPLOAD", ...
    nlohmann::json args;   // ďalšie polia (path, size, ... )
};

struct Response {
    std::string status;    // "OK" alebo "ERROR"
    int code;              // error code (0 = success)
    std::string message;   // human readable message
    nlohmann::json data;   // voliteľné dáta (zoznam súborov, atď.)
};

inline void to_json(nlohmann::json& j, const Request& r) {
    j = nlohmann::json{
        {"cmd",  r.cmd},
        {"args", r.args}
    };
}

inline void from_json(const nlohmann::json& j, Request& r) {
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
