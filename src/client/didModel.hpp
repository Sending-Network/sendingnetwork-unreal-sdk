#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <nlohmann/json.hpp>

namespace Kazv
{
    using json = nlohmann::json;

    class DidListResponse {
    public:
        std::vector<std::string> data;
    };

    class PreloginRequest {
    public:
        std::string did;
        std::string address;

        PreloginRequest(const std::string& d, const std::string& a) : did(d), address(a) {}

        std::string toString() const {
            json j;
            j["did"] = did;
            j["address"] = address;
            return j.dump();
        }
    };

    class PreloginResponse {
    public:
        std::string did;
        std::string message;
        std::string updated;
        std::string randomserver;
    };

    class IdentifierModel {
    public:
        std::string did;
        std::string address;
        std::string token;

        IdentifierModel(const std::string& d, const std::string& a, const std::string& t) : did(d), address(a), token(t) {}

        std::string toString() const {
            json j;
            j["did"] = did;
            j["address"] = address;
            j["token"] = token;
            return j.dump();
        }
    };

    class LoginRequest {
    public:
        std::string type;
        std::string updated;
        std::string randomserver;
        IdentifierModel identifier;

        LoginRequest(const std::string& u, const std::string& r, const std::string& d, const std::string& a, const std::string& t) : updated(u), randomserver(r), identifier(d,a,t) {}

        std::string toString() const {
            json j;
            j["type"] = "m.login.did.identity";
            j["updated"] = updated;
            j["random_server"] = randomserver;
            j["identifier"]["did"] = identifier.did;
            j["identifier"]["address"] = identifier.address;
            j["identifier"]["token"] = identifier.token;
            return j.dump();
        }
    };

    class DidLoginResponse {
    public:
        std::string access_token;
        std::string user_id;
        std::string device_id;
    };
}

