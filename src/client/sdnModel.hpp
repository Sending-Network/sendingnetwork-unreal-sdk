#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <nlohmann/json.hpp>

namespace Kazv
{
    using json = nlohmann::json;

    class InviteRequest {
    public:
        std::string userId;

        InviteRequest(const std::string& u) : userId(u) {}

        std::string toString() const {
            json j;
            j["user_id"] = userId;
            return j.dump();
        }
    };

    class SendMessageRequest {
    public:
        std::string body;
        std::string msgtype;

        SendMessageRequest(const std::string& b, const std::string& m) : body(b), msgtype(m) {}

        std::string toString() const {
            json j;
            j["body"] = body;
            j["msgtype"] = msgtype;
            return j.dump();
        }
    };

    class RoomStateRequest {
    public:
        std::string name;
        std::string topic;

        RoomStateRequest(const std::string& n, const std::string& t) : name(n), topic(t) {}

        std::string toString() const {
            json j;
            j["name"] = name;
            j["topic"] = topic;
            return j.dump();
        }
    };

    // class PreloginResponse {
    // public:
    //     std::string did;
    //     std::string message;
    //     std::string updated;
    //     std::string randomserver;
    // };

}