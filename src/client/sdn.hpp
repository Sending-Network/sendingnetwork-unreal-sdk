#pragma once


#include <string>
#include "sdnModel.hpp"

namespace Kazv
{
    class SDNHttpRequest {
    public:
        SDNHttpRequest();
        ~SDNHttpRequest();

        std::string node;
        std::string access_token;

        std::string inviteUserToRoom(const std::string& roomId, const std::string& data);
        std::string sendMessage(const std::string& roomId, const std::string& data);
        std::string setRoomName(const std::string& roomId, const std::string& data);
        std::string setRoomTopic(const std::string& roomId, const std::string& data);
        std::string joinRoom(const std::string& roomId);
        std::string joinedMembers(const std::string& roomId);
        std::string getRoomState(const std::string& roomId);
        std::string joinedRooms();

    private:
        enum RequestMethod {
            GET,
            POST,
            PUT,
            DELETE
        };

        static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* response);
        std::string baseRequest(const std::string& url, const std::string& data, RequestMethod method);
    };

    
}