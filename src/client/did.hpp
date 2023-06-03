#pragma once

#include <string>
#include "didModel.hpp"

namespace Kazv
{
    class HttpRequest {
    public:
        HttpRequest();
        ~HttpRequest();

        DidListResponse getDidList(const std::string& node, const std::string& address);
        PreloginResponse prelogin(const std::string& node, const std::string& data);
        DidLoginResponse didlogin(const std::string& node, const std::string& data);

        std::string web3Sign(const std::string& privateKey, const std::string& message);

    private:
        static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* response);
    };

    
}


