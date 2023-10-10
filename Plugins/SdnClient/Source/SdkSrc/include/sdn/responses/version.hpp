#pragma once

/// @file
/// @brief Return value of the server and API version query.

#if __has_include(<nlohmann/json_fwd.hpp>)
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif

namespace sdn {
namespace responses {

//! Response from the `GET /_api/client/versions` endpoint.
//
//! Gets the versions of the specification supported by the server.
struct Versions
{
    //! The supported versions.
    std::vector<std::string> versions;

    friend void from_json(const nlohmann::json &obj, Versions &response);
};
}
}
