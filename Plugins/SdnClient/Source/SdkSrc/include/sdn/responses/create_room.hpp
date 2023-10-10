#pragma once

/// @file
/// @brief Response from creating a room.

#if __has_include(<nlohmann/json_fwd.hpp>)
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif

#include <sdn/identifiers.hpp>

namespace sdn {
namespace responses {
//! Response from the `POST /_api/client/r0/createRoom` endpoint.
struct CreateRoom
{
    //! The room ID of the newly created room.
    sdn::identifiers::Room room_id;

    friend void from_json(const nlohmann::json &obj, CreateRoom &response);
};
}
}
