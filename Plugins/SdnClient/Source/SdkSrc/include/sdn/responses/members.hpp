#pragma once

/// @file
/// @brief Responses for the endpoints to list members

#if __has_include(<nlohmann/json_fwd.hpp>)
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif

#include <sdn/events.hpp>
#include <sdn/events/member.hpp>

namespace sdn {
namespace responses {

//! All the member events in a room.
struct Members
{
    //! A chunk of member events.
    std::vector<sdn::events::StateEvent<events::state::Member>> chunk;

    friend void from_json(const nlohmann::json &obj, Members &res);
};
}
}
