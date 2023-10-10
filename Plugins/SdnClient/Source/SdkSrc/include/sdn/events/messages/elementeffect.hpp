#pragma once

/// @file
/// @brief A message with a fancy effect.

#if __has_include(<nlohmann/json_fwd.hpp>)
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif

#include <string>

#include "sdn/events/common.hpp"

namespace sdn {
namespace events {
//! Non-state events sent in the timeline like messages.
namespace msg {

//! Content of `m.room.message` with a msgtype used by Element to show a fancy effect.
struct ElementEffect
{
    //! The body of the message.
    std::string body;
    std::string msgtype;
    //! We only handle org.sdn.custom.html.
    std::string format;
    //! HTML formatted message.
    std::string formatted_body;
    //! Relates to for rich replies
    sdn::common::Relations relations;

    friend void from_json(const nlohmann::json &obj, ElementEffect &content);
    friend void to_json(nlohmann::json &obj, const ElementEffect &content);
};

} // namespace msg
} // namespace events
} // namespace sdn
