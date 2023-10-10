#pragma once

/// @file
/// @brief Audio messages.

#include <optional>
#include <string>

#if __has_include(<nlohmann/json_fwd.hpp>)
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif

#include "sdn/common.hpp"
#include "sdn/events/common.hpp"

namespace sdn {
namespace events {
namespace msg {

//! Content of `m.room.message` with msgtype `m.audio`.
struct Audio
{
    /// @brief A description of the audio or some kind of content description
    /// for accessibility.
    std::string body;
    //! Must be 'm.audio'.
    std::string msgtype;
    //! The sdn URL of the audio clip.
    std::string url;
    //! Metadata for the audio clip referred to in url.
    sdn::common::AudioInfo info;
    //! Encryption members. If present, they replace url.
    std::optional<crypto::EncryptedFile> file;
    //! Relates to for rich replies
    sdn::common::Relations relations;

    friend void from_json(const nlohmann::json &obj, Audio &content);
    friend void to_json(nlohmann::json &obj, const Audio &content);
};

} // namespace msg
} // namespace events
} // namespace sdn
