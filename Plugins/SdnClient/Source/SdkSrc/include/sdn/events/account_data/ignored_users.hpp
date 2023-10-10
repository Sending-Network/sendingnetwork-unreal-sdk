#pragma once

#include <string>
#include <vector>

#if __has_include(<nlohmann/json_fwd.hpp>)
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif

namespace sdn {
namespace events {
namespace account_data {

//! An entry in `m.ignored_user_list`. Currently only the key (mxid) is supported, not arbitrary
//! values.
struct IgnoredUser
{
    std::string id;
};

struct IgnoredUsers
{
    std::vector<IgnoredUser> users;

    //! Deserialization method needed by @p nlohmann::json.
    friend void from_json(const nlohmann::json &obj, IgnoredUsers &content);

    //! Serialization method needed by @p nlohmann::json.
    friend void to_json(nlohmann::json &obj, const IgnoredUsers &content);
};

} // namespace account_data
} // namespace events
} // namespace sdn