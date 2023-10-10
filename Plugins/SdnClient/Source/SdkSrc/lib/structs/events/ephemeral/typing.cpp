#include <nlohmann/json.hpp>

#include "sdn/events/ephemeral/typing.hpp"

namespace sdn {
namespace events {
namespace ephemeral {

void
from_json(const nlohmann::json &obj, Typing &content)
{
    content.user_ids = obj.at("user_ids").get<std::vector<std::string>>();
}

void
to_json(nlohmann::json &obj, const Typing &content)
{
    obj["user_ids"] = content.user_ids;
}

} // namespace state
} // namespace events
} // namespace sdn
