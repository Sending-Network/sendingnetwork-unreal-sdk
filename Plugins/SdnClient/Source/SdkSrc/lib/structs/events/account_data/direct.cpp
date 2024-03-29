#include <nlohmann/json.hpp>

#include "sdn/events/account_data/direct.hpp"

namespace sdn {
namespace events {
namespace account_data {

void
from_json(const nlohmann::json &obj, Direct &content)
{
    content.user_to_rooms = obj.get<decltype(content.user_to_rooms)>();
}

void
to_json(nlohmann::json &obj, const Direct &content)
{
    obj = content.user_to_rooms;
}

} // namespace state
} // namespace events
} // namespace sdn
