#include <nlohmann/json.hpp>
#include <string>

#include "sdn/events/redaction.hpp"

using json = nlohmann::json;

namespace sdn {
namespace events {
namespace msg {

void
from_json(const json &obj, Redaction &event)
{
    if (obj.count("reason") != 0 && !obj.at("reason").is_null())
        event.reason = obj.at("reason").get<std::string>();
}

void
to_json(json &obj, const Redaction &event)
{
    obj["reason"] = event.reason;
}

} // namespace msg
} // namespace events
} // namespace sdn
