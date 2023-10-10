#include <nlohmann/json.hpp>

using json = nlohmann::json;

#include "sdn/events/aliases.hpp"

namespace sdn {
namespace events {
namespace state {

void
from_json(const json &obj, Aliases &content)
{
    content.aliases = obj.value("aliases", std::vector<std::string>{});
}

void
to_json(json &obj, const Aliases &content)
{
    obj["aliases"] = content.aliases;
}

} // namespace state
} // namespace events
} // namespace sdn
