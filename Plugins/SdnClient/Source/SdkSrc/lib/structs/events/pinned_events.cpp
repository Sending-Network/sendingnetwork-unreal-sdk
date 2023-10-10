#include <nlohmann/json.hpp>
#include <string>

#include "sdn/events/pinned_events.hpp"

using json = nlohmann::json;

namespace sdn {
namespace events {
namespace state {

void
from_json(const json &obj, PinnedEvents &event)
{
    event.pinned = obj.value("pinned", std::vector<std::string>{});
}

void
to_json(json &obj, const PinnedEvents &event)
{
    obj["pinned"] = event.pinned;
}

} // namespace state
} // namespace events
} // namespace sdn