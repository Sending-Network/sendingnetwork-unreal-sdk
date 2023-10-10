#include "sdn/responses/messages.hpp"
#include "sdn/responses/common.hpp"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace sdn {
namespace responses {

void
from_json(const json &obj, Messages &messages)
{
    messages.start = obj.value("start", "");
    messages.end   = obj.value("end", "");

    if (obj.contains("chunk"))
        utils::parse_timeline_events(obj.at("chunk"), messages.chunk);
}
}
}
