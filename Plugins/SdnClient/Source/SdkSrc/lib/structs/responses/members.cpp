#include "sdn/responses/members.hpp"

#include <nlohmann/json.hpp>

#include "sdn/log.hpp"

namespace sdn {
namespace responses {

void
from_json(const nlohmann::json &obj, Members &res)
{
    if (obj.contains("chunk")) {
        for (const auto &e : obj["chunk"]) {
            try {
                res.chunk.push_back(e.get<sdn::events::StateEvent<sdn::events::state::Member>>());
            } catch (const std::exception &e) {
                utils::log::log()->warn("Failed to parse member event in members chunk: {}",
                                        e.what());
            }
        }
    }
}

}
}
