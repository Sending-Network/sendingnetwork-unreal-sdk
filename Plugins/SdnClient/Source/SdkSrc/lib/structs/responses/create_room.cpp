#include <nlohmann/json.hpp>

#include "sdn/identifiers.hpp"
#include "sdn/responses/create_room.hpp"

namespace sdn {
namespace responses {

void
from_json(const nlohmann::json &obj, CreateRoom &response)
{
    response.room_id = obj.at("room_id").get<identifiers::Room>();
}
}
}
