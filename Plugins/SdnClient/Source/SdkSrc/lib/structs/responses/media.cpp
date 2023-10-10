#include "sdn/responses/media.hpp"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace sdn {
namespace responses {

void
from_json(const json &obj, ContentURI &res)
{
    res.content_uri = obj.at("content_uri").get<std::string>();
}
}
}
