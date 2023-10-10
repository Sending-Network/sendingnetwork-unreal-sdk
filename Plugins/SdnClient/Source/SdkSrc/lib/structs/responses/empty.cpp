#include "sdn/responses/empty.hpp"

namespace sdn {
namespace responses {

// Provides a deserialization function to use when empty responses are returned from the server
void
from_json(const nlohmann::json &, Empty &)
{
}
}
}
