/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"
#include "csapi/definitions/room_event_batch.hpp"

namespace Kazv::Api {

struct Timeline : RoomEventBatch
{       

/// True if the number of events returned was limited by the ``limit`` on the filter.
    std::optional<bool> limited;

/// A token that can be supplied to the ``from`` parameter of the rooms/{roomId}/messages endpoint.
    std::optional<std::string> prevBatch;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<Timeline> {
  static void to_json(json& jo, const Timeline &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
    jo = static_cast<const RoomEventBatch &>(pod);
  
    
    addToJsonIfNeeded(jo, "limited"s, pod.limited);
    
    addToJsonIfNeeded(jo, "prev_batch"s, pod.prevBatch);
  }
  static void from_json(const json &jo, Timeline& result)
  {
    static_cast<RoomEventBatch &>(result) = jo;
    if (jo.contains("limited"s)) {
      result.limited = jo.at("limited"s);
    }
    if (jo.contains("prev_batch"s)) {
      result.prevBatch = jo.at("prev_batch"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
