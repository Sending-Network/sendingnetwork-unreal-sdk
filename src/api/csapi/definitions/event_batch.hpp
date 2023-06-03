/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {

struct EventBatch
{       

/// List of events.
    EventList events;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<EventBatch> {
  static void to_json(json& jo, const EventBatch &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "events"s, pod.events);
  }
  static void from_json(const json &jo, EventBatch& result)
  {
  
    if (jo.contains("events"s)) {
      result.events = jo.at("events"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
