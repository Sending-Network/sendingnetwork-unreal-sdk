/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {

struct EventFilter
{       

/// The maximum number of events to return.
    std::optional<int> limit;

/// A list of sender IDs to exclude. If this list is absent then no senders are excluded. A matching sender will be excluded even if it is listed in the ``'senders'`` filter.
    immer::array<std::string> notSenders;

/// A list of event types to exclude. If this list is absent then no event types are excluded. A matching type will be excluded even if it is listed in the ``'types'`` filter. A '*' can be used as a wildcard to match any sequence of characters.
    immer::array<std::string> notTypes;

/// A list of senders IDs to include. If this list is absent then all senders are included.
    immer::array<std::string> senders;

/// A list of event types to include. If this list is absent then all event types are included. A ``'*'`` can be used as a wildcard to match any sequence of characters.
    immer::array<std::string> types;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<EventFilter> {
  static void to_json(json& jo, const EventFilter &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "limit"s, pod.limit);
    
    addToJsonIfNeeded(jo, "not_senders"s, pod.notSenders);
    
    addToJsonIfNeeded(jo, "not_types"s, pod.notTypes);
    
    addToJsonIfNeeded(jo, "senders"s, pod.senders);
    
    addToJsonIfNeeded(jo, "types"s, pod.types);
  }
  static void from_json(const json &jo, EventFilter& result)
  {
  
    if (jo.contains("limit"s)) {
      result.limit = jo.at("limit"s);
    }
    if (jo.contains("not_senders"s)) {
      result.notSenders = jo.at("not_senders"s);
    }
    if (jo.contains("not_types"s)) {
      result.notTypes = jo.at("not_types"s);
    }
    if (jo.contains("senders"s)) {
      result.senders = jo.at("senders"s);
    }
    if (jo.contains("types"s)) {
      result.types = jo.at("types"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
