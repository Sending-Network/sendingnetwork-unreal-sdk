/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"
#include "csapi/definitions/event_filter.hpp"

namespace Kazv::Api {

struct RoomEventFilter : EventFilter
{       

/// If ``true``, enables lazy-loading of membership events. See
/// `Lazy-loading room members <#lazy-loading-room-members>`_
/// for more information. Defaults to ``false``.
    std::optional<bool> lazyLoadMembers;

/// If ``true``, sends all membership events for all events, even if they have already
/// been sent to the client. Does not
/// apply unless ``lazy_load_members`` is ``true``. See
/// `Lazy-loading room members <#lazy-loading-room-members>`_
/// for more information. Defaults to ``false``.
    std::optional<bool> includeRedundantMembers;

/// A list of room IDs to exclude. If this list is absent then no rooms are excluded. A matching room will be excluded even if it is listed in the ``'rooms'`` filter.
    immer::array<std::string> notRooms;

/// A list of room IDs to include. If this list is absent then all rooms are included.
    immer::array<std::string> rooms;

/// If ``true``, includes only events with a ``url`` key in their content. If ``false``, excludes those events. If omitted, ``url`` key is not considered for filtering.
    std::optional<bool> containsUrl;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<RoomEventFilter> {
  static void to_json(json& jo, const RoomEventFilter &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
    jo = static_cast<const EventFilter &>(pod);
  
    
    addToJsonIfNeeded(jo, "lazy_load_members"s, pod.lazyLoadMembers);
    
    addToJsonIfNeeded(jo, "include_redundant_members"s, pod.includeRedundantMembers);
    
    addToJsonIfNeeded(jo, "not_rooms"s, pod.notRooms);
    
    addToJsonIfNeeded(jo, "rooms"s, pod.rooms);
    
    addToJsonIfNeeded(jo, "contains_url"s, pod.containsUrl);
  }
  static void from_json(const json &jo, RoomEventFilter& result)
  {
    static_cast<EventFilter &>(result) = jo;
    if (jo.contains("lazy_load_members"s)) {
      result.lazyLoadMembers = jo.at("lazy_load_members"s);
    }
    if (jo.contains("include_redundant_members"s)) {
      result.includeRedundantMembers = jo.at("include_redundant_members"s);
    }
    if (jo.contains("not_rooms"s)) {
      result.notRooms = jo.at("not_rooms"s);
    }
    if (jo.contains("rooms"s)) {
      result.rooms = jo.at("rooms"s);
    }
    if (jo.contains("contains_url"s)) {
      result.containsUrl = jo.at("contains_url"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
