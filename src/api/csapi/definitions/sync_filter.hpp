/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"
#include "csapi/definitions/room_event_filter.hpp"
#include "csapi/definitions/event_filter.hpp"

namespace Kazv::Api {
/// Filters to be applied to room data.
struct RoomFilter
{       

/// A list of room IDs to exclude. If this list is absent then no rooms are excluded. A matching room will be excluded even if it is listed in the ``'rooms'`` filter. This filter is applied before the filters in ``ephemeral``, ``state``, ``timeline`` or ``account_data``
    immer::array<std::string> notRooms;

/// A list of room IDs to include. If this list is absent then all rooms are included. This filter is applied before the filters in ``ephemeral``, ``state``, ``timeline`` or ``account_data``
    immer::array<std::string> rooms;

/// The events that aren't recorded in the room history, e.g. typing and receipts, to include for rooms.
    RoomEventFilter ephemeral;

/// Include rooms that the user has left in the sync, default false
    std::optional<bool> includeLeave;

/// The state events to include for rooms.
    RoomEventFilter state;

/// The message and state update events to include for rooms.
    RoomEventFilter timeline;

/// The per user account data to include for rooms.
    RoomEventFilter accountData;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<RoomFilter> {
  static void to_json(json& jo, const RoomFilter &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "not_rooms"s, pod.notRooms);
    
    addToJsonIfNeeded(jo, "rooms"s, pod.rooms);
    
    addToJsonIfNeeded(jo, "ephemeral"s, pod.ephemeral);
    
    addToJsonIfNeeded(jo, "include_leave"s, pod.includeLeave);
    
    addToJsonIfNeeded(jo, "state"s, pod.state);
    
    addToJsonIfNeeded(jo, "timeline"s, pod.timeline);
    
    addToJsonIfNeeded(jo, "account_data"s, pod.accountData);
  }
  static void from_json(const json &jo, RoomFilter& result)
  {
  
    if (jo.contains("not_rooms"s)) {
      result.notRooms = jo.at("not_rooms"s);
    }
    if (jo.contains("rooms"s)) {
      result.rooms = jo.at("rooms"s);
    }
    if (jo.contains("ephemeral"s)) {
      result.ephemeral = jo.at("ephemeral"s);
    }
    if (jo.contains("include_leave"s)) {
      result.includeLeave = jo.at("include_leave"s);
    }
    if (jo.contains("state"s)) {
      result.state = jo.at("state"s);
    }
    if (jo.contains("timeline"s)) {
      result.timeline = jo.at("timeline"s);
    }
    if (jo.contains("account_data"s)) {
      result.accountData = jo.at("account_data"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {

struct Filter
{       

/// List of event fields to include. If this list is absent then all fields are included. The entries may include '.' characters to indicate sub-fields. So ['content.body'] will include the 'body' field of the 'content' object. A literal '.' character in a field name may be escaped using a '\\'. A server may include more fields than were requested.
    immer::array<std::string> eventFields;

/// The format to use for events. 'client' will return the events in a format suitable for clients. 'federation' will return the raw event as received over federation. The default is 'client'.
    std::optional<std::string> eventFormat;

/// The presence updates to include.
    EventFilter presence;

/// The user account data that isn't associated with rooms to include.
    EventFilter accountData;

/// Filters to be applied to room data.
    RoomFilter room;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<Filter> {
  static void to_json(json& jo, const Filter &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "event_fields"s, pod.eventFields);
    
    addToJsonIfNeeded(jo, "event_format"s, pod.eventFormat);
    
    addToJsonIfNeeded(jo, "presence"s, pod.presence);
    
    addToJsonIfNeeded(jo, "account_data"s, pod.accountData);
    
    addToJsonIfNeeded(jo, "room"s, pod.room);
  }
  static void from_json(const json &jo, Filter& result)
  {
  
    if (jo.contains("event_fields"s)) {
      result.eventFields = jo.at("event_fields"s);
    }
    if (jo.contains("event_format"s)) {
      result.eventFormat = jo.at("event_format"s);
    }
    if (jo.contains("presence"s)) {
      result.presence = jo.at("presence"s);
    }
    if (jo.contains("account_data"s)) {
      result.accountData = jo.at("account_data"s);
    }
    if (jo.contains("room"s)) {
      result.room = jo.at("room"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
