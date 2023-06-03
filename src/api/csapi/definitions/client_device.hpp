/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {
/// A client device
struct Device
{       

/// Identifier of this device.
    std::string deviceId;

/// Display name set by the user for this device. Absent if no name has been
/// set.
    std::optional<std::string> displayName;

/// The IP address where this device was last seen. (May be a few minutes out
/// of date, for efficiency reasons).
    std::optional<std::string> lastSeenIp;

/// The timestamp (in milliseconds since the unix epoch) when this devices
/// was last seen. (May be a few minutes out of date, for efficiency
/// reasons).
    std::optional<std::int_fast64_t> lastSeenTs;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<Device> {
  static void to_json(json& jo, const Device &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["device_id"s] = pod.deviceId;
    
    
    addToJsonIfNeeded(jo, "display_name"s, pod.displayName);
    
    addToJsonIfNeeded(jo, "last_seen_ip"s, pod.lastSeenIp);
    
    addToJsonIfNeeded(jo, "last_seen_ts"s, pod.lastSeenTs);
  }
  static void from_json(const json &jo, Device& result)
  {
  
    if (jo.contains("device_id"s)) {
      result.deviceId = jo.at("device_id"s);
    }
    if (jo.contains("display_name"s)) {
      result.displayName = jo.at("display_name"s);
    }
    if (jo.contains("last_seen_ip"s)) {
      result.lastSeenIp = jo.at("last_seen_ip"s);
    }
    if (jo.contains("last_seen_ts"s)) {
      result.lastSeenTs = jo.at("last_seen_ts"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
