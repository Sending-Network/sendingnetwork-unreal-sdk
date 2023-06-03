/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {
/// Device identity keys
struct DeviceKeys
{       

/// The ID of the user the device belongs to. Must match the user ID used
/// when logging in.
    std::string userId;

/// The ID of the device these keys belong to. Must match the device ID used
/// when logging in.
    std::string deviceId;

/// The encryption algorithms supported by this device.
    immer::array<std::string> algorithms;

/// Public identity keys. The names of the properties should be in the
/// format ``<algorithm>:<device_id>``. The keys themselves should be
/// encoded as specified by the key algorithm.
    immer::map<std::string, std::string> keys;

/// Signatures for the device key object. A map from user ID, to a map from
/// ``<algorithm>:<device_id>`` to the signature.
/// 
/// The signature is calculated using the process described at `Signing
/// JSON`_.
    immer::map<std::string, immer::map<std::string, std::string>> signatures;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<DeviceKeys> {
  static void to_json(json& jo, const DeviceKeys &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["user_id"s] = pod.userId;
    
    jo["device_id"s] = pod.deviceId;
    
    jo["algorithms"s] = pod.algorithms;
    
    jo["keys"s] = pod.keys;
    
    jo["signatures"s] = pod.signatures;
    
  }
  static void from_json(const json &jo, DeviceKeys& result)
  {
  
    if (jo.contains("user_id"s)) {
      result.userId = jo.at("user_id"s);
    }
    if (jo.contains("device_id"s)) {
      result.deviceId = jo.at("device_id"s);
    }
    if (jo.contains("algorithms"s)) {
      result.algorithms = jo.at("algorithms"s);
    }
    if (jo.contains("keys"s)) {
      result.keys = jo.at("keys"s);
    }
    if (jo.contains("signatures"s)) {
      result.signatures = jo.at("signatures"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
