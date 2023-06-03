/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {
/// Definition of valid values for a field.
struct FieldType
{       

/// A regular expression for validation of a field's value. This may be relatively
/// coarse to verify the value as the application service providing this protocol
/// may apply additional validation or filtering.
    std::string regexp;

/// An placeholder serving as a valid example of the field value.
    std::string placeholder;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<FieldType> {
  static void to_json(json& jo, const FieldType &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["regexp"s] = pod.regexp;
    
    jo["placeholder"s] = pod.placeholder;
    
  }
  static void from_json(const json &jo, FieldType& result)
  {
  
    if (jo.contains("regexp"s)) {
      result.regexp = jo.at("regexp"s);
    }
    if (jo.contains("placeholder"s)) {
      result.placeholder = jo.at("placeholder"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {

struct ProtocolInstance
{       

/// A human-readable description for the protocol, such as the name.
    std::string desc;

/// An optional content URI representing the protocol. Overrides the one provided
/// at the higher level Protocol object.
    std::optional<std::string> icon;

/// Preset values for ``fields`` the client may use to search by.
    JsonWrap fields;

/// A unique identifier across all instances.
    std::string networkId;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<ProtocolInstance> {
  static void to_json(json& jo, const ProtocolInstance &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["desc"s] = pod.desc;
    
    
    addToJsonIfNeeded(jo, "icon"s, pod.icon);
    jo["fields"s] = pod.fields;
    
    jo["network_id"s] = pod.networkId;
    
  }
  static void from_json(const json &jo, ProtocolInstance& result)
  {
  
    if (jo.contains("desc"s)) {
      result.desc = jo.at("desc"s);
    }
    if (jo.contains("icon"s)) {
      result.icon = jo.at("icon"s);
    }
    if (jo.contains("fields"s)) {
      result.fields = jo.at("fields"s);
    }
    if (jo.contains("network_id"s)) {
      result.networkId = jo.at("network_id"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {

struct ThirdPartyProtocol
{       

/// Fields which may be used to identify a third party user. These should be
/// ordered to suggest the way that entities may be grouped, where higher
/// groupings are ordered first. For example, the name of a network should be
/// searched before the nickname of a user.
    immer::array<std::string> userFields;

/// Fields which may be used to identify a third party location. These should be
/// ordered to suggest the way that entities may be grouped, where higher
/// groupings are ordered first. For example, the name of a network should be
/// searched before the name of a channel.
    immer::array<std::string> locationFields;

/// A content URI representing an icon for the third party protocol.
    std::string icon;

/// The type definitions for the fields defined in the ``user_fields`` and 
/// ``location_fields``. Each entry in those arrays MUST have an entry here. The
/// ``string`` key for this object is field name itself.
/// 
/// May be an empty object if no fields are defined.
    immer::map<std::string, FieldType> fieldTypes;

/// A list of objects representing independent instances of configuration.
/// For example, multiple networks on IRC if multiple are provided by the
/// same application service.
    immer::array<ProtocolInstance> instances;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<ThirdPartyProtocol> {
  static void to_json(json& jo, const ThirdPartyProtocol &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["user_fields"s] = pod.userFields;
    
    jo["location_fields"s] = pod.locationFields;
    
    jo["icon"s] = pod.icon;
    
    jo["field_types"s] = pod.fieldTypes;
    
    jo["instances"s] = pod.instances;
    
  }
  static void from_json(const json &jo, ThirdPartyProtocol& result)
  {
  
    if (jo.contains("user_fields"s)) {
      result.userFields = jo.at("user_fields"s);
    }
    if (jo.contains("location_fields"s)) {
      result.locationFields = jo.at("location_fields"s);
    }
    if (jo.contains("icon"s)) {
      result.icon = jo.at("icon"s);
    }
    if (jo.contains("field_types"s)) {
      result.fieldTypes = jo.at("field_types"s);
    }
    if (jo.contains("instances"s)) {
      result.instances = jo.at("instances"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
