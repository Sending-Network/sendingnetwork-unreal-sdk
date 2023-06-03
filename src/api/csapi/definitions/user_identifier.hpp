/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {
/// Identification information for a user
struct UserIdentifier
{       

/// The type of identification.  See `Identifier types`_ for supported values and additional property descriptions.
    std::string type;

/// Identification information for a user
    JsonWrap additionalProperties;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<UserIdentifier> {
  static void to_json(json& jo, const UserIdentifier &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
    addPropertyMapToJson(jo, pod.additionalProperties);
    jo["type"s] = pod.type;
    
  }
  static void from_json(const json &jo, UserIdentifier& result)
  {
  
    if (jo.contains("type"s)) {
      result.type = jo.at("type"s);
    }
    result.additionalProperties = jo;
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
