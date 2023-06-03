/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {

struct ThirdPartyUser
{       

/// A User ID represting a third party user.
    std::string userid;

/// The protocol ID that the third party location is a part of.
    std::string protocol;

/// Information used to identify this third party location.
    JsonWrap fields;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<ThirdPartyUser> {
  static void to_json(json& jo, const ThirdPartyUser &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["userid"s] = pod.userid;
    
    jo["protocol"s] = pod.protocol;
    
    jo["fields"s] = pod.fields;
    
  }
  static void from_json(const json &jo, ThirdPartyUser& result)
  {
  
    if (jo.contains("userid"s)) {
      result.userid = jo.at("userid"s);
    }
    if (jo.contains("protocol"s)) {
      result.protocol = jo.at("protocol"s);
    }
    if (jo.contains("fields"s)) {
      result.fields = jo.at("fields"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
