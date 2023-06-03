/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {
/// A signature of an ``m.third_party_invite`` token to prove that this user
/// owns a third party identity which has been invited to the room.
struct ThirdPartySigned
{       

/// The SDN ID of the user who issued the invite.
    std::string sender;

/// The SDN ID of the invitee.
    std::string mxid;

/// The state key of the m.third_party_invite event.
    std::string token;

/// A signatures object containing a signature of the entire signed object.
    immer::map<std::string, immer::map<std::string, std::string>> signatures;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<ThirdPartySigned> {
  static void to_json(json& jo, const ThirdPartySigned &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["sender"s] = pod.sender;
    
    jo["mxid"s] = pod.mxid;
    
    jo["token"s] = pod.token;
    
    jo["signatures"s] = pod.signatures;
    
  }
  static void from_json(const json &jo, ThirdPartySigned& result)
  {
  
    if (jo.contains("sender"s)) {
      result.sender = jo.at("sender"s);
    }
    if (jo.contains("mxid"s)) {
      result.mxid = jo.at("mxid"s);
    }
    if (jo.contains("token"s)) {
      result.token = jo.at("token"s);
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
