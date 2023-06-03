/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {
/// Used by clients to submit authentication information to the interactive-authentication API
struct AuthenticationData
{       

/// The login type that the client is attempting to complete.
    std::string type;

/// The value of the session key given by the node.
    std::optional<std::string> session;

/// Keys dependent on the login type
    immer::map<std::string, JsonWrap> authInfo;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<AuthenticationData> {
  static void to_json(json& jo, const AuthenticationData &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
    addPropertyMapToJson(jo, pod.authInfo);
    jo["type"s] = pod.type;
    
    
    addToJsonIfNeeded(jo, "session"s, pod.session);
  }
  static void from_json(const json &jo, AuthenticationData& result)
  {
  
    if (jo.contains("type"s)) {
      result.type = jo.at("type"s);
    }
    if (jo.contains("session"s)) {
      result.session = jo.at("session"s);
    }
    result.authInfo = jo;
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
