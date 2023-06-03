/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"
#include "csapi/definitions/wellknown/identity_server.hpp"
#include "csapi/definitions/wellknown/node.hpp"

namespace Kazv::Api {
/// Used by clients to determine the node, identity server, and other
/// optional components they should be interacting with.
struct DiscoveryInformation
{       

/// Used by clients to determine the node, identity server, and other
/// optional components they should be interacting with.
    nodeInformation node;

/// Used by clients to determine the node, identity server, and other
/// optional components they should be interacting with.
    std::optional<IdentityServerInformation> identityServer;

/// Application-dependent keys using Java package naming convention.
    immer::map<std::string, JsonWrap> additionalProperties;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<DiscoveryInformation> {
  static void to_json(json& jo, const DiscoveryInformation &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
    addPropertyMapToJson(jo, pod.additionalProperties);
    jo["m.node"s] = pod.node;
    
    
    addToJsonIfNeeded(jo, "m.identity_server"s, pod.identityServer);
  }
  static void from_json(const json &jo, DiscoveryInformation& result)
  {
  
    if (jo.contains("m.node"s)) {
      result.node = jo.at("m.node"s);
    }
    if (jo.contains("m.identity_server"s)) {
      result.identityServer = jo.at("m.identity_server"s);
    }
    result.additionalProperties = jo;
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
