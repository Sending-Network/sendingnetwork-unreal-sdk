/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {
/// Used by clients to discover node information.
struct nodeInformation
{       

/// The base URL for the node for client-server connections.
    std::string baseUrl;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<nodeInformation> {
  static void to_json(json& jo, const nodeInformation &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["base_url"s] = pod.baseUrl;
    
  }
  static void from_json(const json &jo, nodeInformation& result)
  {
  
    if (jo.contains("base_url"s)) {
      result.baseUrl = jo.at("base_url"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
