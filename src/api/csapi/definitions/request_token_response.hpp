/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {

struct RequestTokenResponse
{       

/// The session ID. Session IDs are opaque strings that must consist entirely
/// of the characters ``[0-9a-zA-Z.=_-]``. Their length must not exceed 255
/// characters and they must not be empty.
    std::string sid;

/// An optional field containing a URL where the client must submit the
/// validation token to, with identical parameters to the Identity Service
/// API's ``POST /validate/email/submitToken`` endpoint (without the requirement
/// for an access token). The node must send this token to the user (if
/// applicable), who should then be prompted to provide it to the client.
/// 
/// If this field is not present, the client can assume that verification
/// will happen without the client's involvement provided the node
/// advertises this specification version in the ``/versions`` response
/// (ie: r0.5.0).
    std::optional<std::string> submitUrl;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<RequestTokenResponse> {
  static void to_json(json& jo, const RequestTokenResponse &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["sid"s] = pod.sid;
    
    
    addToJsonIfNeeded(jo, "submit_url"s, pod.submitUrl);
  }
  static void from_json(const json &jo, RequestTokenResponse& result)
  {
  
    if (jo.contains("sid"s)) {
      result.sid = jo.at("sid"s);
    }
    if (jo.contains("submit_url"s)) {
      result.submitUrl = jo.at("submit_url"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
