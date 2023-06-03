/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"
#include "csapi/definitions/../../identity/definitions/request_email_validation.hpp"

namespace Kazv::Api {

struct EmailValidationData : RequestEmailValidation
{       

/// The hostname of the identity server to communicate with. May optionally
/// include a port. This parameter is ignored when the node handles
/// 3PID verification.
/// 
/// This parameter is deprecated with a plan to be removed in a future specification
/// version for ``/account/password`` and ``/register`` requests.
    std::optional<std::string> idServer;

/// An access token previously registered with the identity server. Servers
/// can treat this as optional to distinguish between r0.5-compatible clients
/// and this specification version.
/// 
/// Required if an ``id_server`` is supplied.
    std::optional<std::string> idAccessToken;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<EmailValidationData> {
  static void to_json(json& jo, const EmailValidationData &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
    jo = static_cast<const RequestEmailValidation &>(pod);
  
    
    addToJsonIfNeeded(jo, "id_server"s, pod.idServer);
    
    addToJsonIfNeeded(jo, "id_access_token"s, pod.idAccessToken);
  }
  static void from_json(const json &jo, EmailValidationData& result)
  {
    static_cast<RequestEmailValidation &>(result) = jo;
    if (jo.contains("id_server"s)) {
      result.idServer = jo.at("id_server"s);
    }
    if (jo.contains("id_access_token"s)) {
      result.idAccessToken = jo.at("id_access_token"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
