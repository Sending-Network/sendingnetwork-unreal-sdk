/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/wellknown/full.hpp"
#include "csapi/definitions/user_identifier.hpp"

namespace Kazv::Api {

/*! \brief Get the supported login types to authenticate users
 *
 * Gets the node's supported login types to authenticate users. Clients
 * should pick one of these and supply it as the ``type`` when logging in.
 */
class GetLoginFlowsJob : public BaseJob {
public:
  // Inner data structures

/// Gets the node's supported login types to authenticate users. Clients
/// should pick one of these and supply it as the ``type`` when logging in.
    struct LoginFlow
        {
/// The login type. This is supplied as the ``type`` when
/// logging in.
          std::optional<std::string> type;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The node's supported login types
immer::array<LoginFlow> flows() const;

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

    /// Get the supported login types to authenticate users
    explicit GetLoginFlowsJob(std::string serverUrl
    
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      GetLoginFlowsJob withData(JsonWrap j) &&;
      GetLoginFlowsJob withData(JsonWrap j) const &;
      };
      using GetLoginFlowsResponse = GetLoginFlowsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<GetLoginFlowsJob::LoginFlow> {

  static void to_json(json& jo, const GetLoginFlowsJob::LoginFlow &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "type"s, pod.type);
  }

  static void from_json(const json &jo, GetLoginFlowsJob::LoginFlow& result)
  {
  
    if (jo.contains("type"s)) {
      result.type = jo.at("type"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

/*! \brief Authenticates the user.
 *
 * Authenticates the user, and issues an access token they can
 * use to authorize themself in subsequent requests.
 * 
 * If the client does not supply a ``device_id``, the server must
 * auto-generate one.
 * 
 * The returned access token must be associated with the ``device_id``
 * supplied by the client or generated by the server. The server may
 * invalidate any access token previously associated with that device. See
 * `Relationship between access tokens and devices`_.
 */
class LoginJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The fully-qualified SDN ID for the account.
std::optional<std::string> userId() const;

    
/// An access token for the account.
/// This access token can then be used to authorize other requests.
std::optional<std::string> accessToken() const;

    
/// The server_name of the node on which the account has
/// been registered.
/// 
/// **Deprecated**. Clients should extract the server_name from
/// ``user_id`` (by splitting at the first colon) if they require
/// it. Note also that ``node`` is not spelt this way.
std::optional<std::string> node() const;

    
/// ID of the logged-in device. Will be the same as the
/// corresponding parameter in the request, if one was specified.
std::optional<std::string> deviceId() const;

    
/// Optional client configuration provided by the server. If present,
/// clients SHOULD use the provided object to reconfigure themselves,
/// optionally validating the URLs within. This object takes the same
/// form as the one returned from .well-known autodiscovery.
std::optional<DiscoveryInformation> wellKnown() const;

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Authenticates the user.
 *
    * \param type
    *   The login type being used.
    * 
    * \param identifier
    *   Authenticates the user, and issues an access token they can
    *   use to authorize themself in subsequent requests.
    *   
    *   If the client does not supply a ``device_id``, the server must
    *   auto-generate one.
    *   
    *   The returned access token must be associated with the ``device_id``
    *   supplied by the client or generated by the server. The server may
    *   invalidate any access token previously associated with that device. See
    *   `Relationship between access tokens and devices`_.
    * 
    * \param password
    *   Required when ``type`` is ``m.login.password``. The user's
    *   password.
    * 
    * \param token
    *   Required when ``type`` is ``m.login.token``. Part of `Token-based`_ login.
    * 
    * \param deviceId
    *   ID of the client device. If this does not correspond to a
    *   known client device, a new device will be created. The server
    *   will auto-generate a device_id if this is not specified.
    * 
    * \param initialDeviceDisplayName
    *   A display name to assign to the newly-created device. Ignored
    *   if ``device_id`` corresponds to a known device.
    */
    explicit LoginJob(std::string serverUrl
    
      ,
        std::string type , std::optional<UserIdentifier> identifier  = std::nullopt, std::optional<std::string> password  = std::nullopt, std::optional<std::string> token  = std::nullopt, std::optional<std::string> deviceId  = std::nullopt, std::optional<std::string> initialDeviceDisplayName  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string type, std::optional<UserIdentifier> identifier, std::optional<std::string> password, std::optional<std::string> token, std::optional<std::string> deviceId, std::optional<std::string> initialDeviceDisplayName);

        

        

      LoginJob withData(JsonWrap j) &&;
      LoginJob withData(JsonWrap j) const &;
      };
      using LoginResponse = LoginJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
