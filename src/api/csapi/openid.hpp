/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/openid_token.hpp"

namespace Kazv::Api {

/*! \brief Get an OpenID token object to verify the requester's identity.
 *
 * Gets an OpenID token object that the requester may supply to another
 * service to verify their identity in SDN. The generated token is only
 * valid for exchanging for user information from the federation API for
 * OpenID.
 * 
 * The access token generated is only valid for the OpenID API. It cannot
 * be used to request another OpenID access token or call ``/sync``, for
 * example.
 */
class RequestOpenIdTokenJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// OpenID token information. This response is nearly compatible with the
/// response documented in the `OpenID Connect 1.0 Specification <http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse>`_
/// with the only difference being the lack of an ``id_token``. Instead,
/// the SDN node's name is provided.
    
    OpenidToken data() const
    {
    return
      std::move(jsonBody().get()).get<OpenidToken>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get an OpenID token object to verify the requester's identity.
 *
    * \param userId
    *   The user to request and OpenID token for. Should be the user who
    *   is authenticated for the request.
    * 
    * \param body
    *   An empty object. Reserved for future expansion.
    */
    explicit RequestOpenIdTokenJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , JsonWrap body  = {}
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId, JsonWrap body);

        

        

      RequestOpenIdTokenJob withData(JsonWrap j) &&;
      RequestOpenIdTokenJob withData(JsonWrap j) const &;
      };
      using RequestOpenIdTokenResponse = RequestOpenIdTokenJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
