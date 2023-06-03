/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Invalidates a user access token
 *
 * Invalidates an existing access token, so that it can no longer be used for
 * authorization. The device associated with the access token is also deleted.
 * `Device keys <#device-keys>`_ for the device are deleted alongside the device.
 */
class LogoutJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

    /// Invalidates a user access token
    explicit LogoutJob(std::string serverUrl
    , std::string _accessToken
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      LogoutJob withData(JsonWrap j) &&;
      LogoutJob withData(JsonWrap j) const &;
      };
      using LogoutResponse = LogoutJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Invalidates all access tokens for a user
 *
 * Invalidates all access tokens for a user, so that they can no longer be used for
 * authorization. This includes the access token that made this request. All devices
 * for the user are also deleted. `Device keys <#device-keys>`_ for the device are
 * deleted alongside the device.
 * 
 * This endpoint does not use the `User-Interactive Authentication API`_ because
 * User-Interactive Authentication is designed to protect against attacks where the
 * someone gets hold of a single access token then takes over the account. This
 * endpoint invalidates all access tokens for the user, including the token used in
 * the request, and therefore the attacker is unable to take over the account in
 * this way.
 */
class LogoutAllJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

    /// Invalidates all access tokens for a user
    explicit LogoutAllJob(std::string serverUrl
    , std::string _accessToken
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      LogoutAllJob withData(JsonWrap j) &&;
      LogoutAllJob withData(JsonWrap j) const &;
      };
      using LogoutAllResponse = LogoutAllJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
