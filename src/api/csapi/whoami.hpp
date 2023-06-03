/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Gets information about the owner of an access token.
 *
 * Gets information about the owner of a given access token. 
 * 
 * Note that, as with the rest of the Client-Server API, 
 * Application Services may masquerade as users within their 
 * namespace by giving a ``user_id`` query parameter. In this 
 * situation, the server should verify that the given ``user_id``
 * is registered by the appservice, and return it in the response 
 * body.
 */
class GetTokenOwnerJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The user id that owns the access token.
std::string userId() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

    /// Gets information about the owner of an access token.
    explicit GetTokenOwnerJob(std::string serverUrl
    , std::string _accessToken
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      GetTokenOwnerJob withData(JsonWrap j) &&;
      GetTokenOwnerJob withData(JsonWrap j) const &;
      };
      using GetTokenOwnerResponse = GetTokenOwnerJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
