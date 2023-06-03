/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Obtain TURN server credentials.
 *
 * This API provides credentials for the client to use when initiating
 * calls.
 */
class GetTurnServerJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// The TURN server credentials.
    
    JsonWrap data() const
    {
    return
      std::move(jsonBody().get()).get<JsonWrap>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

    /// Obtain TURN server credentials.
    explicit GetTurnServerJob(std::string serverUrl
    , std::string _accessToken
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      GetTurnServerJob withData(JsonWrap j) &&;
      GetTurnServerJob withData(JsonWrap j) const &;
      };
      using GetTurnServerResponse = GetTurnServerJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
