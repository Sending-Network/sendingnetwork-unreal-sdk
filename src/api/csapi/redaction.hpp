/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Strips all non-integrity-critical information out of an event.
 *
 * Strips all information out of an event which isn't critical to the
 * integrity of the server-side representation of the room.
 * 
 * This cannot be undone.
 * 
 * Users may redact their own events, and any user with a power level
 * greater than or equal to the ``redact`` power level of the room may
 * redact events there.
 */
class RedactEventJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// A unique identifier for the event.
std::optional<std::string> eventId() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Strips all non-integrity-critical information out of an event.
 *
    * \param roomId
    *   The room from which to redact the event.
    * 
    * \param eventId
    *   The ID of the event to redact
    * 
    * \param txnId
    *   The transaction ID for this event. Clients should generate a
    *   unique ID; it will be used by the server to ensure idempotency of requests.
    * 
    * \param reason
    *   The reason for the event being redacted.
    */
    explicit RedactEventJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string eventId , std::string txnId , std::optional<std::string> reason  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::string eventId, std::string txnId, std::optional<std::string> reason);

        

        

      RedactEventJob withData(JsonWrap j) &&;
      RedactEventJob withData(JsonWrap j) const &;
      };
      using RedactEventResponse = RedactEventJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
