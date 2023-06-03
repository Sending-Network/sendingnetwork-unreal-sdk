/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Send a receipt for the given event ID.
 *
 * This API updates the marker for the given receipt type to the event ID
 * specified.
 */
class PostReceiptJob : public BaseJob {
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

  /*! \brief Send a receipt for the given event ID.
 *
    * \param roomId
    *   The room in which to send the event.
    * 
    * \param receiptType
    *   The type of receipt to send.
    * 
    * \param eventId
    *   The event ID to acknowledge up to.
    * 
    * \param receipt
    *   Extra receipt information to attach to ``content`` if any. The
    *   server will automatically set the ``ts`` field.
    */
    explicit PostReceiptJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string receiptType , std::string eventId , JsonWrap receipt  = {}
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::string receiptType, std::string eventId, JsonWrap receipt);

        

        

      PostReceiptJob withData(JsonWrap j) &&;
      PostReceiptJob withData(JsonWrap j) const &;
      };
      using PostReceiptResponse = PostReceiptJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
