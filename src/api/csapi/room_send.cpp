/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "room_send.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SendMessageJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SendMessageJob::buildBody(std::string roomId, std::string eventType, std::string txnId, JsonWrap body)
      {
      // ignore unused param
      (void)(roomId);(void)(eventType);(void)(txnId);(void)(body);
        return 
          JsonBody(body);
      
          

      };

      

SendMessageJob::SendMessageJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string eventType, std::string txnId, JsonWrap body
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/send/" + eventType + "/" + txnId,
          PUT,
          std::string("SendMessage"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, eventType, txnId, body)
              , buildQuery()
                , {}

)
        {
        }

        SendMessageJob SendMessageJob::withData(JsonWrap j) &&
        {
          auto ret = SendMessageJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SendMessageJob SendMessageJob::withData(JsonWrap j) const &
        {
          auto ret = SendMessageJob(*this);
          ret.attachData(j);
          return ret;
        }

        SendMessageJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SendMessageResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("event_id"s)
          ;
          }


    
    std::string SendMessageResponse::eventId() const
    {
    if (jsonBody().get()
    .contains("event_id"s)) {
    return
    jsonBody().get()["event_id"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }

}
