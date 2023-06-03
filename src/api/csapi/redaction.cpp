/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "redaction.hpp"

namespace Kazv::Api
{

  
BaseJob::Query RedactEventJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body RedactEventJob::buildBody(std::string roomId, std::string eventId, std::string txnId, std::optional<std::string> reason)
      {
      // ignore unused param
      (void)(roomId);(void)(eventId);(void)(txnId);(void)(reason);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "reason"s, reason);
        return BaseJob::JsonBody(_data);
        

      };

      

RedactEventJob::RedactEventJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string eventId, std::string txnId, std::optional<std::string> reason
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/redact/" + eventId + "/" + txnId,
          PUT,
          std::string("RedactEvent"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, eventId, txnId, reason)
              , buildQuery()
                , {}

)
        {
        }

        RedactEventJob RedactEventJob::withData(JsonWrap j) &&
        {
          auto ret = RedactEventJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RedactEventJob RedactEventJob::withData(JsonWrap j) const &
        {
          auto ret = RedactEventJob(*this);
          ret.attachData(j);
          return ret;
        }

        RedactEventJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool RedactEventResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> RedactEventResponse::eventId() const
    {
    if (jsonBody().get()
    .contains("event_id"s)) {
    return
    jsonBody().get()["event_id"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

}
