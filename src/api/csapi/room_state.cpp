/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "room_state.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SetRoomStateWithKeyJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetRoomStateWithKeyJob::buildBody(std::string roomId, std::string eventType, std::string stateKey, JsonWrap body)
      {
      // ignore unused param
      (void)(roomId);(void)(eventType);(void)(stateKey);(void)(body);
        return 
          JsonBody(body);
      
          

      };

      

SetRoomStateWithKeyJob::SetRoomStateWithKeyJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string eventType, std::string stateKey, JsonWrap body
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/state/" + eventType + "/" + stateKey,
          PUT,
          std::string("SetRoomStateWithKey"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, eventType, stateKey, body)
              , buildQuery()
                , {}

)
        {
        }

        SetRoomStateWithKeyJob SetRoomStateWithKeyJob::withData(JsonWrap j) &&
        {
          auto ret = SetRoomStateWithKeyJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetRoomStateWithKeyJob SetRoomStateWithKeyJob::withData(JsonWrap j) const &
        {
          auto ret = SetRoomStateWithKeyJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetRoomStateWithKeyJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetRoomStateWithKeyResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("event_id"s)
          ;
          }


    
    std::string SetRoomStateWithKeyResponse::eventId() const
    {
    if (jsonBody().get()
    .contains("event_id"s)) {
    return
    jsonBody().get()["event_id"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }

}
