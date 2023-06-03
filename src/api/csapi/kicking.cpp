/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "kicking.hpp"

namespace Kazv::Api
{

  
BaseJob::Query KickJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body KickJob::buildBody(std::string roomId, std::string userId, std::optional<std::string> reason)
      {
      // ignore unused param
      (void)(roomId);(void)(userId);(void)(reason);
      
        json _data
        ;
        
            _data["user_id"s] = userId;
          
          
            addToJsonIfNeeded(_data, "reason"s, reason);
        return BaseJob::JsonBody(_data);
        

      };

      

KickJob::KickJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string userId, std::optional<std::string> reason
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/kick",
          POST,
          std::string("Kick"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, userId, reason)
              , buildQuery()
                , {}

)
        {
        }

        KickJob KickJob::withData(JsonWrap j) &&
        {
          auto ret = KickJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        KickJob KickJob::withData(JsonWrap j) const &
        {
          auto ret = KickJob(*this);
          ret.attachData(j);
          return ret;
        }

        KickJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool KickResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
