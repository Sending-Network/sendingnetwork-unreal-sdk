/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "typing.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SetTypingJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetTypingJob::buildBody(std::string userId, std::string roomId, bool typing, std::optional<int> timeout)
      {
      // ignore unused param
      (void)(userId);(void)(roomId);(void)(typing);(void)(timeout);
      
        json _data
        ;
        
            _data["typing"s] = typing;
          
          
            addToJsonIfNeeded(_data, "timeout"s, timeout);
        return BaseJob::JsonBody(_data);
        

      };

      

SetTypingJob::SetTypingJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::string roomId, bool typing, std::optional<int> timeout
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/typing/" + userId,
          PUT,
          std::string("SetTyping"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, roomId, typing, timeout)
              , buildQuery()
                , {}

)
        {
        }

        SetTypingJob SetTypingJob::withData(JsonWrap j) &&
        {
          auto ret = SetTypingJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetTypingJob SetTypingJob::withData(JsonWrap j) const &
        {
          auto ret = SetTypingJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetTypingJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetTypingResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
