/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "inviting.hpp"

namespace Kazv::Api
{

  
BaseJob::Query InviteUserJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body InviteUserJob::buildBody(std::string roomId, std::string userId)
      {
      // ignore unused param
      (void)(roomId);(void)(userId);
      
        json _data
        ;
        
            _data["user_id"s] = userId;
          
        return BaseJob::JsonBody(_data);
        

      };

      

InviteUserJob::InviteUserJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string userId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/invite",
          POST,
          std::string("InviteUser"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, userId)
              , buildQuery()
                , {}

)
        {
        }

        InviteUserJob InviteUserJob::withData(JsonWrap j) &&
        {
          auto ret = InviteUserJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        InviteUserJob InviteUserJob::withData(JsonWrap j) const &
        {
          auto ret = InviteUserJob(*this);
          ret.attachData(j);
          return ret;
        }

        InviteUserJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool InviteUserResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
