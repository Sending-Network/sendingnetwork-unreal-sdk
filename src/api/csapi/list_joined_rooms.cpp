/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "list_joined_rooms.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetJoinedRoomsJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetJoinedRoomsJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetJoinedRoomsJob::GetJoinedRoomsJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/joined_rooms",
          GET,
          std::string("GetJoinedRooms"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetJoinedRoomsJob GetJoinedRoomsJob::withData(JsonWrap j) &&
        {
          auto ret = GetJoinedRoomsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetJoinedRoomsJob GetJoinedRoomsJob::withData(JsonWrap j) const &
        {
          auto ret = GetJoinedRoomsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetJoinedRoomsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetJoinedRoomsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("joined_rooms"s)
          ;
          }


    
    immer::array<std::string> GetJoinedRoomsResponse::joinedRooms() const
    {
    if (jsonBody().get()
    .contains("joined_rooms"s)) {
    return
    jsonBody().get()["joined_rooms"s]
    .template get<immer::array<std::string>>();}
    else { return immer::array<std::string>(  );}
    }

}
