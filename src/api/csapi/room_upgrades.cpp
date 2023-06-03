/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "room_upgrades.hpp"

namespace Kazv::Api
{

  
BaseJob::Query UpgradeRoomJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body UpgradeRoomJob::buildBody(std::string roomId, std::string newVersion)
      {
      // ignore unused param
      (void)(roomId);(void)(newVersion);
      
        json _data
        ;
        
            _data["new_version"s] = newVersion;
          
        return BaseJob::JsonBody(_data);
        

      };

      

UpgradeRoomJob::UpgradeRoomJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string newVersion
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/upgrade",
          POST,
          std::string("UpgradeRoom"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, newVersion)
              , buildQuery()
                , {}

)
        {
        }

        UpgradeRoomJob UpgradeRoomJob::withData(JsonWrap j) &&
        {
          auto ret = UpgradeRoomJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        UpgradeRoomJob UpgradeRoomJob::withData(JsonWrap j) const &
        {
          auto ret = UpgradeRoomJob(*this);
          ret.attachData(j);
          return ret;
        }

        UpgradeRoomJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool UpgradeRoomResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("replacement_room"s)
          ;
          }


    
    std::string UpgradeRoomResponse::replacementRoom() const
    {
    if (jsonBody().get()
    .contains("replacement_room"s)) {
    return
    jsonBody().get()["replacement_room"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }

}
