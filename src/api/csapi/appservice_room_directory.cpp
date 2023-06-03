/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "appservice_room_directory.hpp"

namespace Kazv::Api
{

  
BaseJob::Query UpdateAppserviceRoomDirectoryVsibilityJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body UpdateAppserviceRoomDirectoryVsibilityJob::buildBody(std::string networkId, std::string roomId, std::string visibility)
      {
      // ignore unused param
      (void)(networkId);(void)(roomId);(void)(visibility);
      
        json _data
        ;
        
            _data["visibility"s] = visibility;
          
        return BaseJob::JsonBody(_data);
        

      };

      

UpdateAppserviceRoomDirectoryVsibilityJob::UpdateAppserviceRoomDirectoryVsibilityJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string networkId, std::string roomId, std::string visibility
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/directory/list/appservice/" + networkId + "/" + roomId,
          PUT,
          std::string("UpdateAppserviceRoomDirectoryVsibility"),
          _accessToken,
          ReturnType::Json,
            buildBody(networkId, roomId, visibility)
              , buildQuery()
                , {}

)
        {
        }

        UpdateAppserviceRoomDirectoryVsibilityJob UpdateAppserviceRoomDirectoryVsibilityJob::withData(JsonWrap j) &&
        {
          auto ret = UpdateAppserviceRoomDirectoryVsibilityJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        UpdateAppserviceRoomDirectoryVsibilityJob UpdateAppserviceRoomDirectoryVsibilityJob::withData(JsonWrap j) const &
        {
          auto ret = UpdateAppserviceRoomDirectoryVsibilityJob(*this);
          ret.attachData(j);
          return ret;
        }

        UpdateAppserviceRoomDirectoryVsibilityJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool UpdateAppserviceRoomDirectoryVsibilityResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
