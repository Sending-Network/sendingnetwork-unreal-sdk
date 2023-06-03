/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "read_markers.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SetReadMarkerJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetReadMarkerJob::buildBody(std::string roomId, std::string mFullyRead, std::optional<std::string> mRead)
      {
      // ignore unused param
      (void)(roomId);(void)(mFullyRead);(void)(mRead);
      
        json _data
        ;
        
            _data["m.fully_read"s] = mFullyRead;
          
          
            addToJsonIfNeeded(_data, "m.read"s, mRead);
        return BaseJob::JsonBody(_data);
        

      };

      

SetReadMarkerJob::SetReadMarkerJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string mFullyRead, std::optional<std::string> mRead
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/read_markers",
          POST,
          std::string("SetReadMarker"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, mFullyRead, mRead)
              , buildQuery()
                , {}

)
        {
        }

        SetReadMarkerJob SetReadMarkerJob::withData(JsonWrap j) &&
        {
          auto ret = SetReadMarkerJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetReadMarkerJob SetReadMarkerJob::withData(JsonWrap j) const &
        {
          auto ret = SetReadMarkerJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetReadMarkerJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetReadMarkerResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
