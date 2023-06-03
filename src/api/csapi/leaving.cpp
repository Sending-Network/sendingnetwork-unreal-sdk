/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "leaving.hpp"

namespace Kazv::Api
{

  
BaseJob::Query LeaveRoomJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body LeaveRoomJob::buildBody(std::string roomId)
      {
      // ignore unused param
      (void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

      

LeaveRoomJob::LeaveRoomJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/leave",
          POST,
          std::string("LeaveRoom"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId)
              , buildQuery()
                , {}

)
        {
        }

        LeaveRoomJob LeaveRoomJob::withData(JsonWrap j) &&
        {
          auto ret = LeaveRoomJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        LeaveRoomJob LeaveRoomJob::withData(JsonWrap j) const &
        {
          auto ret = LeaveRoomJob(*this);
          ret.attachData(j);
          return ret;
        }

        LeaveRoomJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool LeaveRoomResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query ForgetRoomJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body ForgetRoomJob::buildBody(std::string roomId)
      {
      // ignore unused param
      (void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

      

ForgetRoomJob::ForgetRoomJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/forget",
          POST,
          std::string("ForgetRoom"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId)
              , buildQuery()
                , {}

)
        {
        }

        ForgetRoomJob ForgetRoomJob::withData(JsonWrap j) &&
        {
          auto ret = ForgetRoomJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        ForgetRoomJob ForgetRoomJob::withData(JsonWrap j) const &
        {
          auto ret = ForgetRoomJob(*this);
          ret.attachData(j);
          return ret;
        }

        ForgetRoomJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool ForgetRoomResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
