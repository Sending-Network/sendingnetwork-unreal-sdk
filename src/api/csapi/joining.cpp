/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "joining.hpp"

namespace Kazv::Api
{

  
BaseJob::Query JoinRoomByIdJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body JoinRoomByIdJob::buildBody(std::string roomId, std::optional<ThirdPartySigned> thirdPartySigned)
      {
      // ignore unused param
      (void)(roomId);(void)(thirdPartySigned);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "third_party_signed"s, thirdPartySigned);
        return BaseJob::JsonBody(_data);
        

      };

      

JoinRoomByIdJob::JoinRoomByIdJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::optional<ThirdPartySigned> thirdPartySigned
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/join",
          POST,
          std::string("JoinRoomById"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, thirdPartySigned)
              , buildQuery()
                , {}

)
        {
        }

        JoinRoomByIdJob JoinRoomByIdJob::withData(JsonWrap j) &&
        {
          auto ret = JoinRoomByIdJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        JoinRoomByIdJob JoinRoomByIdJob::withData(JsonWrap j) const &
        {
          auto ret = JoinRoomByIdJob(*this);
          ret.attachData(j);
          return ret;
        }

        JoinRoomByIdJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool JoinRoomByIdResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("room_id"s)
          ;
          }


    
    std::string JoinRoomByIdResponse::roomId() const
    {
    if (jsonBody().get()
    .contains("room_id"s)) {
    return
    jsonBody().get()["room_id"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }


  
BaseJob::Query JoinRoomJob::buildQuery(
immer::array<std::string> serverName)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "server_name"s, serverName);
return _q;
}

    BaseJob::Body JoinRoomJob::buildBody(std::string roomIdOrAlias, immer::array<std::string> serverName, std::optional<ThirdPartySigned> thirdPartySigned)
      {
      // ignore unused param
      (void)(roomIdOrAlias);(void)(serverName);(void)(thirdPartySigned);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "third_party_signed"s, thirdPartySigned);
        return BaseJob::JsonBody(_data);
        

      };

      

JoinRoomJob::JoinRoomJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomIdOrAlias, immer::array<std::string> serverName, std::optional<ThirdPartySigned> thirdPartySigned
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/join/" + roomIdOrAlias,
          POST,
          std::string("JoinRoom"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomIdOrAlias, serverName, thirdPartySigned)
              , buildQuery(serverName)
                , {}

)
        {
        }

        JoinRoomJob JoinRoomJob::withData(JsonWrap j) &&
        {
          auto ret = JoinRoomJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        JoinRoomJob JoinRoomJob::withData(JsonWrap j) const &
        {
          auto ret = JoinRoomJob(*this);
          ret.attachData(j);
          return ret;
        }

        JoinRoomJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool JoinRoomResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("room_id"s)
          ;
          }


    
    std::string JoinRoomResponse::roomId() const
    {
    if (jsonBody().get()
    .contains("room_id"s)) {
    return
    jsonBody().get()["room_id"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }

}
