/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "rooms.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetOneRoomEventJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetOneRoomEventJob::buildBody(std::string roomId, std::string eventId)
      {
      // ignore unused param
      (void)(roomId);(void)(eventId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetOneRoomEventJob::GetOneRoomEventJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string eventId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/event/" + eventId,
          GET,
          std::string("GetOneRoomEvent"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, eventId)
              , buildQuery()
                , {}

)
        {
        }

        GetOneRoomEventJob GetOneRoomEventJob::withData(JsonWrap j) &&
        {
          auto ret = GetOneRoomEventJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetOneRoomEventJob GetOneRoomEventJob::withData(JsonWrap j) const &
        {
          auto ret = GetOneRoomEventJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetOneRoomEventJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetOneRoomEventResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetRoomStateWithKeyJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetRoomStateWithKeyJob::buildBody(std::string roomId, std::string eventType, std::string stateKey)
      {
      // ignore unused param
      (void)(roomId);(void)(eventType);(void)(stateKey);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetRoomStateWithKeyJob::GetRoomStateWithKeyJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string eventType, std::string stateKey
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/state/" + eventType + "/" + stateKey,
          GET,
          std::string("GetRoomStateWithKey"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, eventType, stateKey)
              , buildQuery()
                , {}

)
        {
        }

        GetRoomStateWithKeyJob GetRoomStateWithKeyJob::withData(JsonWrap j) &&
        {
          auto ret = GetRoomStateWithKeyJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetRoomStateWithKeyJob GetRoomStateWithKeyJob::withData(JsonWrap j) const &
        {
          auto ret = GetRoomStateWithKeyJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetRoomStateWithKeyJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetRoomStateWithKeyResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetRoomStateJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetRoomStateJob::buildBody(std::string roomId)
      {
      // ignore unused param
      (void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetRoomStateJob::GetRoomStateJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/state",
          GET,
          std::string("GetRoomState"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId)
              , buildQuery()
                , {}

)
        {
        }

        GetRoomStateJob GetRoomStateJob::withData(JsonWrap j) &&
        {
          auto ret = GetRoomStateJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetRoomStateJob GetRoomStateJob::withData(JsonWrap j) const &
        {
          auto ret = GetRoomStateJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetRoomStateJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetRoomStateResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetMembersByRoomJob::buildQuery(
std::optional<std::string> at, std::optional<std::string> membership, std::optional<std::string> notMembership)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "at"s, at);
  
    addToQueryIfNeeded(_q, "membership"s, membership);
  
    addToQueryIfNeeded(_q, "not_membership"s, notMembership);
return _q;
}

    BaseJob::Body GetMembersByRoomJob::buildBody(std::string roomId, std::optional<std::string> at, std::optional<std::string> membership, std::optional<std::string> notMembership)
      {
      // ignore unused param
      (void)(roomId);(void)(at);(void)(membership);(void)(notMembership);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetMembersByRoomJob::GetMembersByRoomJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::optional<std::string> at, std::optional<std::string> membership, std::optional<std::string> notMembership
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/members",
          GET,
          std::string("GetMembersByRoom"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, at, membership, notMembership)
              , buildQuery(at, membership, notMembership)
                , {}

)
        {
        }

        GetMembersByRoomJob GetMembersByRoomJob::withData(JsonWrap j) &&
        {
          auto ret = GetMembersByRoomJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetMembersByRoomJob GetMembersByRoomJob::withData(JsonWrap j) const &
        {
          auto ret = GetMembersByRoomJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetMembersByRoomJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetMembersByRoomResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    EventList GetMembersByRoomResponse::chunk() const
    {
    if (jsonBody().get()
    .contains("chunk"s)) {
    return
    jsonBody().get()["chunk"s]
    .template get<EventList>();}
    else { return EventList(  );}
    }


  
BaseJob::Query GetJoinedMembersByRoomJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetJoinedMembersByRoomJob::buildBody(std::string roomId)
      {
      // ignore unused param
      (void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetJoinedMembersByRoomJob::GetJoinedMembersByRoomJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/joined_members",
          GET,
          std::string("GetJoinedMembersByRoom"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId)
              , buildQuery()
                , {}

)
        {
        }

        GetJoinedMembersByRoomJob GetJoinedMembersByRoomJob::withData(JsonWrap j) &&
        {
          auto ret = GetJoinedMembersByRoomJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetJoinedMembersByRoomJob GetJoinedMembersByRoomJob::withData(JsonWrap j) const &
        {
          auto ret = GetJoinedMembersByRoomJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetJoinedMembersByRoomJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetJoinedMembersByRoomResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    immer::map<std::string, GetJoinedMembersByRoomJob::RoomMember> GetJoinedMembersByRoomResponse::joined() const
    {
    if (jsonBody().get()
    .contains("joined"s)) {
    return
    jsonBody().get()["joined"s]
    .template get<immer::map<std::string, RoomMember>>();}
    else { return immer::map<std::string, RoomMember>(  );}
    }

}
