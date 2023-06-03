/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "directory.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SetRoomAliasJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetRoomAliasJob::buildBody(std::string roomAlias, std::string roomId)
      {
      // ignore unused param
      (void)(roomAlias);(void)(roomId);
      
        json _data
        ;
        
            _data["room_id"s] = roomId;
          
        return BaseJob::JsonBody(_data);
        

      };

      

SetRoomAliasJob::SetRoomAliasJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomAlias, std::string roomId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/directory/room/" + roomAlias,
          PUT,
          std::string("SetRoomAlias"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomAlias, roomId)
              , buildQuery()
                , {}

)
        {
        }

        SetRoomAliasJob SetRoomAliasJob::withData(JsonWrap j) &&
        {
          auto ret = SetRoomAliasJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetRoomAliasJob SetRoomAliasJob::withData(JsonWrap j) const &
        {
          auto ret = SetRoomAliasJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetRoomAliasJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetRoomAliasResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetRoomIdByAliasJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetRoomIdByAliasJob::buildBody(std::string roomAlias)
      {
      // ignore unused param
      (void)(roomAlias);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetRoomIdByAliasJob::GetRoomIdByAliasJob(
        std::string serverUrl
        
            ,
        std::string roomAlias
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/directory/room/" + roomAlias,
          GET,
          std::string("GetRoomIdByAlias"),
           {} ,
          ReturnType::Json,
            buildBody(roomAlias)
              , buildQuery()
                , {}

)
        {
        }

        GetRoomIdByAliasJob GetRoomIdByAliasJob::withData(JsonWrap j) &&
        {
          auto ret = GetRoomIdByAliasJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetRoomIdByAliasJob GetRoomIdByAliasJob::withData(JsonWrap j) const &
        {
          auto ret = GetRoomIdByAliasJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetRoomIdByAliasJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetRoomIdByAliasResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> GetRoomIdByAliasResponse::roomId() const
    {
    if (jsonBody().get()
    .contains("room_id"s)) {
    return
    jsonBody().get()["room_id"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    immer::array<std::string> GetRoomIdByAliasResponse::servers() const
    {
    if (jsonBody().get()
    .contains("servers"s)) {
    return
    jsonBody().get()["servers"s]
    .template get<immer::array<std::string>>();}
    else { return immer::array<std::string>(  );}
    }


  
BaseJob::Query DeleteRoomAliasJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body DeleteRoomAliasJob::buildBody(std::string roomAlias)
      {
      // ignore unused param
      (void)(roomAlias);
      
      
              return BaseJob::EmptyBody{};

      };

      

DeleteRoomAliasJob::DeleteRoomAliasJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomAlias
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/directory/room/" + roomAlias,
          DELETE,
          std::string("DeleteRoomAlias"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomAlias)
              , buildQuery()
                , {}

)
        {
        }

        DeleteRoomAliasJob DeleteRoomAliasJob::withData(JsonWrap j) &&
        {
          auto ret = DeleteRoomAliasJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        DeleteRoomAliasJob DeleteRoomAliasJob::withData(JsonWrap j) const &
        {
          auto ret = DeleteRoomAliasJob(*this);
          ret.attachData(j);
          return ret;
        }

        DeleteRoomAliasJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool DeleteRoomAliasResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetLocalAliasesJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetLocalAliasesJob::buildBody(std::string roomId)
      {
      // ignore unused param
      (void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetLocalAliasesJob::GetLocalAliasesJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/aliases",
          GET,
          std::string("GetLocalAliases"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId)
              , buildQuery()
                , {}

)
        {
        }

        GetLocalAliasesJob GetLocalAliasesJob::withData(JsonWrap j) &&
        {
          auto ret = GetLocalAliasesJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetLocalAliasesJob GetLocalAliasesJob::withData(JsonWrap j) const &
        {
          auto ret = GetLocalAliasesJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetLocalAliasesJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetLocalAliasesResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("aliases"s)
          ;
          }


    
    immer::array<std::string> GetLocalAliasesResponse::aliases() const
    {
    if (jsonBody().get()
    .contains("aliases"s)) {
    return
    jsonBody().get()["aliases"s]
    .template get<immer::array<std::string>>();}
    else { return immer::array<std::string>(  );}
    }

}
