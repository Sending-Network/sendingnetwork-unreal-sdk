/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "list_public_rooms.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetRoomVisibilityOnDirectoryJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetRoomVisibilityOnDirectoryJob::buildBody(std::string roomId)
      {
      // ignore unused param
      (void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetRoomVisibilityOnDirectoryJob::GetRoomVisibilityOnDirectoryJob(
        std::string serverUrl
        
            ,
        std::string roomId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/directory/list/room/" + roomId,
          GET,
          std::string("GetRoomVisibilityOnDirectory"),
           {} ,
          ReturnType::Json,
            buildBody(roomId)
              , buildQuery()
                , {}

)
        {
        }

        GetRoomVisibilityOnDirectoryJob GetRoomVisibilityOnDirectoryJob::withData(JsonWrap j) &&
        {
          auto ret = GetRoomVisibilityOnDirectoryJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetRoomVisibilityOnDirectoryJob GetRoomVisibilityOnDirectoryJob::withData(JsonWrap j) const &
        {
          auto ret = GetRoomVisibilityOnDirectoryJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetRoomVisibilityOnDirectoryJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetRoomVisibilityOnDirectoryResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> GetRoomVisibilityOnDirectoryResponse::visibility() const
    {
    if (jsonBody().get()
    .contains("visibility"s)) {
    return
    jsonBody().get()["visibility"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }


  
BaseJob::Query SetRoomVisibilityOnDirectoryJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetRoomVisibilityOnDirectoryJob::buildBody(std::string roomId, std::optional<std::string> visibility)
      {
      // ignore unused param
      (void)(roomId);(void)(visibility);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "visibility"s, visibility);
        return BaseJob::JsonBody(_data);
        

      };

      

SetRoomVisibilityOnDirectoryJob::SetRoomVisibilityOnDirectoryJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::optional<std::string> visibility
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/directory/list/room/" + roomId,
          PUT,
          std::string("SetRoomVisibilityOnDirectory"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, visibility)
              , buildQuery()
                , {}

)
        {
        }

        SetRoomVisibilityOnDirectoryJob SetRoomVisibilityOnDirectoryJob::withData(JsonWrap j) &&
        {
          auto ret = SetRoomVisibilityOnDirectoryJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetRoomVisibilityOnDirectoryJob SetRoomVisibilityOnDirectoryJob::withData(JsonWrap j) const &
        {
          auto ret = SetRoomVisibilityOnDirectoryJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetRoomVisibilityOnDirectoryJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetRoomVisibilityOnDirectoryResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetPublicRoomsJob::buildQuery(
std::optional<int> limit, std::optional<std::string> since, std::optional<std::string> server)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "limit"s, limit);
  
    addToQueryIfNeeded(_q, "since"s, since);
  
    addToQueryIfNeeded(_q, "server"s, server);
return _q;
}

    BaseJob::Body GetPublicRoomsJob::buildBody(std::optional<int> limit, std::optional<std::string> since, std::optional<std::string> server)
      {
      // ignore unused param
      (void)(limit);(void)(since);(void)(server);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetPublicRoomsJob::GetPublicRoomsJob(
        std::string serverUrl
        
            ,
        std::optional<int> limit, std::optional<std::string> since, std::optional<std::string> server
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/publicRooms",
          GET,
          std::string("GetPublicRooms"),
           {} ,
          ReturnType::Json,
            buildBody(limit, since, server)
              , buildQuery(limit, since, server)
                , {}

)
        {
        }

        GetPublicRoomsJob GetPublicRoomsJob::withData(JsonWrap j) &&
        {
          auto ret = GetPublicRoomsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetPublicRoomsJob GetPublicRoomsJob::withData(JsonWrap j) const &
        {
          auto ret = GetPublicRoomsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetPublicRoomsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetPublicRoomsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("chunk"s)
          ;
          }


    
    immer::array<PublicRoomsChunk> GetPublicRoomsResponse::chunk() const
    {
    if (jsonBody().get()
    .contains("chunk"s)) {
    return
    jsonBody().get()["chunk"s]
    .template get<immer::array<PublicRoomsChunk>>();}
    else { return immer::array<PublicRoomsChunk>(  );}
    }

    
    std::optional<std::string> GetPublicRoomsResponse::nextBatch() const
    {
    if (jsonBody().get()
    .contains("next_batch"s)) {
    return
    jsonBody().get()["next_batch"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> GetPublicRoomsResponse::prevBatch() const
    {
    if (jsonBody().get()
    .contains("prev_batch"s)) {
    return
    jsonBody().get()["prev_batch"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<int> GetPublicRoomsResponse::totalRoomCountEstimate() const
    {
    if (jsonBody().get()
    .contains("total_room_count_estimate"s)) {
    return
    jsonBody().get()["total_room_count_estimate"s]
    .template get<int>();}
    else { return std::optional<int>(  );}
    }


  
BaseJob::Query QueryPublicRoomsJob::buildQuery(
std::optional<std::string> server)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "server"s, server);
return _q;
}

    BaseJob::Body QueryPublicRoomsJob::buildBody(std::optional<std::string> server, std::optional<int> limit, std::optional<std::string> since, std::optional<Filter> filter, std::optional<bool> includeAllNetworks, std::optional<std::string> thirdPartyInstanceId)
      {
      // ignore unused param
      (void)(server);(void)(limit);(void)(since);(void)(filter);(void)(includeAllNetworks);(void)(thirdPartyInstanceId);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "limit"s, limit);
          
            addToJsonIfNeeded(_data, "since"s, since);
          
            addToJsonIfNeeded(_data, "filter"s, filter);
          
            addToJsonIfNeeded(_data, "include_all_networks"s, includeAllNetworks);
          
            addToJsonIfNeeded(_data, "third_party_instance_id"s, thirdPartyInstanceId);
        return BaseJob::JsonBody(_data);
        

      };

      

QueryPublicRoomsJob::QueryPublicRoomsJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::optional<std::string> server, std::optional<int> limit, std::optional<std::string> since, std::optional<Filter> filter, std::optional<bool> includeAllNetworks, std::optional<std::string> thirdPartyInstanceId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/publicRooms",
          POST,
          std::string("QueryPublicRooms"),
          _accessToken,
          ReturnType::Json,
            buildBody(server, limit, since, filter, includeAllNetworks, thirdPartyInstanceId)
              , buildQuery(server)
                , {}

)
        {
        }

        QueryPublicRoomsJob QueryPublicRoomsJob::withData(JsonWrap j) &&
        {
          auto ret = QueryPublicRoomsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        QueryPublicRoomsJob QueryPublicRoomsJob::withData(JsonWrap j) const &
        {
          auto ret = QueryPublicRoomsJob(*this);
          ret.attachData(j);
          return ret;
        }

        QueryPublicRoomsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool QueryPublicRoomsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("chunk"s)
          ;
          }


    
    immer::array<PublicRoomsChunk> QueryPublicRoomsResponse::chunk() const
    {
    if (jsonBody().get()
    .contains("chunk"s)) {
    return
    jsonBody().get()["chunk"s]
    .template get<immer::array<PublicRoomsChunk>>();}
    else { return immer::array<PublicRoomsChunk>(  );}
    }

    
    std::optional<std::string> QueryPublicRoomsResponse::nextBatch() const
    {
    if (jsonBody().get()
    .contains("next_batch"s)) {
    return
    jsonBody().get()["next_batch"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> QueryPublicRoomsResponse::prevBatch() const
    {
    if (jsonBody().get()
    .contains("prev_batch"s)) {
    return
    jsonBody().get()["prev_batch"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<int> QueryPublicRoomsResponse::totalRoomCountEstimate() const
    {
    if (jsonBody().get()
    .contains("total_room_count_estimate"s)) {
    return
    jsonBody().get()["total_room_count_estimate"s]
    .template get<int>();}
    else { return std::optional<int>(  );}
    }

}
