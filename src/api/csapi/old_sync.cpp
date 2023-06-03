/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "old_sync.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetEventsJob::buildQuery(
std::optional<std::string> from, std::optional<int> timeout)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "from"s, from);
  
    addToQueryIfNeeded(_q, "timeout"s, timeout);
return _q;
}

    BaseJob::Body GetEventsJob::buildBody(std::optional<std::string> from, std::optional<int> timeout)
      {
      // ignore unused param
      (void)(from);(void)(timeout);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetEventsJob::GetEventsJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::optional<std::string> from, std::optional<int> timeout
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/events",
          GET,
          std::string("GetEvents"),
          _accessToken,
          ReturnType::Json,
            buildBody(from, timeout)
              , buildQuery(from, timeout)
                , {}

)
        {
        }

        GetEventsJob GetEventsJob::withData(JsonWrap j) &&
        {
          auto ret = GetEventsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetEventsJob GetEventsJob::withData(JsonWrap j) const &
        {
          auto ret = GetEventsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetEventsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetEventsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> GetEventsResponse::start() const
    {
    if (jsonBody().get()
    .contains("start"s)) {
    return
    jsonBody().get()["start"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> GetEventsResponse::end() const
    {
    if (jsonBody().get()
    .contains("end"s)) {
    return
    jsonBody().get()["end"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    EventList GetEventsResponse::chunk() const
    {
    if (jsonBody().get()
    .contains("chunk"s)) {
    return
    jsonBody().get()["chunk"s]
    .template get<EventList>();}
    else { return EventList(  );}
    }


  
BaseJob::Query InitialSyncJob::buildQuery(
std::optional<int> limit, std::optional<bool> archived)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "limit"s, limit);
  
    addToQueryIfNeeded(_q, "archived"s, archived);
return _q;
}

    BaseJob::Body InitialSyncJob::buildBody(std::optional<int> limit, std::optional<bool> archived)
      {
      // ignore unused param
      (void)(limit);(void)(archived);
      
      
              return BaseJob::EmptyBody{};

      };

      

InitialSyncJob::InitialSyncJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::optional<int> limit, std::optional<bool> archived
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/initialSync",
          GET,
          std::string("InitialSync"),
          _accessToken,
          ReturnType::Json,
            buildBody(limit, archived)
              , buildQuery(limit, archived)
                , {}

)
        {
        }

        InitialSyncJob InitialSyncJob::withData(JsonWrap j) &&
        {
          auto ret = InitialSyncJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        InitialSyncJob InitialSyncJob::withData(JsonWrap j) const &
        {
          auto ret = InitialSyncJob(*this);
          ret.attachData(j);
          return ret;
        }

        InitialSyncJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool InitialSyncResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("end"s)
            && jsonBody().get().contains("presence"s)
            && jsonBody().get().contains("rooms"s)
          ;
          }


    
    std::string InitialSyncResponse::end() const
    {
    if (jsonBody().get()
    .contains("end"s)) {
    return
    jsonBody().get()["end"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }

    
    EventList InitialSyncResponse::presence() const
    {
    if (jsonBody().get()
    .contains("presence"s)) {
    return
    jsonBody().get()["presence"s]
    .template get<EventList>();}
    else { return EventList(  );}
    }

    
    immer::array<InitialSyncJob::RoomInfo> InitialSyncResponse::rooms() const
    {
    if (jsonBody().get()
    .contains("rooms"s)) {
    return
    jsonBody().get()["rooms"s]
    .template get<immer::array<RoomInfo>>();}
    else { return immer::array<RoomInfo>(  );}
    }

    
    EventList InitialSyncResponse::accountData() const
    {
    if (jsonBody().get()
    .contains("account_data"s)) {
    return
    jsonBody().get()["account_data"s]
    .template get<EventList>();}
    else { return EventList(  );}
    }


  
BaseJob::Query GetOneEventJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetOneEventJob::buildBody(std::string eventId)
      {
      // ignore unused param
      (void)(eventId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetOneEventJob::GetOneEventJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string eventId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/events/" + eventId,
          GET,
          std::string("GetOneEvent"),
          _accessToken,
          ReturnType::Json,
            buildBody(eventId)
              , buildQuery()
                , {}

)
        {
        }

        GetOneEventJob GetOneEventJob::withData(JsonWrap j) &&
        {
          auto ret = GetOneEventJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetOneEventJob GetOneEventJob::withData(JsonWrap j) const &
        {
          auto ret = GetOneEventJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetOneEventJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetOneEventResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
