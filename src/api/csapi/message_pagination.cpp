/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "message_pagination.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetRoomEventsJob::buildQuery(
std::string from, std::optional<std::string> to, std::string dir, std::optional<int> limit, std::optional<std::string> filter)
{
BaseJob::Query _q;
    addToQuery(_q, "from"s, from);
  
  
    addToQueryIfNeeded(_q, "to"s, to);
    addToQuery(_q, "dir"s, dir);
  
  
    addToQueryIfNeeded(_q, "limit"s, limit);
  
    addToQueryIfNeeded(_q, "filter"s, filter);
return _q;
}

    BaseJob::Body GetRoomEventsJob::buildBody(std::string roomId, std::string from, std::string dir, std::optional<std::string> to, std::optional<int> limit, std::optional<std::string> filter)
      {
      // ignore unused param
      (void)(roomId);(void)(from);(void)(dir);(void)(to);(void)(limit);(void)(filter);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetRoomEventsJob::GetRoomEventsJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string from, std::string dir, std::optional<std::string> to, std::optional<int> limit, std::optional<std::string> filter
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/messages",
          GET,
          std::string("GetRoomEvents"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, from, dir, to, limit, filter)
              , buildQuery(from, to, dir, limit, filter)
                , {}

)
        {
        }

        GetRoomEventsJob GetRoomEventsJob::withData(JsonWrap j) &&
        {
          auto ret = GetRoomEventsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetRoomEventsJob GetRoomEventsJob::withData(JsonWrap j) const &
        {
          auto ret = GetRoomEventsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetRoomEventsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetRoomEventsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> GetRoomEventsResponse::start() const
    {
    if (jsonBody().get()
    .contains("start"s)) {
    return
    jsonBody().get()["start"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> GetRoomEventsResponse::end() const
    {
    if (jsonBody().get()
    .contains("end"s)) {
    return
    jsonBody().get()["end"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    EventList GetRoomEventsResponse::chunk() const
    {
    if (jsonBody().get()
    .contains("chunk"s)) {
    return
    jsonBody().get()["chunk"s]
    .template get<EventList>();}
    else { return EventList(  );}
    }

    
    EventList GetRoomEventsResponse::state() const
    {
    if (jsonBody().get()
    .contains("state"s)) {
    return
    jsonBody().get()["state"s]
    .template get<EventList>();}
    else { return EventList(  );}
    }

}
