/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "event_context.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetEventContextJob::buildQuery(
std::optional<int> limit, std::optional<std::string> filter)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "limit"s, limit);
  
    addToQueryIfNeeded(_q, "filter"s, filter);
return _q;
}

    BaseJob::Body GetEventContextJob::buildBody(std::string roomId, std::string eventId, std::optional<int> limit, std::optional<std::string> filter)
      {
      // ignore unused param
      (void)(roomId);(void)(eventId);(void)(limit);(void)(filter);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetEventContextJob::GetEventContextJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string eventId, std::optional<int> limit, std::optional<std::string> filter
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/context/" + eventId,
          GET,
          std::string("GetEventContext"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, eventId, limit, filter)
              , buildQuery(limit, filter)
                , {}

)
        {
        }

        GetEventContextJob GetEventContextJob::withData(JsonWrap j) &&
        {
          auto ret = GetEventContextJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetEventContextJob GetEventContextJob::withData(JsonWrap j) const &
        {
          auto ret = GetEventContextJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetEventContextJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetEventContextResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> GetEventContextResponse::start() const
    {
    if (jsonBody().get()
    .contains("start"s)) {
    return
    jsonBody().get()["start"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> GetEventContextResponse::end() const
    {
    if (jsonBody().get()
    .contains("end"s)) {
    return
    jsonBody().get()["end"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    EventList GetEventContextResponse::eventsBefore() const
    {
    if (jsonBody().get()
    .contains("events_before"s)) {
    return
    jsonBody().get()["events_before"s]
    .template get<EventList>();}
    else { return EventList(  );}
    }

    
    JsonWrap GetEventContextResponse::event() const
    {
    if (jsonBody().get()
    .contains("event"s)) {
    return
    jsonBody().get()["event"s]
    .template get<JsonWrap>();}
    else { return JsonWrap(  );}
    }

    
    EventList GetEventContextResponse::eventsAfter() const
    {
    if (jsonBody().get()
    .contains("events_after"s)) {
    return
    jsonBody().get()["events_after"s]
    .template get<EventList>();}
    else { return EventList(  );}
    }

    
    EventList GetEventContextResponse::state() const
    {
    if (jsonBody().get()
    .contains("state"s)) {
    return
    jsonBody().get()["state"s]
    .template get<EventList>();}
    else { return EventList(  );}
    }

}
