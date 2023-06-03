/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "peeking_events.hpp"

namespace Kazv::Api
{

  
BaseJob::Query PeekEventsJob::buildQuery(
std::optional<std::string> from, std::optional<int> timeout, std::optional<std::string> roomId)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "from"s, from);
  
    addToQueryIfNeeded(_q, "timeout"s, timeout);
  
    addToQueryIfNeeded(_q, "room_id"s, roomId);
return _q;
}

    BaseJob::Body PeekEventsJob::buildBody(std::optional<std::string> from, std::optional<int> timeout, std::optional<std::string> roomId)
      {
      // ignore unused param
      (void)(from);(void)(timeout);(void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

      

PeekEventsJob::PeekEventsJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::optional<std::string> from, std::optional<int> timeout, std::optional<std::string> roomId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/events",
          GET,
          std::string("PeekEvents"),
          _accessToken,
          ReturnType::Json,
            buildBody(from, timeout, roomId)
              , buildQuery(from, timeout, roomId)
                , {}

)
        {
        }

        PeekEventsJob PeekEventsJob::withData(JsonWrap j) &&
        {
          auto ret = PeekEventsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        PeekEventsJob PeekEventsJob::withData(JsonWrap j) const &
        {
          auto ret = PeekEventsJob(*this);
          ret.attachData(j);
          return ret;
        }

        PeekEventsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool PeekEventsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> PeekEventsResponse::start() const
    {
    if (jsonBody().get()
    .contains("start"s)) {
    return
    jsonBody().get()["start"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> PeekEventsResponse::end() const
    {
    if (jsonBody().get()
    .contains("end"s)) {
    return
    jsonBody().get()["end"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    EventList PeekEventsResponse::chunk() const
    {
    if (jsonBody().get()
    .contains("chunk"s)) {
    return
    jsonBody().get()["chunk"s]
    .template get<EventList>();}
    else { return EventList(  );}
    }

}
