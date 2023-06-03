/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Get events and state around the specified event.
 *
 * This API returns a number of events that happened just before and
 * after the specified event. This allows clients to get the context
 * surrounding an event.
 * 
 * *Note*: This endpoint supports lazy-loading of room member events. See
 * `Lazy-loading room members <#lazy-loading-room-members>`_ for more information.
 */
class GetEventContextJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// A token that can be used to paginate backwards with.
std::optional<std::string> start() const;

    
/// A token that can be used to paginate forwards with.
std::optional<std::string> end() const;

    
/// A list of room events that happened just before the
/// requested event, in reverse-chronological order.
EventList eventsBefore() const;

    
/// Details of the requested event.
JsonWrap event() const;

    
/// A list of room events that happened just after the
/// requested event, in chronological order.
EventList eventsAfter() const;

    
/// The state of the room at the last event returned.
EventList state() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get events and state around the specified event.
 *
    * \param roomId
    *   The room to get events from.
    * 
    * \param eventId
    *   The event to get context around.
    * 
    * \param limit
    *   The maximum number of events to return. Default: 10.
    * 
    * \param filter
    *   A JSON ``RoomEventFilter`` to filter the returned events with. The
    *   filter is only applied to ``events_before``, ``events_after``, and
    *   ``state``. It is not applied to the ``event`` itself. The filter may 
    *   be applied before or/and after the ``limit`` parameter - whichever the 
    *   node prefers.
    *   
    *   See `Filtering <#filtering>`_ for more information.
    */
    explicit GetEventContextJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string eventId , std::optional<int> limit  = std::nullopt, std::optional<std::string> filter  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::optional<int> limit, std::optional<std::string> filter);

      static BaseJob::Body buildBody(std::string roomId, std::string eventId, std::optional<int> limit, std::optional<std::string> filter);

        

        

      GetEventContextJob withData(JsonWrap j) &&;
      GetEventContextJob withData(JsonWrap j) const &;
      };
      using GetEventContextResponse = GetEventContextJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
