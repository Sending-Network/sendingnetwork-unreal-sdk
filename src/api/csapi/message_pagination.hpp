/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Get a list of events for this room
 *
 * This API returns a list of message and state events for a room. It uses
 * pagination query parameters to paginate history in the room.
 * 
 * *Note*: This endpoint supports lazy-loading of room member events. See
 * `Lazy-loading room members <#lazy-loading-room-members>`_ for more information.
 */
class GetRoomEventsJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The token the pagination starts from. If ``dir=b`` this will be
/// the token supplied in ``from``.
std::optional<std::string> start() const;

    
/// The token the pagination ends at. If ``dir=b`` this token should
/// be used again to request even earlier events.
std::optional<std::string> end() const;

    
/// A list of room events. The order depends on the ``dir`` parameter.
/// For ``dir=b`` events will be in reverse-chronological order,
/// for ``dir=f`` in chronological order, so that events start
/// at the ``from`` point.
EventList chunk() const;

    
/// A list of state events relevant to showing the ``chunk``. For example, if
/// ``lazy_load_members`` is enabled in the filter then this may contain
/// the membership events for the senders of events in the ``chunk``.
/// 
/// Unless ``include_redundant_members`` is ``true``, the server
/// may remove membership events which would have already been
/// sent to the client in prior calls to this endpoint, assuming
/// the membership of those members has not changed.
EventList state() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get a list of events for this room
 *
    * \param roomId
    *   The room to get events from.
    * 
    * \param from
    *   The token to start returning events from. This token can be obtained
    *   from a ``prev_batch`` token returned for each room by the sync API,
    *   or from a ``start`` or ``end`` token returned by a previous request
    *   to this endpoint.
    * 
    * \param dir
    *   The direction to return events from.
    * 
    * \param to
    *   The token to stop returning events at. This token can be obtained from
    *   a ``prev_batch`` token returned for each room by the sync endpoint,
    *   or from a ``start`` or ``end`` token returned by a previous request to
    *   this endpoint.
    * 
    * \param limit
    *   The maximum number of events to return. Default: 10.
    * 
    * \param filter
    *   A JSON RoomEventFilter to filter returned events with.
    */
    explicit GetRoomEventsJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string from , std::string dir , std::optional<std::string> to  = std::nullopt, std::optional<int> limit  = std::nullopt, std::optional<std::string> filter  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::string from, std::optional<std::string> to, std::string dir, std::optional<int> limit, std::optional<std::string> filter);

      static BaseJob::Body buildBody(std::string roomId, std::string from, std::string dir, std::optional<std::string> to, std::optional<int> limit, std::optional<std::string> filter);

        

        

      GetRoomEventsJob withData(JsonWrap j) &&;
      GetRoomEventsJob withData(JsonWrap j) const &;
      };
      using GetRoomEventsResponse = GetRoomEventsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
