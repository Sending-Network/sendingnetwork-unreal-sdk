/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Listen on the event stream.
 *
 * This will listen for new events related to a particular room and return
 * them to the caller. This will block until an event is received, or until
 * the ``timeout`` is reached.
 * 
 * This API is the same as the normal ``/events`` endpoint, but can be
 * called by users who have not joined the room.
 * 
 * Note that the normal ``/events`` endpoint has been deprecated. This
 * API will also be deprecated at some point, but its replacement is not
 * yet known.
 */
class PeekEventsJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// A token which correlates to the first value in ``chunk``. This
/// is usually the same token supplied to ``from=``.
std::optional<std::string> start() const;

    
/// A token which correlates to the last value in ``chunk``. This
/// token should be used in the next request to ``/events``.
std::optional<std::string> end() const;

    
/// An array of events.
EventList chunk() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Listen on the event stream.
 *
    * \param from
    *   The token to stream from. This token is either from a previous
    *   request to this API or from the initial sync API.
    * 
    * \param timeout
    *   The maximum time in milliseconds to wait for an event.
    * 
    * \param roomId
    *   The room ID for which events should be returned.
    */
    explicit PeekEventsJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::optional<std::string> from  = std::nullopt, std::optional<int> timeout  = std::nullopt, std::optional<std::string> roomId  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::optional<std::string> from, std::optional<int> timeout, std::optional<std::string> roomId);

      static BaseJob::Body buildBody(std::optional<std::string> from, std::optional<int> timeout, std::optional<std::string> roomId);

        

        

      PeekEventsJob withData(JsonWrap j) &&;
      PeekEventsJob withData(JsonWrap j) const &;
      };
      using PeekEventsResponse = PeekEventsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
