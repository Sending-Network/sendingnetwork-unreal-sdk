/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Send a state event to the given room.
 *
 * .. For backwards compatibility with older links...
 * .. _`put-sdn-client-r0-rooms-roomid-state-eventtype`:
 * 
 * State events can be sent using this endpoint.  These events will be
 * overwritten if ``<room id>``, ``<event type>`` and ``<state key>`` all
 * match.
 * 
 * Requests to this endpoint **cannot use transaction IDs**
 * like other ``PUT`` paths because they cannot be differentiated from the
 * ``state_key``. Furthermore, ``POST`` is unsupported on state paths.
 * 
 * The body of the request should be the content object of the event; the
 * fields in this object will vary depending on the type of event. See
 * `Room Events`_ for the ``m.`` event specification.
 * 
 * If the event type being sent is ``m.room.canonical_alias`` servers
 * SHOULD ensure that any new aliases being listed in the event are valid
 * per their grammar/syntax and that they point to the room ID where the
 * state event is to be sent. Servers do not validate aliases which are
 * being removed or are already present in the state event.
 */
class SetRoomStateWithKeyJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// A unique identifier for the event.
std::string eventId() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Send a state event to the given room.
 *
    * \param roomId
    *   The room to set the state in
    * 
    * \param eventType
    *   The type of event to send.
    * 
    * \param stateKey
    *   The state_key for the state to send. Defaults to the empty string. When
    *   an empty string, the trailing slash on this endpoint is optional.
    * 
    * \param body
    *   .. For backwards compatibility with older links...
    *   .. _`put-sdn-client-r0-rooms-roomid-state-eventtype`:
    *   
    *   State events can be sent using this endpoint.  These events will be
    *   overwritten if ``<room id>``, ``<event type>`` and ``<state key>`` all
    *   match.
    *   
    *   Requests to this endpoint **cannot use transaction IDs**
    *   like other ``PUT`` paths because they cannot be differentiated from the
    *   ``state_key``. Furthermore, ``POST`` is unsupported on state paths.
    *   
    *   The body of the request should be the content object of the event; the
    *   fields in this object will vary depending on the type of event. See
    *   `Room Events`_ for the ``m.`` event specification.
    *   
    *   If the event type being sent is ``m.room.canonical_alias`` servers
    *   SHOULD ensure that any new aliases being listed in the event are valid
    *   per their grammar/syntax and that they point to the room ID where the
    *   state event is to be sent. Servers do not validate aliases which are
    *   being removed or are already present in the state event.
    */
    explicit SetRoomStateWithKeyJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string eventType , std::string stateKey , JsonWrap body  = {}
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::string eventType, std::string stateKey, JsonWrap body);

        

        

      SetRoomStateWithKeyJob withData(JsonWrap j) &&;
      SetRoomStateWithKeyJob withData(JsonWrap j) const &;
      };
      using SetRoomStateWithKeyResponse = SetRoomStateWithKeyJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
