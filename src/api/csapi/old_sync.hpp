/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "event.hpp"

namespace Kazv::Api {

/*! \brief Listen on the event stream.
 *
 * This will listen for new events and return them to the caller. This will
 * block until an event is received, or until the ``timeout`` is reached.
 * 
 * This endpoint was deprecated in r0 of this specification. Clients
 * should instead call the |/sync|_ API with a ``since`` parameter.
 */
class GetEventsJob : public BaseJob {
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
    */
    explicit GetEventsJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::optional<std::string> from  = std::nullopt, std::optional<int> timeout  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::optional<std::string> from, std::optional<int> timeout);

      static BaseJob::Body buildBody(std::optional<std::string> from, std::optional<int> timeout);

        

        

      GetEventsJob withData(JsonWrap j) &&;
      GetEventsJob withData(JsonWrap j) const &;
      };
      using GetEventsResponse = GetEventsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get the user's current state.
 *
 * This returns the full state for this user, with an optional limit on the
 * number of messages per room to return.
 * 
 * This endpoint was deprecated in r0 of this specification. Clients
 * should instead call the |/sync|_ API with no ``since`` parameter.
 */
class InitialSyncJob : public BaseJob {
public:
  // Inner data structures

/// The pagination chunk for this room.
    struct PaginationChunk
        {
/// A token which correlates to the first value in ``chunk``.
/// Used for pagination.
          std::string start;
/// A token which correlates to the last value in ``chunk``.
/// Used for pagination.
          std::string end;
/// If the user is a member of the room this will be a
/// list of the most recent messages for this room. If
/// the user has left the room this will be the
/// messages that preceeded them leaving. This array
/// will consist of at most ``limit`` elements.
          EventList chunk;
        
        };

/// This returns the full state for this user, with an optional limit on the
/// number of messages per room to return.
/// 
/// This endpoint was deprecated in r0 of this specification. Clients
/// should instead call the |/sync|_ API with no ``since`` parameter.
    struct RoomInfo
        {
/// The ID of this room.
          std::string roomId;
/// The user's membership state in this room.
          std::string membership;
/// The invite event if ``membership`` is ``invite``
          Event invite;
/// The pagination chunk for this room.
          std::optional<PaginationChunk> messages;
/// If the user is a member of the room this will be the
/// current state of the room as a list of events. If the
/// user has left the room this will be the state of the
/// room when they left it.
          EventList state;
/// Whether this room is visible to the ``/publicRooms`` API
/// or not."
          std::optional<std::string> visibility;
/// The private data that this user has attached to
/// this room.
          EventList accountData;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// A token which correlates to the last value in ``chunk``. This
/// token should be used with the ``/events`` API to listen for new
/// events.
std::string end() const;

    
/// A list of presence events.
EventList presence() const;

    
/// This returns the full state for this user, with an optional limit on the
/// number of messages per room to return.
/// 
/// This endpoint was deprecated in r0 of this specification. Clients
/// should instead call the |/sync|_ API with no ``since`` parameter.
immer::array<RoomInfo> rooms() const;

    
/// The global private data created by this user.
EventList accountData() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get the user's current state.
 *
    * \param limit
    *   The maximum number of messages to return for each room.
    * 
    * \param archived
    *   Whether to include rooms that the user has left. If ``false`` then
    *   only rooms that the user has been invited to or has joined are
    *   included. If set to ``true`` then rooms that the user has left are
    *   included as well. By default this is ``false``.
    */
    explicit InitialSyncJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::optional<int> limit  = std::nullopt, std::optional<bool> archived  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::optional<int> limit, std::optional<bool> archived);

      static BaseJob::Body buildBody(std::optional<int> limit, std::optional<bool> archived);

        

        

      InitialSyncJob withData(JsonWrap j) &&;
      InitialSyncJob withData(JsonWrap j) const &;
      };
      using InitialSyncResponse = InitialSyncJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<InitialSyncJob::PaginationChunk> {

  static void to_json(json& jo, const InitialSyncJob::PaginationChunk &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["start"s] = pod.start;
    
    jo["end"s] = pod.end;
    
    jo["chunk"s] = pod.chunk;
    
  }

  static void from_json(const json &jo, InitialSyncJob::PaginationChunk& result)
  {
  
    if (jo.contains("start"s)) {
      result.start = jo.at("start"s);
    }
    if (jo.contains("end"s)) {
      result.end = jo.at("end"s);
    }
    if (jo.contains("chunk"s)) {
      result.chunk = jo.at("chunk"s);
    }
  
  }

};
      template<>
      struct adl_serializer<InitialSyncJob::RoomInfo> {

  static void to_json(json& jo, const InitialSyncJob::RoomInfo &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["room_id"s] = pod.roomId;
    
    jo["membership"s] = pod.membership;
    
    
    addToJsonIfNeeded(jo, "invite"s, pod.invite);
    
    addToJsonIfNeeded(jo, "messages"s, pod.messages);
    
    addToJsonIfNeeded(jo, "state"s, pod.state);
    
    addToJsonIfNeeded(jo, "visibility"s, pod.visibility);
    
    addToJsonIfNeeded(jo, "account_data"s, pod.accountData);
  }

  static void from_json(const json &jo, InitialSyncJob::RoomInfo& result)
  {
  
    if (jo.contains("room_id"s)) {
      result.roomId = jo.at("room_id"s);
    }
    if (jo.contains("membership"s)) {
      result.membership = jo.at("membership"s);
    }
    if (jo.contains("invite"s)) {
      result.invite = jo.at("invite"s);
    }
    if (jo.contains("messages"s)) {
      result.messages = jo.at("messages"s);
    }
    if (jo.contains("state"s)) {
      result.state = jo.at("state"s);
    }
    if (jo.contains("visibility"s)) {
      result.visibility = jo.at("visibility"s);
    }
    if (jo.contains("account_data"s)) {
      result.accountData = jo.at("account_data"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

/*! \brief Get a single event by event ID.
 *
 * Get a single event based on ``event_id``. You must have permission to
 * retrieve this event e.g. by being a member in the room for this event.
 * 
 * This endpoint was deprecated in r0 of this specification. Clients
 * should instead call the |/rooms/{roomId}/event/{eventId}|_ API
 * or the |/rooms/{roomId}/context/{eventId}|_ API.
 */
class GetOneEventJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// The full event.
    
    JsonWrap data() const
    {
    return
      std::move(jsonBody().get()).get<JsonWrap>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get a single event by event ID.
 *
    * \param eventId
    *   The event ID to get.
    */
    explicit GetOneEventJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string eventId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string eventId);

        

        

      GetOneEventJob withData(JsonWrap j) &&;
      GetOneEventJob withData(JsonWrap j) const &;
      };
      using GetOneEventResponse = GetOneEventJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
