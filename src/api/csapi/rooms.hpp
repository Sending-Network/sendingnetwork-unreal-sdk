/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "event.hpp"

namespace Kazv::Api {

/*! \brief Get a single event by event ID.
 *
 * Get a single event based on ``roomId/eventId``. You must have permission to
 * retrieve this event e.g. by being a member in the room for this event.
 */
class GetOneRoomEventJob : public BaseJob {
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
    * \param roomId
    *   The ID of the room the event is in.
    * 
    * \param eventId
    *   The event ID to get.
    */
    explicit GetOneRoomEventJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string eventId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::string eventId);

        

        

      GetOneRoomEventJob withData(JsonWrap j) &&;
      GetOneRoomEventJob withData(JsonWrap j) const &;
      };
      using GetOneRoomEventResponse = GetOneRoomEventJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get the state identified by the type and key.
 *
 * .. For backwards compatibility with older links...
 * .. _`get-sdn-client-r0-rooms-roomid-state-eventtype`:
 * 
 * Looks up the contents of a state event in a room. If the user is
 * joined to the room then the state is taken from the current
 * state of the room. If the user has left the room then the state is
 * taken from the state of the room when they left.
 */
class GetRoomStateWithKeyJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get the state identified by the type and key.
 *
    * \param roomId
    *   The room to look up the state in.
    * 
    * \param eventType
    *   The type of state to look up.
    * 
    * \param stateKey
    *   The key of the state to look up. Defaults to an empty string. When
    *   an empty string, the trailing slash on this endpoint is optional.
    */
    explicit GetRoomStateWithKeyJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string eventType , std::string stateKey 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::string eventType, std::string stateKey);

        

        

      GetRoomStateWithKeyJob withData(JsonWrap j) &&;
      GetRoomStateWithKeyJob withData(JsonWrap j) const &;
      };
      using GetRoomStateWithKeyResponse = GetRoomStateWithKeyJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get all state events in the current state of a room.
 *
 * Get the state events for the current state of a room.
 */
class GetRoomStateJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// The current state of the room
    
    EventList data() const
    {
    return
      std::move(jsonBody().get()).get<EventList>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get all state events in the current state of a room.
 *
    * \param roomId
    *   The room to look up the state for.
    */
    explicit GetRoomStateJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId);

        

        

      GetRoomStateJob withData(JsonWrap j) &&;
      GetRoomStateJob withData(JsonWrap j) const &;
      };
      using GetRoomStateResponse = GetRoomStateJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get the m.room.member events for the room.
 *
 * Get the list of members for this room.
 */
class GetMembersByRoomJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// Get the list of members for this room.
EventList chunk() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get the m.room.member events for the room.
 *
    * \param roomId
    *   The room to get the member events for.
    * 
    * \param at
    *   The point in time (pagination token) to return members for in the room.
    *   This token can be obtained from a ``prev_batch`` token returned for
    *   each room by the sync API. Defaults to the current state of the room,
    *   as determined by the server.
    * 
    * \param membership
    *   The kind of membership to filter for. Defaults to no filtering if
    *   unspecified. When specified alongside ``not_membership``, the two
    *   parameters create an 'or' condition: either the membership *is*
    *   the same as ``membership`` **or** *is not* the same as ``not_membership``.
    * 
    * \param notMembership
    *   The kind of membership to exclude from the results. Defaults to no
    *   filtering if unspecified.
    */
    explicit GetMembersByRoomJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::optional<std::string> at  = std::nullopt, std::optional<std::string> membership  = std::nullopt, std::optional<std::string> notMembership  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::optional<std::string> at, std::optional<std::string> membership, std::optional<std::string> notMembership);

      static BaseJob::Body buildBody(std::string roomId, std::optional<std::string> at, std::optional<std::string> membership, std::optional<std::string> notMembership);

        

        

      GetMembersByRoomJob withData(JsonWrap j) &&;
      GetMembersByRoomJob withData(JsonWrap j) const &;
      };
      using GetMembersByRoomResponse = GetMembersByRoomJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Gets the list of currently joined users and their profile data.
 *
 * This API returns a map of MXIDs to member info objects for members of the room. The current user must be in the room for it to work, unless it is an Application Service in which case any of the AS's users must be in the room. This API is primarily for Application Services and should be faster to respond than ``/members`` as it can be implemented more efficiently on the server.
 */
class GetJoinedMembersByRoomJob : public BaseJob {
public:
  // Inner data structures

/// This API returns a map of MXIDs to member info objects for members of the room. The current user must be in the room for it to work, unless it is an Application Service in which case any of the AS's users must be in the room. This API is primarily for Application Services and should be faster to respond than ``/members`` as it can be implemented more efficiently on the server.
    struct RoomMember
        {
/// The display name of the user this object is representing.
          std::optional<std::string> displayName;
/// The mxc avatar url of the user this object is representing.
          std::optional<std::string> avatarUrl;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// A map from user ID to a RoomMember object.
immer::map<std::string, RoomMember> joined() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Gets the list of currently joined users and their profile data.
 *
    * \param roomId
    *   The room to get the members of.
    */
    explicit GetJoinedMembersByRoomJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId);

        

        

      GetJoinedMembersByRoomJob withData(JsonWrap j) &&;
      GetJoinedMembersByRoomJob withData(JsonWrap j) const &;
      };
      using GetJoinedMembersByRoomResponse = GetJoinedMembersByRoomJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<GetJoinedMembersByRoomJob::RoomMember> {

  static void to_json(json& jo, const GetJoinedMembersByRoomJob::RoomMember &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "display_name"s, pod.displayName);
    
    addToJsonIfNeeded(jo, "avatar_url"s, pod.avatarUrl);
  }

  static void from_json(const json &jo, GetJoinedMembersByRoomJob::RoomMember& result)
  {
  
    if (jo.contains("display_name"s)) {
      result.displayName = jo.at("display_name"s);
    }
    if (jo.contains("avatar_url"s)) {
      result.avatarUrl = jo.at("avatar_url"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
