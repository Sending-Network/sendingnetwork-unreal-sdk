/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "event.hpp"
#include "csapi/definitions/event_batch.hpp"
#include "csapi/definitions/timeline_batch.hpp"
#include "csapi/definitions/state_event_batch.hpp"

namespace Kazv::Api {

/*! \brief Synchronise the client's state and receive new messages.
 *
 * Synchronise the client's state with the latest state on the server.
 * Clients use this API when they first log in to get an initial snapshot
 * of the state on the server, and then continue to call this API to get
 * incremental deltas to the state, and to receive new messages.
 * 
 * *Note*: This endpoint supports lazy-loading. See `Filtering <#filtering>`_
 * for more information. Lazy-loading members is only supported on a ``StateFilter``
 * for this endpoint. When lazy-loading is enabled, servers MUST include the
 * syncing user's own membership event when they join a room, or when the
 * full state of rooms is requested, to aid discovering the user's avatar &
 * displayname.
 * 
 * Further, like other members, the user's own membership event is eligible
 * for being considered redundant by the server. When a sync is ``limited``,
 * the server MUST return membership events for events in the gap
 * (between ``since`` and the start of the returned timeline), regardless
 * as to whether or not they are redundant. This ensures that joins/leaves
 * and profile changes which occur during the gap are not lost.
 * 
 * Note that the default behaviour of ``state`` is to include all membership
 * events, alongside other state, when lazy-loading is not enabled.
 */
class SyncJob : public BaseJob {
public:
  // Inner data structures

/// Information about the room which clients may need to
/// correctly render it to users.
    struct RoomSummary
        {
/// The users which can be used to generate a room name
/// if the room does not have one. Required if the room's
/// ``m.room.name`` or ``m.room.canonical_alias`` state events
/// are unset or empty.
/// 
/// This should be the first 5 members of the room, ordered
/// by stream ordering, which are joined or invited. The
/// list must never include the client's own user ID. When
/// no joined or invited members are available, this should
/// consist of the banned and left users. More than 5 members
/// may be provided, however less than 5 should only be provided
/// when there are less than 5 members to represent.
/// 
/// When lazy-loading room members is enabled, the membership
/// events for the heroes MUST be included in the ``state``,
/// unless they are redundant. When the list of users changes,
/// the server notifies the client by sending a fresh list of
/// heroes. If there are no changes since the last sync, this
/// field may be omitted.
          immer::array<std::string> mHeroes;
/// The number of users with ``membership`` of ``join``,
/// including the client's own user ID. If this field has
/// not changed since the last sync, it may be omitted.
/// Required otherwise.
          std::optional<int> mJoinedMemberCount;
/// The number of users with ``membership`` of ``invite``.
/// If this field has not changed since the last sync, it
/// may be omitted. Required otherwise.
          std::optional<int> mInvitedMemberCount;
        
        };

/// Counts of unread notifications for this room. See the
/// `Receiving notifications section <#receiving-notifications>`_
/// for more information on how these are calculated.
    struct UnreadNotificationCounts
        {
/// The number of unread notifications for this room with the highlight flag set
          std::optional<int> highlightCount;
/// The total number of unread notifications for this room
          std::optional<int> notificationCount;
        
        };

/// Synchronise the client's state with the latest state on the server.
/// Clients use this API when they first log in to get an initial snapshot
/// of the state on the server, and then continue to call this API to get
/// incremental deltas to the state, and to receive new messages.
/// 
/// *Note*: This endpoint supports lazy-loading. See `Filtering <#filtering>`_
/// for more information. Lazy-loading members is only supported on a ``StateFilter``
/// for this endpoint. When lazy-loading is enabled, servers MUST include the
/// syncing user's own membership event when they join a room, or when the
/// full state of rooms is requested, to aid discovering the user's avatar &
/// displayname.
/// 
/// Further, like other members, the user's own membership event is eligible
/// for being considered redundant by the server. When a sync is ``limited``,
/// the server MUST return membership events for events in the gap
/// (between ``since`` and the start of the returned timeline), regardless
/// as to whether or not they are redundant. This ensures that joins/leaves
/// and profile changes which occur during the gap are not lost.
/// 
/// Note that the default behaviour of ``state`` is to include all membership
/// events, alongside other state, when lazy-loading is not enabled.
    struct JoinedRoom
        {
/// Information about the room which clients may need to
/// correctly render it to users.
          std::optional<RoomSummary> summary;
/// Updates to the state, between the time indicated by
/// the ``since`` parameter, and the start of the
/// ``timeline`` (or all state up to the start of the
/// ``timeline``, if ``since`` is not given, or
/// ``full_state`` is true).
/// 
/// N.B. state updates for ``m.room.member`` events will
/// be incomplete if ``lazy_load_members`` is enabled in
/// the ``/sync`` filter, and only return the member events
/// required to display the senders of the timeline events
/// in this response.
          std::optional<StateEventBatch> state;
/// The timeline of messages and state changes in the
/// room.
          Timeline timeline;
/// The ephemeral events in the room that aren't
/// recorded in the timeline or state of the room.
/// e.g. typing.
          std::optional<EventBatch> ephemeral;
/// The private data that this user has attached to
/// this room.
          std::optional<EventBatch> accountData;
/// Counts of unread notifications for this room. See the
/// `Receiving notifications section <#receiving-notifications>`_
/// for more information on how these are calculated.
          std::optional<UnreadNotificationCounts> unreadNotifications;
        
        };

/// The state of a room that the user has been invited
/// to. These state events may only have the ``sender``,
/// ``type``, ``state_key`` and ``content`` keys
/// present. These events do not replace any state that
/// the client already has for the room, for example if
/// the client has archived the room. Instead the
/// client should keep two separate copies of the
/// state: the one from the ``invite_state`` and one
/// from the archived ``state``. If the client joins
/// the room then the current state will be given as a
/// delta against the archived ``state`` not the
/// ``invite_state``.
    struct InviteState
        {
/// The StrippedState events that form the invite state.
          EventList events;
        
        };

/// Synchronise the client's state with the latest state on the server.
/// Clients use this API when they first log in to get an initial snapshot
/// of the state on the server, and then continue to call this API to get
/// incremental deltas to the state, and to receive new messages.
/// 
/// *Note*: This endpoint supports lazy-loading. See `Filtering <#filtering>`_
/// for more information. Lazy-loading members is only supported on a ``StateFilter``
/// for this endpoint. When lazy-loading is enabled, servers MUST include the
/// syncing user's own membership event when they join a room, or when the
/// full state of rooms is requested, to aid discovering the user's avatar &
/// displayname.
/// 
/// Further, like other members, the user's own membership event is eligible
/// for being considered redundant by the server. When a sync is ``limited``,
/// the server MUST return membership events for events in the gap
/// (between ``since`` and the start of the returned timeline), regardless
/// as to whether or not they are redundant. This ensures that joins/leaves
/// and profile changes which occur during the gap are not lost.
/// 
/// Note that the default behaviour of ``state`` is to include all membership
/// events, alongside other state, when lazy-loading is not enabled.
    struct InvitedRoom
        {
/// The state of a room that the user has been invited
/// to. These state events may only have the ``sender``,
/// ``type``, ``state_key`` and ``content`` keys
/// present. These events do not replace any state that
/// the client already has for the room, for example if
/// the client has archived the room. Instead the
/// client should keep two separate copies of the
/// state: the one from the ``invite_state`` and one
/// from the archived ``state``. If the client joins
/// the room then the current state will be given as a
/// delta against the archived ``state`` not the
/// ``invite_state``.
          std::optional<InviteState> inviteState;
        
        };

/// Synchronise the client's state with the latest state on the server.
/// Clients use this API when they first log in to get an initial snapshot
/// of the state on the server, and then continue to call this API to get
/// incremental deltas to the state, and to receive new messages.
/// 
/// *Note*: This endpoint supports lazy-loading. See `Filtering <#filtering>`_
/// for more information. Lazy-loading members is only supported on a ``StateFilter``
/// for this endpoint. When lazy-loading is enabled, servers MUST include the
/// syncing user's own membership event when they join a room, or when the
/// full state of rooms is requested, to aid discovering the user's avatar &
/// displayname.
/// 
/// Further, like other members, the user's own membership event is eligible
/// for being considered redundant by the server. When a sync is ``limited``,
/// the server MUST return membership events for events in the gap
/// (between ``since`` and the start of the returned timeline), regardless
/// as to whether or not they are redundant. This ensures that joins/leaves
/// and profile changes which occur during the gap are not lost.
/// 
/// Note that the default behaviour of ``state`` is to include all membership
/// events, alongside other state, when lazy-loading is not enabled.
    struct LeftRoom
        {
/// The state updates for the room up to the start of the timeline.
          std::optional<StateEventBatch> state;
/// The timeline of messages and state changes in the
/// room up to the point when the user left.
          Timeline timeline;
/// The private data that this user has attached to
/// this room.
          std::optional<EventBatch> accountData;
        
        };

/// Updates to rooms.
    struct Rooms
        {
/// The rooms that the user has joined, mapped as room ID to
/// room information.
          immer::map<std::string, JoinedRoom> join;
/// The rooms that the user has been invited to, mapped as room ID to
/// room information.
          immer::map<std::string, InvitedRoom> invite;
/// The rooms that the user has left or been banned from, mapped as room ID to
/// room information.
          immer::map<std::string, LeftRoom> leave;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The batch token to supply in the ``since`` param of the next
/// ``/sync`` request.
std::string nextBatch() const;

    
/// Updates to rooms.
std::optional<Rooms> rooms() const;

    
/// The updates to the presence status of other users.
std::optional<EventBatch> presence() const;

    
/// The global private data created by this user.
std::optional<EventBatch> accountData() const;

    
/// Information on the send-to-device messages for the client
/// device, as defined in |send_to_device_sync|_.
JsonWrap toDevice() const;

    
/// Information on end-to-end device updates, as specified in
/// |device_lists_sync|_.
JsonWrap deviceLists() const;

    
/// Information on end-to-end encryption keys, as specified
/// in |device_lists_sync|_.
immer::map<std::string, int> deviceOneTimeKeysCount() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Synchronise the client's state and receive new messages.
 *
    * \param filter
    *   The ID of a filter created using the filter API or a filter JSON
    *   object encoded as a string. The server will detect whether it is
    *   an ID or a JSON object by whether the first character is a ``"{"``
    *   open brace. Passing the JSON inline is best suited to one off
    *   requests. Creating a filter using the filter API is recommended for
    *   clients that reuse the same filter multiple times, for example in
    *   long poll requests.
    *   
    *   See `Filtering <#filtering>`_ for more information.
    * 
    * \param since
    *   A point in time to continue a sync from.
    * 
    * \param fullState
    *   Controls whether to include the full state for all rooms the user
    *   is a member of.
    *   
    *   If this is set to ``true``, then all state events will be returned,
    *   even if ``since`` is non-empty. The timeline will still be limited
    *   by the ``since`` parameter. In this case, the ``timeout`` parameter
    *   will be ignored and the query will return immediately, possibly with
    *   an empty timeline.
    *   
    *   If ``false``, and ``since`` is non-empty, only state which has
    *   changed since the point indicated by ``since`` will be returned.
    *   
    *   By default, this is ``false``.
    * 
    * \param setPresence
    *   Controls whether the client is automatically marked as online by
    *   polling this API. If this parameter is omitted then the client is
    *   automatically marked as online when it uses this API. Otherwise if
    *   the parameter is set to "offline" then the client is not marked as
    *   being online when it uses this API. When set to "unavailable", the
    *   client is marked as being idle.
    * 
    * \param timeout
    *   The maximum time to wait, in milliseconds, before returning this
    *   request. If no events (or other data) become available before this
    *   time elapses, the server will return a response with empty fields.
    *   
    *   By default, this is ``0``, so the server will return immediately
    *   even if the response is empty.
    */
    explicit SyncJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::optional<std::string> filter  = std::nullopt, std::optional<std::string> since  = std::nullopt, std::optional<bool> fullState  = std::nullopt, std::optional<std::string> setPresence  = std::nullopt, std::optional<int> timeout  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::optional<std::string> filter, std::optional<std::string> since, std::optional<bool> fullState, std::optional<std::string> setPresence, std::optional<int> timeout);

      static BaseJob::Body buildBody(std::optional<std::string> filter, std::optional<std::string> since, std::optional<bool> fullState, std::optional<std::string> setPresence, std::optional<int> timeout);

        

        

      SyncJob withData(JsonWrap j) &&;
      SyncJob withData(JsonWrap j) const &;
      };
      using SyncResponse = SyncJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<SyncJob::RoomSummary> {

  static void to_json(json& jo, const SyncJob::RoomSummary &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "m.heroes"s, pod.mHeroes);
    
    addToJsonIfNeeded(jo, "m.joined_member_count"s, pod.mJoinedMemberCount);
    
    addToJsonIfNeeded(jo, "m.invited_member_count"s, pod.mInvitedMemberCount);
  }

  static void from_json(const json &jo, SyncJob::RoomSummary& result)
  {
  
    if (jo.contains("m.heroes"s)) {
      result.mHeroes = jo.at("m.heroes"s);
    }
    if (jo.contains("m.joined_member_count"s)) {
      result.mJoinedMemberCount = jo.at("m.joined_member_count"s);
    }
    if (jo.contains("m.invited_member_count"s)) {
      result.mInvitedMemberCount = jo.at("m.invited_member_count"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SyncJob::UnreadNotificationCounts> {

  static void to_json(json& jo, const SyncJob::UnreadNotificationCounts &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "highlight_count"s, pod.highlightCount);
    
    addToJsonIfNeeded(jo, "notification_count"s, pod.notificationCount);
  }

  static void from_json(const json &jo, SyncJob::UnreadNotificationCounts& result)
  {
  
    if (jo.contains("highlight_count"s)) {
      result.highlightCount = jo.at("highlight_count"s);
    }
    if (jo.contains("notification_count"s)) {
      result.notificationCount = jo.at("notification_count"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SyncJob::JoinedRoom> {

  static void to_json(json& jo, const SyncJob::JoinedRoom &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "summary"s, pod.summary);
    
    addToJsonIfNeeded(jo, "state"s, pod.state);
    
    addToJsonIfNeeded(jo, "timeline"s, pod.timeline);
    
    addToJsonIfNeeded(jo, "ephemeral"s, pod.ephemeral);
    
    addToJsonIfNeeded(jo, "account_data"s, pod.accountData);
    
    addToJsonIfNeeded(jo, "unread_notifications"s, pod.unreadNotifications);
  }

  static void from_json(const json &jo, SyncJob::JoinedRoom& result)
  {
  
    if (jo.contains("summary"s)) {
      result.summary = jo.at("summary"s);
    }
    if (jo.contains("state"s)) {
      result.state = jo.at("state"s);
    }
    if (jo.contains("timeline"s)) {
      result.timeline = jo.at("timeline"s);
    }
    if (jo.contains("ephemeral"s)) {
      result.ephemeral = jo.at("ephemeral"s);
    }
    if (jo.contains("account_data"s)) {
      result.accountData = jo.at("account_data"s);
    }
    if (jo.contains("unread_notifications"s)) {
      result.unreadNotifications = jo.at("unread_notifications"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SyncJob::InviteState> {

  static void to_json(json& jo, const SyncJob::InviteState &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "events"s, pod.events);
  }

  static void from_json(const json &jo, SyncJob::InviteState& result)
  {
  
    if (jo.contains("events"s)) {
      result.events = jo.at("events"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SyncJob::InvitedRoom> {

  static void to_json(json& jo, const SyncJob::InvitedRoom &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "invite_state"s, pod.inviteState);
  }

  static void from_json(const json &jo, SyncJob::InvitedRoom& result)
  {
  
    if (jo.contains("invite_state"s)) {
      result.inviteState = jo.at("invite_state"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SyncJob::LeftRoom> {

  static void to_json(json& jo, const SyncJob::LeftRoom &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "state"s, pod.state);
    
    addToJsonIfNeeded(jo, "timeline"s, pod.timeline);
    
    addToJsonIfNeeded(jo, "account_data"s, pod.accountData);
  }

  static void from_json(const json &jo, SyncJob::LeftRoom& result)
  {
  
    if (jo.contains("state"s)) {
      result.state = jo.at("state"s);
    }
    if (jo.contains("timeline"s)) {
      result.timeline = jo.at("timeline"s);
    }
    if (jo.contains("account_data"s)) {
      result.accountData = jo.at("account_data"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SyncJob::Rooms> {

  static void to_json(json& jo, const SyncJob::Rooms &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "join"s, pod.join);
    
    addToJsonIfNeeded(jo, "invite"s, pod.invite);
    
    addToJsonIfNeeded(jo, "leave"s, pod.leave);
  }

  static void from_json(const json &jo, SyncJob::Rooms& result)
  {
  
    if (jo.contains("join"s)) {
      result.join = jo.at("join"s);
    }
    if (jo.contains("invite"s)) {
      result.invite = jo.at("invite"s);
    }
    if (jo.contains("leave"s)) {
      result.leave = jo.at("leave"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
