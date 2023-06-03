/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Create a new room
 *
 * Create a new room with various configuration options.
 * 
 * The server MUST apply the normal state resolution rules when creating
 * the new room, including checking power levels for each event. It MUST
 * apply the events implied by the request in the following order:
 * 
 * 1. The ``m.room.create`` event itself. Must be the first event in the
 *    room.
 * 
 * 2. An ``m.room.member`` event for the creator to join the room. This is
 *    needed so the remaining events can be sent.
 * 
 * 3. A default ``m.room.power_levels`` event, giving the room creator
 *    (and not other members) permission to send state events. Overridden
 *    by the ``power_level_content_override`` parameter.
 * 
 * 4. Events set by the ``preset``. Currently these are the ``m.room.join_rules``,
 *    ``m.room.history_visibility``, and ``m.room.guest_access`` state events.
 * 
 * 5. Events listed in ``initial_state``, in the order that they are
 *    listed.
 * 
 * 6. Events implied by ``name`` and ``topic`` (``m.room.name`` and ``m.room.topic``
 *    state events).
 * 
 * 7. Invite events implied by ``invite`` and ``invite_3pid`` (``m.room.member`` with
 *    ``membership: invite`` and ``m.room.third_party_invite``).
 * 
 * The available presets do the following with respect to room state:
 * 
 * ========================  ==============  ======================  ================  =========
 *          Preset           ``join_rules``  ``history_visibility``  ``guest_access``  Other
 * ========================  ==============  ======================  ================  =========
 * ``private_chat``          ``invite``      ``shared``              ``can_join``
 * ``trusted_private_chat``  ``invite``      ``shared``              ``can_join``      All invitees are given the same power level as the room creator.
 * ``public_chat``           ``public``      ``shared``              ``forbidden``
 * ========================  ==============  ======================  ================  =========
 * 
 * The server will create a ``m.room.create`` event in the room with the
 * requesting user as the creator, alongside other keys provided in the
 * ``creation_content``.
 */
class CreateRoomJob : public BaseJob {
public:
  // Inner data structures

/// Create a new room with various configuration options.
/// 
/// The server MUST apply the normal state resolution rules when creating
/// the new room, including checking power levels for each event. It MUST
/// apply the events implied by the request in the following order:
/// 
/// 1. The ``m.room.create`` event itself. Must be the first event in the
///    room.
/// 
/// 2. An ``m.room.member`` event for the creator to join the room. This is
///    needed so the remaining events can be sent.
/// 
/// 3. A default ``m.room.power_levels`` event, giving the room creator
///    (and not other members) permission to send state events. Overridden
///    by the ``power_level_content_override`` parameter.
/// 
/// 4. Events set by the ``preset``. Currently these are the ``m.room.join_rules``,
///    ``m.room.history_visibility``, and ``m.room.guest_access`` state events.
/// 
/// 5. Events listed in ``initial_state``, in the order that they are
///    listed.
/// 
/// 6. Events implied by ``name`` and ``topic`` (``m.room.name`` and ``m.room.topic``
///    state events).
/// 
/// 7. Invite events implied by ``invite`` and ``invite_3pid`` (``m.room.member`` with
///    ``membership: invite`` and ``m.room.third_party_invite``).
/// 
/// The available presets do the following with respect to room state:
/// 
/// ========================  ==============  ======================  ================  =========
///          Preset           ``join_rules``  ``history_visibility``  ``guest_access``  Other
/// ========================  ==============  ======================  ================  =========
/// ``private_chat``          ``invite``      ``shared``              ``can_join``
/// ``trusted_private_chat``  ``invite``      ``shared``              ``can_join``      All invitees are given the same power level as the room creator.
/// ``public_chat``           ``public``      ``shared``              ``forbidden``
/// ========================  ==============  ======================  ================  =========
/// 
/// The server will create a ``m.room.create`` event in the room with the
/// requesting user as the creator, alongside other keys provided in the
/// ``creation_content``.
    struct Invite3pid
        {
/// The hostname+port of the identity server which should be used for third party identifier lookups.
          std::string idServer;
/// An access token previously registered with the identity server. Servers
/// can treat this as optional to distinguish between r0.5-compatible clients
/// and this specification version.
          std::string idAccessToken;
/// The kind of address being passed in the address field, for example ``email``.
          std::string medium;
/// The invitee's third party identifier.
          std::string address;
        
        };

/// Create a new room with various configuration options.
/// 
/// The server MUST apply the normal state resolution rules when creating
/// the new room, including checking power levels for each event. It MUST
/// apply the events implied by the request in the following order:
/// 
/// 1. The ``m.room.create`` event itself. Must be the first event in the
///    room.
/// 
/// 2. An ``m.room.member`` event for the creator to join the room. This is
///    needed so the remaining events can be sent.
/// 
/// 3. A default ``m.room.power_levels`` event, giving the room creator
///    (and not other members) permission to send state events. Overridden
///    by the ``power_level_content_override`` parameter.
/// 
/// 4. Events set by the ``preset``. Currently these are the ``m.room.join_rules``,
///    ``m.room.history_visibility``, and ``m.room.guest_access`` state events.
/// 
/// 5. Events listed in ``initial_state``, in the order that they are
///    listed.
/// 
/// 6. Events implied by ``name`` and ``topic`` (``m.room.name`` and ``m.room.topic``
///    state events).
/// 
/// 7. Invite events implied by ``invite`` and ``invite_3pid`` (``m.room.member`` with
///    ``membership: invite`` and ``m.room.third_party_invite``).
/// 
/// The available presets do the following with respect to room state:
/// 
/// ========================  ==============  ======================  ================  =========
///          Preset           ``join_rules``  ``history_visibility``  ``guest_access``  Other
/// ========================  ==============  ======================  ================  =========
/// ``private_chat``          ``invite``      ``shared``              ``can_join``
/// ``trusted_private_chat``  ``invite``      ``shared``              ``can_join``      All invitees are given the same power level as the room creator.
/// ``public_chat``           ``public``      ``shared``              ``forbidden``
/// ========================  ==============  ======================  ================  =========
/// 
/// The server will create a ``m.room.create`` event in the room with the
/// requesting user as the creator, alongside other keys provided in the
/// ``creation_content``.
    struct StateEvent
        {
/// The type of event to send.
          std::string type;
/// The state_key of the state event. Defaults to an empty string.
          std::optional<std::string> stateKey;
/// The content of the event.
          JsonWrap content;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The created room's ID.
std::string roomId() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Create a new room
 *
    * \param visibility
    *   A ``public`` visibility indicates that the room will be shown
    *   in the published room list. A ``private`` visibility will hide
    *   the room from the published room list. Rooms default to
    *   ``private`` visibility if this key is not included. NB: This
    *   should not be confused with ``join_rules`` which also uses the
    *   word ``public``.
    * 
    * \param roomAliasName
    *   The desired room alias **local part**. If this is included, a
    *   room alias will be created and mapped to the newly created
    *   room. The alias will belong on the *same* node which
    *   created the room. For example, if this was set to "foo" and
    *   sent to the node "example.com" the complete room alias
    *   would be ``#foo:example.com``.
    *   
    *   The complete room alias will become the canonical alias for
    *   the room.
    * 
    * \param name
    *   If this is included, an ``m.room.name`` event will be sent
    *   into the room to indicate the name of the room. See Room
    *   Events for more information on ``m.room.name``.
    * 
    * \param topic
    *   If this is included, an ``m.room.topic`` event will be sent
    *   into the room to indicate the topic for the room. See Room
    *   Events for more information on ``m.room.topic``.
    * 
    * \param invite
    *   A list of user IDs to invite to the room. This will tell the
    *   server to invite everyone in the list to the newly created room.
    * 
    * \param invite3pid
    *   A list of objects representing third party IDs to invite into
    *   the room.
    * 
    * \param roomVersion
    *   The room version to set for the room. If not provided, the node is
    *   to use its configured default. If provided, the node will return a
    *   400 error with the errcode ``M_UNSUPPORTED_ROOM_VERSION`` if it does not
    *   support the room version.
    * 
    * \param creationContent
    *   Extra keys, such as ``m.federate``, to be added to the content
    *   of the `m.room.create`_ event. The server will clobber the following
    *   keys: ``creator``, ``room_version``. Future versions of the specification
    *   may allow the server to clobber other keys.
    * 
    * \param initialState
    *   A list of state events to set in the new room. This allows
    *   the user to override the default state events set in the new
    *   room. The expected format of the state events are an object
    *   with type, state_key and content keys set.
    *   
    *   Takes precedence over events set by ``preset``, but gets
    *   overriden by ``name`` and ``topic`` keys.
    * 
    * \param preset
    *   Convenience parameter for setting various default state events
    *   based on a preset.
    *   
    *   If unspecified, the server should use the ``visibility`` to determine
    *   which preset to use. A visbility of ``public`` equates to a preset of
    *   ``public_chat`` and ``private`` visibility equates to a preset of
    *   ``private_chat``.
    * 
    * \param isDirect
    *   This flag makes the server set the ``is_direct`` flag on the
    *   ``m.room.member`` events sent to the users in ``invite`` and
    *   ``invite_3pid``. See `Direct Messaging`_ for more information.
    * 
    * \param powerLevelContentOverride
    *   The power level content to override in the default power level
    *   event. This object is applied on top of the generated `m.room.power_levels`_
    *   event content prior to it being sent to the room. Defaults to
    *   overriding nothing.
    */
    explicit CreateRoomJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::optional<std::string> visibility  = std::nullopt, std::optional<std::string> roomAliasName  = std::nullopt, std::optional<std::string> name  = std::nullopt, std::optional<std::string> topic  = std::nullopt, immer::array<std::string> invite  = {}, immer::array<Invite3pid> invite3pid  = {}, std::optional<std::string> roomVersion  = std::nullopt, JsonWrap creationContent  = {}, immer::array<StateEvent> initialState  = {}, std::optional<std::string> preset  = std::nullopt, std::optional<bool> isDirect  = std::nullopt, JsonWrap powerLevelContentOverride  = {}
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::optional<std::string> visibility, std::optional<std::string> roomAliasName, std::optional<std::string> name, std::optional<std::string> topic, immer::array<std::string> invite, immer::array<Invite3pid> invite3pid, std::optional<std::string> roomVersion, JsonWrap creationContent, immer::array<StateEvent> initialState, std::optional<std::string> preset, std::optional<bool> isDirect, JsonWrap powerLevelContentOverride);

        

        

      CreateRoomJob withData(JsonWrap j) &&;
      CreateRoomJob withData(JsonWrap j) const &;
      };
      using CreateRoomResponse = CreateRoomJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<CreateRoomJob::Invite3pid> {

  static void to_json(json& jo, const CreateRoomJob::Invite3pid &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["id_server"s] = pod.idServer;
    
    jo["id_access_token"s] = pod.idAccessToken;
    
    jo["medium"s] = pod.medium;
    
    jo["address"s] = pod.address;
    
  }

  static void from_json(const json &jo, CreateRoomJob::Invite3pid& result)
  {
  
    if (jo.contains("id_server"s)) {
      result.idServer = jo.at("id_server"s);
    }
    if (jo.contains("id_access_token"s)) {
      result.idAccessToken = jo.at("id_access_token"s);
    }
    if (jo.contains("medium"s)) {
      result.medium = jo.at("medium"s);
    }
    if (jo.contains("address"s)) {
      result.address = jo.at("address"s);
    }
  
  }

};
      template<>
      struct adl_serializer<CreateRoomJob::StateEvent> {

  static void to_json(json& jo, const CreateRoomJob::StateEvent &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["type"s] = pod.type;
    
    
    addToJsonIfNeeded(jo, "state_key"s, pod.stateKey);
    jo["content"s] = pod.content;
    
  }

  static void from_json(const json &jo, CreateRoomJob::StateEvent& result)
  {
  
    if (jo.contains("type"s)) {
      result.type = jo.at("type"s);
    }
    if (jo.contains("state_key"s)) {
      result.stateKey = jo.at("state_key"s);
    }
    if (jo.contains("content"s)) {
      result.content = jo.at("content"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
