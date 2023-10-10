#pragma once

/// @file
/// @brief Basetypes for events. Content is defined elsewhere.

#if __has_include(<nlohmann/json_fwd.hpp>)
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif

#include "sdn/events/event_type.hpp"
#include "sdn/events/messages/image.hpp"
#include "sdn/events/redaction.hpp"
#include "sdn/identifiers.hpp"

//! Top level namespace for sdnclient
namespace sdn {
namespace events {
//! The basic set of fields all events must have.
template<class Content>
struct Event
{
    //! The type of event.
    //! This *should* be namespaced similar to Java package
    //! naming conventions e.g. 'com.example.subdomain.event.type'
    EventType type;
    //! Contains the fully-qualified ID of the user who sent this event.
    std::string sender;

    //! The fields in this object will vary depending on the type of event.
    //! When interacting with the REST API, this is the HTTP body.
    Content content;

    template<class C>
    friend void to_json(nlohmann::json &obj, const Event<C> &event);
    template<class C>
    friend void from_json(const nlohmann::json &obj, Event<C> &event);
};

//! Extension of the Event type for device events.
template<class Content>
struct DeviceEvent : public Event<Content>
{
    template<class C>
    friend void from_json(const nlohmann::json &obj, DeviceEvent<C> &event);
    template<class C>
    friend void to_json(nlohmann::json &obj, const DeviceEvent<C> &event);
};

//! Additional server provided data for this event.
struct UnsignedData
{
    //! The time in milliseconds that has elapsed since the event was sent.
    //! This field is generated by the local homeserver,
    //! and may be incorrect if the local time on at least one
    //! of the two servers is out of sync, which can cause the age to
    //! either be negative or greater than it actually is.
    uint64_t age = 0;
    //! The client-supplied transaction ID, if the client
    //! being given the event is the same one which sent it.
    std::string transaction_id;
    //! The previous sender of a state event.
    std::string prev_sender;
    //! The replaced state event.
    std::string replaces_state;
    //! The event ID that redacted this event.
    std::string redacted_by;
    //! The event that redacted this event.
    std::optional<Event<sdn::events::msg::Redaction>> redacted_because;

    friend void from_json(const nlohmann::json &obj, UnsignedData &data);
    friend void to_json(nlohmann::json &obj, const UnsignedData &event);
};

template<class Content>
struct StrippedEvent : public Event<Content>
{
    std::string state_key;

    template<class C>
    friend void from_json(const nlohmann::json &obj, StrippedEvent<C> &event);
    template<class C>
    friend void to_json(nlohmann::json &obj, const StrippedEvent<C> &event);
};

//! RoomEvent.
template<class Content>
struct RoomEvent : public Event<Content>
{
    //! The globally unique event identifier.
    std::string event_id;
    //! The ID of the room associated with this event.
    std::string room_id;
    //! Timestamp in milliseconds on originating homeserver
    //! when this event was sent.
    uint64_t origin_server_ts;
    // SPEC_BUG: The contents of unsigned_data are also present as top level keys.
    //! Contains optional extra information about the event.
    UnsignedData unsigned_data;

    template<class C>
    friend void from_json(const nlohmann::json &obj, RoomEvent<C> &event);
    template<class C>
    friend void to_json(nlohmann::json &obj, const RoomEvent<C> &event);
};

//! Extension of the RoomEvent.
template<class Content>
struct StateEvent : public RoomEvent<Content>
{
    //! A unique key which defines the overwriting semantics
    //! for this piece of room state.
    std::string state_key;

    template<class C>
    friend void to_json(nlohmann::json &obj, const StateEvent<C> &event);
    template<class C>
    friend void from_json(const nlohmann::json &obj, StateEvent<C> &event);
};

//! Extension of the RoomEvent.
template<class Content>
struct RedactionEvent : public RoomEvent<Content>
{
    //! The event id of the event that was redacted.
    std::string redacts;

    template<class C>
    friend void to_json(nlohmann::json &obj, const RedactionEvent<C> &event);
    template<class C>
    friend void from_json(const nlohmann::json &obj, RedactionEvent<C> &event);
};

//! Extension of the RoomEvent.
template<class Content>
struct EncryptedEvent : public RoomEvent<Content>
{
    template<class C>
    friend void to_json(nlohmann::json &obj, const EncryptedEvent<C> &event);
    template<class C>
    friend void from_json(const nlohmann::json &obj, EncryptedEvent<C> &event);
};

enum class MessageType
{
    // m.audio
    Audio,
    // m.emote
    Emote,
    // m.file
    File,
    // m.image
    Image,
    // m.location
    Location,
    // m.notice
    Notice,
    // m.text
    Text,
    // m.video
    Video,
    /// m.key.verification.request
    KeyVerificationRequest,
    // Any of Element's custom effect msgtypes
    ElementEffect,
    // Unrecognized message type
    Unknown,

    // A redacted message that should be parsed differently
    Redacted,
    // Malformed content
    Invalid,
};

MessageType
getMessageType(const std::string &type);

MessageType
getMessageType(const nlohmann::json &obj);

struct Sticker : public RoomEvent<sdn::events::msg::StickerImage>
{};

/// @brief An ephemeral event like typing or read receipts
/// @sa Event
template<class Content>
struct EphemeralEvent
{
    //! The fields in this object will vary depending on the type of event.
    //! When interacting with the REST API, this is the HTTP body.
    Content content;
    //! The type of event.
    //! This *should* be namespaced similar to Java package
    //! naming conventions e.g. 'com.example.subdomain.event.type'
    EventType type;
    //! The room this was sent in. May not always be present.
    std::string room_id;

    template<class C>
    friend void to_json(nlohmann::json &obj, const EphemeralEvent<C> &event);
    template<class C>
    friend void from_json(const nlohmann::json &obj, EphemeralEvent<C> &event);
};

/// @brief An account_data event like fully_read or tags.
/// @sa Event
template<class Content>
using AccountDataEvent = EphemeralEvent<Content>;

} // namespace events
} // namespace sdn
