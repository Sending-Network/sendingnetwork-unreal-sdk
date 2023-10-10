#pragma once

/// @file
/// @brief Collections to store multiple events of different types

#include <variant>

#include "sdn/events.hpp"
#include "sdn/events/account_data/direct.hpp"
#include "sdn/events/account_data/fully_read.hpp"
#include "sdn/events/account_data/ignored_users.hpp"
#include "sdn/events/aliases.hpp"
#include "sdn/events/avatar.hpp"
#include "sdn/events/canonical_alias.hpp"
#include "sdn/events/create.hpp"
#include "sdn/events/encrypted.hpp"
#include "sdn/events/encryption.hpp"
#include "sdn/events/ephemeral/receipt.hpp"
#include "sdn/events/ephemeral/typing.hpp"
#include "sdn/events/guest_access.hpp"
#include "sdn/events/history_visibility.hpp"
#include "sdn/events/join_rules.hpp"
#include "sdn/events/member.hpp"
#include "sdn/events/mscs/image_packs.hpp"
#include "sdn/events/name.hpp"
#include "sdn/events/nheko_extensions/event_expiry.hpp"
#include "sdn/events/nheko_extensions/hidden_events.hpp"
#include "sdn/events/pinned_events.hpp"
#include "sdn/events/policy_rules.hpp"
#include "sdn/events/power_levels.hpp"
#include "sdn/events/presence.hpp"
#include "sdn/events/reaction.hpp"
#include "sdn/events/redaction.hpp"
#include "sdn/events/server_acl.hpp"
#include "sdn/events/spaces.hpp"
#include "sdn/events/tag.hpp"
#include "sdn/events/tombstone.hpp"
#include "sdn/events/topic.hpp"
#include "sdn/events/unknown.hpp"
#include "sdn/events/voip.hpp"
#include "sdn/events/widget.hpp"
#include "sdn/pushrules.hpp"

#include "sdn/events/messages/audio.hpp"
#include "sdn/events/messages/elementeffect.hpp"
#include "sdn/events/messages/emote.hpp"
#include "sdn/events/messages/file.hpp"
#include "sdn/events/messages/image.hpp"
#include "sdn/events/messages/notice.hpp"
#include "sdn/events/messages/text.hpp"
#include "sdn/events/messages/unknown.hpp"
#include "sdn/events/messages/video.hpp"

namespace sdn {
namespace events {

//! Contains heterogeneous collections of events using std::variant.
namespace collections {

//! Collection of key verification events
struct DeviceEvents
  : public std::variant<sdn::events::DeviceEvent<sdn::events::msg::RoomKey>,
                        sdn::events::DeviceEvent<sdn::events::msg::ForwardedRoomKey>,
                        sdn::events::DeviceEvent<sdn::events::msg::KeyRequest>,
                        sdn::events::DeviceEvent<sdn::events::msg::OlmEncrypted>,
                        sdn::events::DeviceEvent<sdn::events::msg::Encrypted>,
                        sdn::events::DeviceEvent<sdn::events::msg::Dummy>,
                        sdn::events::DeviceEvent<sdn::events::msg::KeyVerificationRequest>,
                        sdn::events::DeviceEvent<sdn::events::msg::KeyVerificationStart>,
                        sdn::events::DeviceEvent<sdn::events::msg::KeyVerificationReady>,
                        sdn::events::DeviceEvent<sdn::events::msg::KeyVerificationDone>,
                        sdn::events::DeviceEvent<sdn::events::msg::KeyVerificationAccept>,
                        sdn::events::DeviceEvent<sdn::events::msg::KeyVerificationCancel>,
                        sdn::events::DeviceEvent<sdn::events::msg::KeyVerificationKey>,
                        sdn::events::DeviceEvent<sdn::events::msg::KeyVerificationMac>,
                        sdn::events::DeviceEvent<sdn::events::msg::SecretRequest>,
                        sdn::events::DeviceEvent<sdn::events::msg::SecretSend>,
                        sdn::events::DeviceEvent<sdn::events::Unknown>>
{
    using variant::variant;
};

//! Collection of room specific account data
struct RoomAccountDataEvents
  : public std::variant<
      sdn::events::AccountDataEvent<sdn::events::account_data::Tags>,
      sdn::events::AccountDataEvent<sdn::events::account_data::Direct>,
      sdn::events::AccountDataEvent<sdn::events::account_data::FullyRead>,
      sdn::events::AccountDataEvent<sdn::events::account_data::IgnoredUsers>,
      sdn::events::AccountDataEvent<sdn::pushrules::GlobalRuleset>,
      sdn::events::AccountDataEvent<sdn::events::account_data::nheko_extensions::HiddenEvents>,
      sdn::events::AccountDataEvent<sdn::events::account_data::nheko_extensions::EventExpiry>,
      sdn::events::AccountDataEvent<sdn::events::msc2545::ImagePack>,
      sdn::events::AccountDataEvent<sdn::events::msc2545::ImagePackRooms>,
      sdn::events::AccountDataEvent<sdn::events::Unknown>>
{
    using variant::variant;
};

//! Collection of @p StateEvent only.
struct StateEvents
  : public std::variant<sdn::events::StateEvent<sdn::events::state::Aliases>,
                        sdn::events::StateEvent<sdn::events::state::Avatar>,
                        sdn::events::StateEvent<sdn::events::state::CanonicalAlias>,
                        sdn::events::StateEvent<sdn::events::state::Create>,
                        sdn::events::StateEvent<sdn::events::state::Encryption>,
                        sdn::events::StateEvent<sdn::events::state::GuestAccess>,
                        sdn::events::StateEvent<sdn::events::state::HistoryVisibility>,
                        sdn::events::StateEvent<sdn::events::state::JoinRules>,
                        sdn::events::StateEvent<sdn::events::state::Member>,
                        sdn::events::StateEvent<sdn::events::state::Name>,
                        sdn::events::StateEvent<sdn::events::state::PinnedEvents>,
                        sdn::events::StateEvent<sdn::events::state::PowerLevels>,
                        sdn::events::StateEvent<sdn::events::state::policy_rule::UserRule>,
                        sdn::events::StateEvent<sdn::events::state::policy_rule::RoomRule>,
                        sdn::events::StateEvent<sdn::events::state::policy_rule::ServerRule>,
                        sdn::events::StateEvent<sdn::events::state::space::Child>,
                        sdn::events::StateEvent<sdn::events::state::space::Parent>,
                        sdn::events::StateEvent<sdn::events::state::Tombstone>,
                        sdn::events::StateEvent<sdn::events::state::ServerAcl>,
                        sdn::events::StateEvent<sdn::events::state::Topic>,
                        sdn::events::StateEvent<sdn::events::state::Widget>,
                        sdn::events::StateEvent<sdn::events::msg::Redacted>,
                        sdn::events::StateEvent<sdn::events::msc2545::ImagePack>,
                        sdn::events::StateEvent<sdn::events::Unknown>>
{
    using variant::variant;
};

//! Collection of @p StrippedEvent only.
struct StrippedEvents
  : public std::variant<sdn::events::StrippedEvent<sdn::events::state::Aliases>,
                        sdn::events::StrippedEvent<sdn::events::state::Avatar>,
                        sdn::events::StrippedEvent<sdn::events::state::CanonicalAlias>,
                        sdn::events::StrippedEvent<sdn::events::state::Create>,
                        sdn::events::StrippedEvent<sdn::events::state::Encryption>,
                        sdn::events::StrippedEvent<sdn::events::state::GuestAccess>,
                        sdn::events::StrippedEvent<sdn::events::state::HistoryVisibility>,
                        sdn::events::StrippedEvent<sdn::events::state::JoinRules>,
                        sdn::events::StrippedEvent<sdn::events::state::Member>,
                        sdn::events::StrippedEvent<sdn::events::state::Name>,
                        sdn::events::StrippedEvent<sdn::events::state::PinnedEvents>,
                        sdn::events::StrippedEvent<sdn::events::state::PowerLevels>,
                        sdn::events::StrippedEvent<sdn::events::state::policy_rule::UserRule>,
                        sdn::events::StrippedEvent<sdn::events::state::policy_rule::RoomRule>,
                        sdn::events::StrippedEvent<sdn::events::state::policy_rule::ServerRule>,
                        sdn::events::StrippedEvent<sdn::events::state::space::Child>,
                        sdn::events::StrippedEvent<sdn::events::state::space::Parent>,
                        sdn::events::StrippedEvent<sdn::events::state::Tombstone>,
                        sdn::events::StrippedEvent<sdn::events::state::ServerAcl>,
                        sdn::events::StrippedEvent<sdn::events::state::Topic>,
                        sdn::events::StrippedEvent<sdn::events::state::Widget>,
                        sdn::events::StrippedEvent<sdn::events::msg::Redacted>,
                        sdn::events::StrippedEvent<sdn::events::Unknown>>
{
    using variant::variant;
};

//! Collection of @p StateEvent and @p RoomEvent. Those events would be
//! available on the returned timeline.
struct TimelineEvents
  : public std::variant<sdn::events::StateEvent<sdn::events::state::Aliases>,
                        sdn::events::StateEvent<sdn::events::state::Avatar>,
                        sdn::events::StateEvent<sdn::events::state::CanonicalAlias>,
                        sdn::events::StateEvent<sdn::events::state::Create>,
                        sdn::events::StateEvent<sdn::events::state::Encryption>,
                        sdn::events::StateEvent<sdn::events::state::GuestAccess>,
                        sdn::events::StateEvent<sdn::events::state::HistoryVisibility>,
                        sdn::events::StateEvent<sdn::events::state::JoinRules>,
                        sdn::events::StateEvent<sdn::events::state::Member>,
                        sdn::events::StateEvent<sdn::events::state::Name>,
                        sdn::events::StateEvent<sdn::events::state::PinnedEvents>,
                        sdn::events::StateEvent<sdn::events::state::PowerLevels>,
                        sdn::events::StateEvent<sdn::events::state::policy_rule::UserRule>,
                        sdn::events::StateEvent<sdn::events::state::policy_rule::RoomRule>,
                        sdn::events::StateEvent<sdn::events::state::policy_rule::ServerRule>,
                        sdn::events::StateEvent<sdn::events::state::space::Child>,
                        sdn::events::StateEvent<sdn::events::state::space::Parent>,
                        sdn::events::StateEvent<sdn::events::state::Tombstone>,
                        sdn::events::StateEvent<sdn::events::state::ServerAcl>,
                        sdn::events::StateEvent<sdn::events::state::Topic>,
                        sdn::events::StateEvent<sdn::events::state::Widget>,
                        sdn::events::StateEvent<sdn::events::msc2545::ImagePack>,
                        sdn::events::StateEvent<sdn::events::msg::Redacted>,
                        sdn::events::EncryptedEvent<sdn::events::msg::Encrypted>,
                        sdn::events::RedactionEvent<sdn::events::msg::Redaction>,
                        sdn::events::Sticker,
                        sdn::events::RoomEvent<sdn::events::msg::Reaction>,
                        sdn::events::RoomEvent<sdn::events::msg::Redacted>,
                        sdn::events::RoomEvent<sdn::events::msg::Audio>,
                        sdn::events::RoomEvent<sdn::events::msg::ElementEffect>,
                        sdn::events::RoomEvent<sdn::events::msg::Emote>,
                        sdn::events::RoomEvent<sdn::events::msg::File>,
                        sdn::events::RoomEvent<sdn::events::msg::Image>,
                        // TODO: events::RoomEvent<sdn::events::msg::Location>,
                        sdn::events::RoomEvent<sdn::events::msg::Notice>,
                        sdn::events::RoomEvent<sdn::events::msg::Text>,
                        sdn::events::RoomEvent<sdn::events::msg::Unknown>,
                        sdn::events::RoomEvent<sdn::events::msg::Video>,
                        sdn::events::RoomEvent<sdn::events::msg::KeyVerificationRequest>,
                        sdn::events::RoomEvent<sdn::events::msg::KeyVerificationStart>,
                        sdn::events::RoomEvent<sdn::events::msg::KeyVerificationReady>,
                        sdn::events::RoomEvent<sdn::events::msg::KeyVerificationDone>,
                        sdn::events::RoomEvent<sdn::events::msg::KeyVerificationAccept>,
                        sdn::events::RoomEvent<sdn::events::msg::KeyVerificationCancel>,
                        sdn::events::RoomEvent<sdn::events::msg::KeyVerificationKey>,
                        sdn::events::RoomEvent<sdn::events::msg::KeyVerificationMac>,
                        sdn::events::RoomEvent<sdn::events::voip::CallCandidates>,
                        sdn::events::RoomEvent<sdn::events::voip::CallInvite>,
                        sdn::events::RoomEvent<sdn::events::voip::CallAnswer>,
                        sdn::events::RoomEvent<sdn::events::voip::CallHangUp>,
                        sdn::events::RoomEvent<sdn::events::voip::CallSelectAnswer>,
                        sdn::events::RoomEvent<sdn::events::voip::CallReject>,
                        sdn::events::RoomEvent<sdn::events::voip::CallNegotiate>,
                        sdn::events::RoomEvent<sdn::events::Unknown>>
{
    using variant::variant;

    // The Qt MOC chokes on this, because the default implementation from the variant gets into some
    // conflict with the variant types not having an operator==. Being explicit fixes that.
    bool operator==(const TimelineEvents &) const = delete;
    bool operator<(const TimelineEvents &) const  = delete;

    friend void from_json(const nlohmann::json &obj, TimelineEvents &e);
    friend void to_json(nlohmann::json &obj, const TimelineEvents &e);
};

struct EphemeralEvents
  : public std::variant<sdn::events::EphemeralEvent<sdn::events::ephemeral::Typing>,
                        sdn::events::EphemeralEvent<sdn::events::ephemeral::Receipt>,
                        sdn::events::EphemeralEvent<sdn::events::Unknown>>
{
    using variant::variant;
};

} // namespace collections

//! Get the right event type for some type of message content.
template<typename Content>
constexpr inline EventType message_content_to_type = EventType::Unsupported;

template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::Encrypted> =
  EventType::RoomEncrypted;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::Reaction> =
  EventType::Reaction;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::Audio> =
  EventType::RoomMessage;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::Emote> =
  EventType::RoomMessage;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::File> = EventType::RoomMessage;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::Image> =
  EventType::RoomMessage;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::Notice> =
  EventType::RoomMessage;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::Text> = EventType::RoomMessage;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::Unknown> =
  EventType::RoomMessage;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::Video> =
  EventType::RoomMessage;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::ElementEffect> =
  EventType::RoomMessage;
template<>
constexpr inline EventType message_content_to_type<sdn::events::msg::StickerImage> =
  EventType::Sticker;
template<>
constexpr inline EventType message_content_to_type<sdn::events::voip::CallInvite> =
  EventType::CallInvite;
template<>
constexpr inline EventType message_content_to_type<sdn::events::voip::CallCandidates> =
  EventType::CallCandidates;
template<>
constexpr inline EventType message_content_to_type<sdn::events::voip::CallAnswer> =
  EventType::CallAnswer;
template<>
constexpr inline EventType message_content_to_type<sdn::events::voip::CallHangUp> =
  EventType::CallHangUp;
template<>
constexpr inline EventType message_content_to_type<sdn::events::voip::CallSelectAnswer> =
  EventType::CallSelectAnswer;
template<>
constexpr inline EventType message_content_to_type<sdn::events::voip::CallReject> =
  EventType::CallReject;
template<>
constexpr inline EventType message_content_to_type<sdn::events::voip::CallNegotiate> =
  EventType::CallNegotiate;

//! Get the right event type for some type of state event content.
template<typename Content>
constexpr inline EventType state_content_to_type = EventType::Unsupported;

template<>
constexpr inline EventType state_content_to_type<sdn::events::state::Aliases> =
  EventType::RoomAliases;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::Avatar> =
  EventType::RoomAvatar;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::CanonicalAlias> =
  EventType::RoomCanonicalAlias;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::Create> =
  EventType::RoomCreate;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::Encryption> =
  EventType::RoomEncryption;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::GuestAccess> =
  EventType::RoomGuestAccess;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::HistoryVisibility> =
  EventType::RoomHistoryVisibility;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::JoinRules> =
  EventType::RoomJoinRules;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::Member> =
  EventType::RoomMember;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::Name> = EventType::RoomName;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::PinnedEvents> =
  EventType::RoomPinnedEvents;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::policy_rule::UserRule> =
  EventType::PolicyRuleUser;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::policy_rule::RoomRule> =
  EventType::PolicyRuleRoom;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::policy_rule::ServerRule> =
  EventType::PolicyRuleServer;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::PowerLevels> =
  EventType::RoomPowerLevels;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::Tombstone> =
  EventType::RoomTombstone;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::ServerAcl> =
  EventType::RoomServerAcl;

template<>
constexpr inline EventType state_content_to_type<sdn::events::state::space::Child> =
  EventType::SpaceChild;
template<>
constexpr inline EventType state_content_to_type<sdn::events::state::space::Parent> =
  EventType::SpaceParent;

template<>
constexpr inline EventType state_content_to_type<sdn::events::state::Widget> =
  EventType::VectorWidget;

template<>
constexpr inline EventType state_content_to_type<sdn::events::state::Topic> = EventType::RoomTopic;
template<>
constexpr inline EventType state_content_to_type<sdn::events::msc2545::ImagePack> =
  EventType::ImagePackInRoom;

//! Get the right event type for some type of device message content.
template<typename Content>
constexpr inline EventType to_device_content_to_type = EventType::Unsupported;

template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::RoomKey> =
  EventType::RoomKey;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::ForwardedRoomKey> =
  EventType::ForwardedRoomKey;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::KeyRequest> =
  EventType::RoomKeyRequest;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::OlmEncrypted> =
  EventType::RoomEncrypted;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::Encrypted> =
  EventType::RoomEncrypted;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::Dummy> = EventType::Dummy;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::KeyVerificationRequest> =
  EventType::KeyVerificationRequest;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::KeyVerificationStart> =
  EventType::KeyVerificationStart;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::KeyVerificationReady> =
  EventType::KeyVerificationReady;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::KeyVerificationDone> =
  EventType::KeyVerificationDone;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::KeyVerificationAccept> =
  EventType::KeyVerificationAccept;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::KeyVerificationCancel> =
  EventType::KeyVerificationCancel;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::KeyVerificationKey> =
  EventType::KeyVerificationKey;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::KeyVerificationMac> =
  EventType::KeyVerificationMac;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::SecretSend> =
  EventType::SecretSend;
template<>
constexpr inline EventType to_device_content_to_type<sdn::events::msg::SecretRequest> =
  EventType::SecretRequest;

//! Get the right event type for some type of account_data event content.
template<typename Content>
constexpr inline EventType account_data_content_to_type = EventType::Unsupported;

template<>
constexpr inline EventType account_data_content_to_type<sdn::events::msc2545::ImagePack> =
  EventType::ImagePackInAccountData;
template<>
constexpr inline EventType account_data_content_to_type<sdn::events::msc2545::ImagePackRooms> =
  EventType::ImagePackRooms;
template<>
constexpr inline EventType account_data_content_to_type<sdn::events::account_data::Tags> =
  EventType::Tag;
template<>
constexpr inline EventType account_data_content_to_type<sdn::events::account_data::Direct> =
  EventType::Direct;
template<>
constexpr inline EventType account_data_content_to_type<sdn::events::account_data::IgnoredUsers> =
  EventType::IgnoredUsers;
template<>
constexpr inline EventType
  account_data_content_to_type<sdn::events::account_data::nheko_extensions::HiddenEvents> =
    EventType::NhekoHiddenEvents;
template<>
constexpr inline EventType
  account_data_content_to_type<sdn::events::account_data::nheko_extensions::EventExpiry> =
    EventType::NhekoEventExpiry;

} // namespace events
} // namespace sdn
