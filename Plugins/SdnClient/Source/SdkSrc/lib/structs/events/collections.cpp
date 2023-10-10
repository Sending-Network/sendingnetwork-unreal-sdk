#include "sdn/events/collections.hpp"
#include "sdn/events_impl.hpp"
#include "sdn/log.hpp"

#include <nlohmann/json.hpp>

namespace sdn::events {
using namespace sdn::events::collections;

#define SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(EventType, Content)                                   \
    template void to_json<Content>(nlohmann::json &, const EventType<Content> &);                  \
    template void from_json<Content>(const nlohmann::json &, EventType<Content> &);

SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::Aliases)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::Avatar)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::CanonicalAlias)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::Create)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::Encryption)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::GuestAccess)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::HistoryVisibility)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::JoinRules)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::Member)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::Name)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::PinnedEvents)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::PowerLevels)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::Tombstone)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::ServerAcl)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::Topic)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::Widget)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::policy_rule::UserRule)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::policy_rule::RoomRule)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent,
                                     sdn::events::state::policy_rule::ServerRule)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::space::Child)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::state::space::Parent)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, sdn::events::msg::Redacted)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, msc2545::ImagePack)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StateEvent, Unknown)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::EncryptedEvent, sdn::events::msg::Encrypted)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::EncryptedEvent, sdn::events::msg::OlmEncrypted)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::StickerImage)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::Reaction)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::Redacted)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::Audio)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::ElementEffect)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::Emote)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::File)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::Image)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::Notice)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::Text)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::Unknown)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::Video)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::KeyVerificationRequest)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::KeyVerificationStart)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::KeyVerificationReady)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::KeyVerificationDone)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::KeyVerificationAccept)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::KeyVerificationCancel)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::KeyVerificationKey)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::msg::KeyVerificationMac)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::voip::CallInvite)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::voip::CallCandidates)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::voip::CallAnswer)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::voip::CallHangUp)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::voip::CallSelectAnswer)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::voip::CallReject)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, sdn::events::voip::CallNegotiate)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RoomEvent, Unknown)

SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::Aliases)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::Avatar)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::CanonicalAlias)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::Create)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::Encryption)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::GuestAccess)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::HistoryVisibility)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::JoinRules)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::Member)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::Name)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::PinnedEvents)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::PowerLevels)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::Tombstone)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::ServerAcl)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::Topic)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::Widget)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent,
                                     sdn::events::state::policy_rule::UserRule)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent,
                                     sdn::events::state::policy_rule::RoomRule)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent,
                                     sdn::events::state::policy_rule::ServerRule)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::space::Child)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, sdn::events::state::space::Parent)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, msg::Redacted)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::StrippedEvent, Unknown)

SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::Encrypted)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::OlmEncrypted)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::KeyVerificationRequest)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::KeyVerificationStart)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::KeyVerificationReady)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::KeyVerificationDone)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::KeyVerificationAccept)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::KeyVerificationCancel)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::KeyVerificationKey)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::KeyVerificationMac)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::RoomKey)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::ForwardedRoomKey)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::KeyRequest)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::SecretRequest)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::SecretSend)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, sdn::events::msg::Dummy)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::DeviceEvent, Unknown)

SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::EphemeralEvent, ephemeral::Typing)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::EphemeralEvent, ephemeral::Receipt)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::EphemeralEvent, Unknown)

SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::AccountDataEvent, sdn::events::account_data::Direct)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::AccountDataEvent, sdn::events::account_data::Tags)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::AccountDataEvent, sdn::events::account_data::FullyRead)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::AccountDataEvent,
                                     sdn::events::account_data::IgnoredUsers)

SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::AccountDataEvent, pushrules::GlobalRuleset)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::AccountDataEvent,
                                     sdn::events::account_data::nheko_extensions::HiddenEvents)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::AccountDataEvent,
                                     sdn::events::account_data::nheko_extensions::EventExpiry)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::AccountDataEvent, msc2545::ImagePackRooms)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::AccountDataEvent, msc2545::ImagePack)
SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::Event, presence::Presence)

SDNCLIENT_INSTANTIATE_JSON_FUNCTIONS(events::RedactionEvent, msg::Redaction)
}

namespace sdn::events::collections {
void
to_json(nlohmann::json &obj, const TimelineEvents &e)
{
    std::visit([&obj](const auto &ev) { return to_json(obj, ev); }, e);
}

void
from_json(const nlohmann::json &obj, TimelineEvents &e)
{
    const auto type = sdn::events::getEventType(obj);
    using namespace sdn::events::state;
    using namespace sdn::events::msg;
    using namespace sdn::events::voip;

    try {
        if (obj.contains("unsigned") && obj["unsigned"].contains("redacted_by")) {
            if (obj.contains("state_key"))
                e = events::StateEvent<msg::Redacted>(obj);
            else
                e = events::RoomEvent<msg::Redacted>(obj);
            return;
        }

        switch (type) {
        case events::EventType::Reaction: {
            e = events::RoomEvent<Reaction>(obj);
            break;
        }
        case events::EventType::RoomAliases: {
            e = events::StateEvent<Aliases>(obj);
            break;
        }
        case events::EventType::RoomAvatar: {
            e = events::StateEvent<Avatar>(obj);
            break;
        }
        case events::EventType::RoomCanonicalAlias: {
            e = events::StateEvent<CanonicalAlias>(obj);
            break;
        }
        case events::EventType::RoomCreate: {
            e = events::StateEvent<Create>(obj);
            break;
        }
        case events::EventType::RoomEncrypted: {
            e = events::EncryptedEvent<sdn::events::msg::Encrypted>(obj);
            break;
        }
        case events::EventType::RoomEncryption: {
            e = events::StateEvent<Encryption>(obj);
            break;
        }
        case events::EventType::RoomGuestAccess: {
            e = events::StateEvent<GuestAccess>(obj);
            break;
        }
        case events::EventType::RoomHistoryVisibility: {
            e = events::StateEvent<HistoryVisibility>(obj);
            break;
        }
        case events::EventType::RoomJoinRules: {
            e = events::StateEvent<JoinRules>(obj);
            break;
        }
        case events::EventType::RoomMember: {
            e = events::StateEvent<Member>(obj);
            break;
        }
        case events::EventType::RoomName: {
            e = events::StateEvent<Name>(obj);
            break;
        }
        case events::EventType::RoomPowerLevels: {
            e = events::StateEvent<PowerLevels>(obj);
            break;
        }
        case events::EventType::RoomRedaction: {
            e = events::RedactionEvent<sdn::events::msg::Redaction>(obj);
            break;
        }
        case events::EventType::RoomTombstone: {
            e = events::StateEvent<Tombstone>(obj);
            break;
        }
        case events::EventType::RoomServerAcl: {
            e = events::StateEvent<ServerAcl>(obj);
            break;
        }
        case events::EventType::RoomTopic: {
            e = events::StateEvent<Topic>(obj);
            break;
        }
        case events::EventType::Widget: {
            e = events::StateEvent<Widget>(obj);
            break;
        }
        case events::EventType::VectorWidget: {
            e = events::StateEvent<Widget>(obj);
            break;
        }
        case events::EventType::RoomPinnedEvents: {
            e = events::StateEvent<PinnedEvents>(obj);
            break;
        }
        case events::EventType::PolicyRuleUser: {
            e = events::StateEvent<policy_rule::UserRule>(obj);
            break;
        }
        case events::EventType::PolicyRuleRoom: {
            e = events::StateEvent<policy_rule::RoomRule>(obj);
            break;
        }
        case events::EventType::PolicyRuleServer: {
            e = events::StateEvent<policy_rule::ServerRule>(obj);
            break;
        }
        case events::EventType::SpaceChild: {
            e = events::StateEvent<space::Child>(obj);
            break;
        }
        case events::EventType::SpaceParent: {
            e = events::StateEvent<space::Parent>(obj);
            break;
        }
        case events::EventType::ImagePackInRoom: {
            e = events::StateEvent<msc2545::ImagePack>(obj);
            break;
        }
        case events::EventType::KeyVerificationCancel: {
            e = events::RoomEvent<events::msg::KeyVerificationCancel>(obj);
            break;
        }
        case events::EventType::KeyVerificationRequest: {
            e = events::RoomEvent<events::msg::KeyVerificationRequest>(obj);
            break;
        }
        case events::EventType::KeyVerificationReady: {
            e = events::RoomEvent<events::msg::KeyVerificationReady>(obj);
            break;
        }
        case events::EventType::KeyVerificationStart: {
            e = events::RoomEvent<events::msg::KeyVerificationStart>(obj);
            break;
        }
        case events::EventType::KeyVerificationDone: {
            e = events::RoomEvent<events::msg::KeyVerificationDone>(obj);
            break;
        }
        case events::EventType::KeyVerificationKey: {
            e = events::RoomEvent<events::msg::KeyVerificationKey>(obj);
            break;
        }
        case events::EventType::KeyVerificationMac: {
            e = events::RoomEvent<events::msg::KeyVerificationMac>(obj);
            break;
        }
        case events::EventType::KeyVerificationAccept: {
            e = events::RoomEvent<events::msg::KeyVerificationAccept>(obj);
            break;
        }
        case events::EventType::RoomMessage: {
            using MsgType       = sdn::events::MessageType;
            const auto msg_type = sdn::events::getMessageType(obj.at("content"));

            switch (msg_type) {
            case MsgType::Audio: {
                e = events::RoomEvent<events::msg::Audio>(obj);
                break;
            }
            case MsgType::ElementEffect: {
                e = events::RoomEvent<events::msg::ElementEffect>(obj);
                break;
            }
            case MsgType::Emote: {
                e = events::RoomEvent<events::msg::Emote>(obj);
                break;
            }
            case MsgType::File: {
                e = events::RoomEvent<events::msg::File>(obj);
                break;
            }
            case MsgType::Image: {
                e = events::RoomEvent<events::msg::Image>(obj);
                break;
            }
            case MsgType::Location: {
                /* events::RoomEvent<events::msg::Location> location = e; */
                /* container.emplace_back(location); */
                break;
            }
            case MsgType::Notice: {
                e = events::RoomEvent<events::msg::Notice>(obj);
                break;
            }
            case MsgType::Text: {
                e = events::RoomEvent<events::msg::Text>(obj);
                break;
            }
            case MsgType::Video: {
                e = events::RoomEvent<events::msg::Video>(obj);
                break;
            }
            case MsgType::KeyVerificationRequest: {
                e = events::RoomEvent<events::msg::KeyVerificationRequest>(obj);
                break;
            }
            case MsgType::Unknown: {
                e = events::RoomEvent<events::msg::Unknown>(obj);
                break;
            }
            case MsgType::Redacted: {
                e = events::RoomEvent<events::Unknown>(obj);
                break;
            }
            case MsgType::Invalid:
                break;
            }
            break;
        }
        case events::EventType::Sticker: {
            e = events::Sticker(obj);
            break;
        }
        case events::EventType::CallInvite: {
            e = events::RoomEvent<events::voip::CallInvite>(obj);
            break;
        }
        case events::EventType::CallCandidates: {
            e = events::RoomEvent<events::voip::CallCandidates>(obj);
            break;
        }
        case events::EventType::CallAnswer: {
            e = events::RoomEvent<events::voip::CallAnswer>(obj);
            break;
        }
        case events::EventType::CallHangUp: {
            e = events::RoomEvent<events::voip::CallHangUp>(obj);
            break;
        }
        case events::EventType::CallSelectAnswer: {
            e = events::RoomEvent<events::voip::CallSelectAnswer>(obj);
            break;
        }
        case events::EventType::CallReject: {
            e = events::RoomEvent<events::voip::CallReject>(obj);
            break;
        }
        case events::EventType::CallNegotiate: {
            e = events::RoomEvent<events::voip::CallNegotiate>(obj);
            break;
        }
        case events::EventType::Unsupported: {
            e = events::RoomEvent<events::Unknown>(obj);
            break;
        }
        case events::EventType::RoomKey:          // not part of the timeline
        case events::EventType::ForwardedRoomKey: // not part of the timeline
        case events::EventType::RoomKeyRequest:   // Not part of the timeline
        case events::EventType::Direct:           // Not part of the timeline
        case events::EventType::Tag:              // Not part of the timeline
        case events::EventType::Presence:         // Not part of the timeline
        case events::EventType::PushRules:        // Not part of the timeline
        case events::EventType::SecretRequest:    // Not part of the timeline
        case events::EventType::SecretSend:       // Not part of the timeline
        case events::EventType::Typing:
        case events::EventType::Receipt:
        case events::EventType::FullyRead:
        case events::EventType::IgnoredUsers:
        case events::EventType::NhekoHiddenEvents:
        case events::EventType::NhekoEventExpiry:
        case events::EventType::ImagePackInAccountData:
        case events::EventType::ImagePackRooms:
        case events::EventType::Dummy:
            break;
        }
    } catch (std::exception &err) {
        sdn::utils::log::log()->error("Invalid event type: {} {}", err.what(), obj.dump(2));
        e = events::RoomEvent<events::Unknown>(obj);
    }
}
}
