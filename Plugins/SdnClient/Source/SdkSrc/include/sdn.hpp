#pragma once

/// @file
/// @brief A header including pretty much all the headers of the library.
/// Including this will have a significant compile time cost.

#include "sdn/identifiers.hpp"

#include "sdn/events.hpp"
#include "sdn/events/aliases.hpp"
#include "sdn/events/avatar.hpp"
#include "sdn/events/canonical_alias.hpp"
#include "sdn/events/create.hpp"
#include "sdn/events/guest_access.hpp"
#include "sdn/events/history_visibility.hpp"
#include "sdn/events/join_rules.hpp"
#include "sdn/events/member.hpp"
#include "sdn/events/name.hpp"
#include "sdn/events/pinned_events.hpp"
#include "sdn/events/power_levels.hpp"
#include "sdn/events/redaction.hpp"
#include "sdn/events/tag.hpp"
#include "sdn/events/topic.hpp"
#include "sdn/events/voip.hpp"

#include "sdn/events/messages/audio.hpp"
#include "sdn/events/messages/elementeffect.hpp"
#include "sdn/events/messages/emote.hpp"
#include "sdn/events/messages/file.hpp"
#include "sdn/events/messages/image.hpp"
#include "sdn/events/messages/notice.hpp"
#include "sdn/events/messages/text.hpp"
#include "sdn/events/messages/unknown.hpp"
#include "sdn/events/messages/video.hpp"

#include "sdn/user_interactive.hpp"

#include "sdn/requests.hpp"
#include "sdn/responses.hpp"
