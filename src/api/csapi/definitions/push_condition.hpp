/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {

struct PushCondition
{       

/// The kind of condition to apply. See `conditions <#conditions>`_ for
/// more information on the allowed kinds and how they work.
    std::string kind;

/// Required for ``event_match`` conditions. The dot-separated field of the
/// event to match.
/// 
/// Required for ``sender_notification_permission`` conditions. The field in
/// the power level event the user needs a minimum power level for. Fields
/// must be specified under the ``notifications`` property in the power level
/// event's ``content``.
    std::optional<std::string> key;

/// Required for ``event_match`` conditions. The glob-style pattern to
/// match against. Patterns with no special glob characters should be
/// treated as having asterisks prepended and appended when testing the
/// condition.
    std::optional<std::string> pattern;

/// Required for ``room_member_count`` conditions. A decimal integer
/// optionally prefixed by one of, ==, <, >, >= or <=. A prefix of < matches
/// rooms where the member count is strictly less than the given number and
/// so forth. If no prefix is present, this parameter defaults to ==.
    std::optional<std::string> is;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<PushCondition> {
  static void to_json(json& jo, const PushCondition &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["kind"s] = pod.kind;
    
    
    addToJsonIfNeeded(jo, "key"s, pod.key);
    
    addToJsonIfNeeded(jo, "pattern"s, pod.pattern);
    
    addToJsonIfNeeded(jo, "is"s, pod.is);
  }
  static void from_json(const json &jo, PushCondition& result)
  {
  
    if (jo.contains("kind"s)) {
      result.kind = jo.at("kind"s);
    }
    if (jo.contains("key"s)) {
      result.key = jo.at("key"s);
    }
    if (jo.contains("pattern"s)) {
      result.pattern = jo.at("pattern"s);
    }
    if (jo.contains("is"s)) {
      result.is = jo.at("is"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
