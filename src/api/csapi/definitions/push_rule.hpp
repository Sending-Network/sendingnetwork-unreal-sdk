/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"
#include "csapi/definitions/push_condition.hpp"

namespace Kazv::Api {

struct PushRule
{       

/// The actions to perform when this rule is matched.
    immer::array<Variant> actions;

/// Whether this is a default rule, or has been set explicitly.
    bool isDefault;

/// Whether the push rule is enabled or not.
    bool enabled;

/// The ID of this rule.
    std::string ruleId;

/// The conditions that must hold true for an event in order for a rule to be
/// applied to an event. A rule with no conditions always matches. Only
/// applicable to ``underride`` and ``override`` rules.
    immer::array<PushCondition> conditions;

/// The glob-style pattern to match against.  Only applicable to ``content``
/// rules.
    std::optional<std::string> pattern;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<PushRule> {
  static void to_json(json& jo, const PushRule &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["actions"s] = pod.actions;
    
    jo["default"s] = pod.isDefault;
    
    jo["enabled"s] = pod.enabled;
    
    jo["rule_id"s] = pod.ruleId;
    
    
    addToJsonIfNeeded(jo, "conditions"s, pod.conditions);
    
    addToJsonIfNeeded(jo, "pattern"s, pod.pattern);
  }
  static void from_json(const json &jo, PushRule& result)
  {
  
    if (jo.contains("actions"s)) {
      result.actions = jo.at("actions"s);
    }
    if (jo.contains("default"s)) {
      result.isDefault = jo.at("default"s);
    }
    if (jo.contains("enabled"s)) {
      result.enabled = jo.at("enabled"s);
    }
    if (jo.contains("rule_id"s)) {
      result.ruleId = jo.at("rule_id"s);
    }
    if (jo.contains("conditions"s)) {
      result.conditions = jo.at("conditions"s);
    }
    if (jo.contains("pattern"s)) {
      result.pattern = jo.at("pattern"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
