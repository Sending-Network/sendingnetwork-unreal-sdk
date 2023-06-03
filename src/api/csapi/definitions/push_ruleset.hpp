/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"
#include "csapi/definitions/push_rule.hpp"

namespace Kazv::Api {

struct PushRuleset
{       

    
    immer::array<PushRule> content;

    
    immer::array<PushRule> override;

    
    immer::array<PushRule> room;

    
    immer::array<PushRule> sender;

    
    immer::array<PushRule> underride;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<PushRuleset> {
  static void to_json(json& jo, const PushRuleset &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "content"s, pod.content);
    
    addToJsonIfNeeded(jo, "override"s, pod.override);
    
    addToJsonIfNeeded(jo, "room"s, pod.room);
    
    addToJsonIfNeeded(jo, "sender"s, pod.sender);
    
    addToJsonIfNeeded(jo, "underride"s, pod.underride);
  }
  static void from_json(const json &jo, PushRuleset& result)
  {
  
    if (jo.contains("content"s)) {
      result.content = jo.at("content"s);
    }
    if (jo.contains("override"s)) {
      result.override = jo.at("override"s);
    }
    if (jo.contains("room"s)) {
      result.room = jo.at("room"s);
    }
    if (jo.contains("sender"s)) {
      result.sender = jo.at("sender"s);
    }
    if (jo.contains("underride"s)) {
      result.underride = jo.at("underride"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
