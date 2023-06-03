/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "types.hpp"


namespace Kazv::Api {

struct PublicRoomsChunk
{       

/// Aliases of the room. May be empty.
    immer::array<std::string> aliases;

/// The canonical alias of the room, if any.
    std::optional<std::string> canonicalAlias;

/// The name of the room, if any.
    std::optional<std::string> name;

/// The number of members joined to the room.
    int numJoinedMembers;

/// The ID of the room.
    std::string roomId;

/// The topic of the room, if any.
    std::optional<std::string> topic;

/// Whether the room may be viewed by guest users without joining.
    bool worldReadable;

/// Whether guest users may join the room and participate in it.
/// If they can, they will be subject to ordinary power level
/// rules like any other user.
    bool guestCanJoin;

/// The URL for the room's avatar, if one is set.
    std::optional<std::string> avatarUrl;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<PublicRoomsChunk> {
  static void to_json(json& jo, const PublicRoomsChunk &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "aliases"s, pod.aliases);
    
    addToJsonIfNeeded(jo, "canonical_alias"s, pod.canonicalAlias);
    
    addToJsonIfNeeded(jo, "name"s, pod.name);
    jo["num_joined_members"s] = pod.numJoinedMembers;
    
    jo["room_id"s] = pod.roomId;
    
    
    addToJsonIfNeeded(jo, "topic"s, pod.topic);
    jo["world_readable"s] = pod.worldReadable;
    
    jo["guest_can_join"s] = pod.guestCanJoin;
    
    
    addToJsonIfNeeded(jo, "avatar_url"s, pod.avatarUrl);
  }
  static void from_json(const json &jo, PublicRoomsChunk& result)
  {
  
    if (jo.contains("aliases"s)) {
      result.aliases = jo.at("aliases"s);
    }
    if (jo.contains("canonical_alias"s)) {
      result.canonicalAlias = jo.at("canonical_alias"s);
    }
    if (jo.contains("name"s)) {
      result.name = jo.at("name"s);
    }
    if (jo.contains("num_joined_members"s)) {
      result.numJoinedMembers = jo.at("num_joined_members"s);
    }
    if (jo.contains("room_id"s)) {
      result.roomId = jo.at("room_id"s);
    }
    if (jo.contains("topic"s)) {
      result.topic = jo.at("topic"s);
    }
    if (jo.contains("world_readable"s)) {
      result.worldReadable = jo.at("world_readable"s);
    }
    if (jo.contains("guest_can_join"s)) {
      result.guestCanJoin = jo.at("guest_can_join"s);
    }
    if (jo.contains("avatar_url"s)) {
      result.avatarUrl = jo.at("avatar_url"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
/// A list of the rooms on the server.
struct PublicRoomsResponse
{       

/// A paginated chunk of public rooms.
    immer::array<PublicRoomsChunk> chunk;

/// A pagination token for the response. The absence of this token
/// means there are no more results to fetch and the client should
/// stop paginating.
    std::optional<std::string> nextBatch;

/// A pagination token that allows fetching previous results. The
/// absence of this token means there are no results before this
/// batch, i.e. this is the first batch.
    std::optional<std::string> prevBatch;

/// An estimate on the total number of public rooms, if the
/// server has an estimate.
    std::optional<int> totalRoomCountEstimate;
};

}
namespace nlohmann
{
using namespace Kazv;
using namespace Kazv::Api;
template<>
struct adl_serializer<PublicRoomsResponse> {
  static void to_json(json& jo, const PublicRoomsResponse &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["chunk"s] = pod.chunk;
    
    
    addToJsonIfNeeded(jo, "next_batch"s, pod.nextBatch);
    
    addToJsonIfNeeded(jo, "prev_batch"s, pod.prevBatch);
    
    addToJsonIfNeeded(jo, "total_room_count_estimate"s, pod.totalRoomCountEstimate);
  }
  static void from_json(const json &jo, PublicRoomsResponse& result)
  {
  
    if (jo.contains("chunk"s)) {
      result.chunk = jo.at("chunk"s);
    }
    if (jo.contains("next_batch"s)) {
      result.nextBatch = jo.at("next_batch"s);
    }
    if (jo.contains("prev_batch"s)) {
      result.prevBatch = jo.at("prev_batch"s);
    }
    if (jo.contains("total_room_count_estimate"s)) {
      result.totalRoomCountEstimate = jo.at("total_room_count_estimate"s);
    }
  
  }
};
    }

    namespace Kazv::Api
    {
} // namespace Kazv::Api
