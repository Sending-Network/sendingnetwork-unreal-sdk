/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "create_room.hpp"

namespace Kazv::Api
{

  
BaseJob::Query CreateRoomJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body CreateRoomJob::buildBody(std::optional<std::string> visibility, std::optional<std::string> roomAliasName, std::optional<std::string> name, std::optional<std::string> topic, immer::array<std::string> invite, immer::array<Invite3pid> invite3pid, std::optional<std::string> roomVersion, JsonWrap creationContent, immer::array<StateEvent> initialState, std::optional<std::string> preset, std::optional<bool> isDirect, JsonWrap powerLevelContentOverride)
      {
      // ignore unused param
      (void)(visibility);(void)(roomAliasName);(void)(name);(void)(topic);(void)(invite);(void)(invite3pid);(void)(roomVersion);(void)(creationContent);(void)(initialState);(void)(preset);(void)(isDirect);(void)(powerLevelContentOverride);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "visibility"s, visibility);
          
            addToJsonIfNeeded(_data, "room_alias_name"s, roomAliasName);
          
            addToJsonIfNeeded(_data, "name"s, name);
          
            addToJsonIfNeeded(_data, "topic"s, topic);
          
            addToJsonIfNeeded(_data, "invite"s, invite);
          
            addToJsonIfNeeded(_data, "invite_3pid"s, invite3pid);
          
            addToJsonIfNeeded(_data, "room_version"s, roomVersion);
          
            addToJsonIfNeeded(_data, "creation_content"s, creationContent);
          
            addToJsonIfNeeded(_data, "initial_state"s, initialState);
          
            addToJsonIfNeeded(_data, "preset"s, preset);
          
            addToJsonIfNeeded(_data, "is_direct"s, isDirect);
          
            addToJsonIfNeeded(_data, "power_level_content_override"s, powerLevelContentOverride);
        return BaseJob::JsonBody(_data);
        

      };

      

CreateRoomJob::CreateRoomJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::optional<std::string> visibility, std::optional<std::string> roomAliasName, std::optional<std::string> name, std::optional<std::string> topic, immer::array<std::string> invite, immer::array<Invite3pid> invite3pid, std::optional<std::string> roomVersion, JsonWrap creationContent, immer::array<StateEvent> initialState, std::optional<std::string> preset, std::optional<bool> isDirect, JsonWrap powerLevelContentOverride
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/createRoom",
          POST,
          std::string("CreateRoom"),
          _accessToken,
          ReturnType::Json,
            buildBody(visibility, roomAliasName, name, topic, invite, invite3pid, roomVersion, creationContent, initialState, preset, isDirect, powerLevelContentOverride)
              , buildQuery()
                , {}

)
        {
        }

        CreateRoomJob CreateRoomJob::withData(JsonWrap j) &&
        {
          auto ret = CreateRoomJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        CreateRoomJob CreateRoomJob::withData(JsonWrap j) const &
        {
          auto ret = CreateRoomJob(*this);
          ret.attachData(j);
          return ret;
        }

        CreateRoomJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool CreateRoomResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("room_id"s)
          ;
          }


    
    std::string CreateRoomResponse::roomId() const
    {
    if (jsonBody().get()
    .contains("room_id"s)) {
    return
    jsonBody().get()["room_id"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }

}
