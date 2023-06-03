/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "tags.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetRoomTagsJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetRoomTagsJob::buildBody(std::string userId, std::string roomId)
      {
      // ignore unused param
      (void)(userId);(void)(roomId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetRoomTagsJob::GetRoomTagsJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::string roomId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user/" + userId + "/rooms/" + roomId + "/tags",
          GET,
          std::string("GetRoomTags"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, roomId)
              , buildQuery()
                , {}

)
        {
        }

        GetRoomTagsJob GetRoomTagsJob::withData(JsonWrap j) &&
        {
          auto ret = GetRoomTagsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetRoomTagsJob GetRoomTagsJob::withData(JsonWrap j) const &
        {
          auto ret = GetRoomTagsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetRoomTagsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetRoomTagsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    immer::map<std::string, GetRoomTagsJob::Tag> GetRoomTagsResponse::tags() const
    {
    if (jsonBody().get()
    .contains("tags"s)) {
    return
    jsonBody().get()["tags"s]
    .template get<immer::map<std::string, Tag>>();}
    else { return immer::map<std::string, Tag>(  );}
    }


  
BaseJob::Query SetRoomTagJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetRoomTagJob::buildBody(std::string userId, std::string roomId, std::string tag, std::optional<float> order, JsonWrap additionalProperties)
      {
      // ignore unused param
      (void)(userId);(void)(roomId);(void)(tag);(void)(order);(void)(additionalProperties);
      
        json _data
        ;
          addPropertyMapToJson(_data, additionalProperties);
          
            addToJsonIfNeeded(_data, "order"s, order);
        return BaseJob::JsonBody(_data);
        

      };

      

SetRoomTagJob::SetRoomTagJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::string roomId, std::string tag, std::optional<float> order, JsonWrap additionalProperties
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user/" + userId + "/rooms/" + roomId + "/tags/" + tag,
          PUT,
          std::string("SetRoomTag"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, roomId, tag, order, additionalProperties)
              , buildQuery()
                , {}

)
        {
        }

        SetRoomTagJob SetRoomTagJob::withData(JsonWrap j) &&
        {
          auto ret = SetRoomTagJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetRoomTagJob SetRoomTagJob::withData(JsonWrap j) const &
        {
          auto ret = SetRoomTagJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetRoomTagJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetRoomTagResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query DeleteRoomTagJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body DeleteRoomTagJob::buildBody(std::string userId, std::string roomId, std::string tag)
      {
      // ignore unused param
      (void)(userId);(void)(roomId);(void)(tag);
      
      
              return BaseJob::EmptyBody{};

      };

      

DeleteRoomTagJob::DeleteRoomTagJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::string roomId, std::string tag
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user/" + userId + "/rooms/" + roomId + "/tags/" + tag,
          DELETE,
          std::string("DeleteRoomTag"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, roomId, tag)
              , buildQuery()
                , {}

)
        {
        }

        DeleteRoomTagJob DeleteRoomTagJob::withData(JsonWrap j) &&
        {
          auto ret = DeleteRoomTagJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        DeleteRoomTagJob DeleteRoomTagJob::withData(JsonWrap j) const &
        {
          auto ret = DeleteRoomTagJob(*this);
          ret.attachData(j);
          return ret;
        }

        DeleteRoomTagJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool DeleteRoomTagResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
