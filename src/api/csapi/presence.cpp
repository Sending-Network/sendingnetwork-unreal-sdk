/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "presence.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SetPresenceJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetPresenceJob::buildBody(std::string userId, std::string presence, std::optional<std::string> statusMsg)
      {
      // ignore unused param
      (void)(userId);(void)(presence);(void)(statusMsg);
      
        json _data
        ;
        
            _data["presence"s] = presence;
          
          
            addToJsonIfNeeded(_data, "status_msg"s, statusMsg);
        return BaseJob::JsonBody(_data);
        

      };

      

SetPresenceJob::SetPresenceJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::string presence, std::optional<std::string> statusMsg
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/presence/" + userId + "/status",
          PUT,
          std::string("SetPresence"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, presence, statusMsg)
              , buildQuery()
                , {}

)
        {
        }

        SetPresenceJob SetPresenceJob::withData(JsonWrap j) &&
        {
          auto ret = SetPresenceJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetPresenceJob SetPresenceJob::withData(JsonWrap j) const &
        {
          auto ret = SetPresenceJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetPresenceJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetPresenceResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetPresenceJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetPresenceJob::buildBody(std::string userId)
      {
      // ignore unused param
      (void)(userId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetPresenceJob::GetPresenceJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/presence/" + userId + "/status",
          GET,
          std::string("GetPresence"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId)
              , buildQuery()
                , {}

)
        {
        }

        GetPresenceJob GetPresenceJob::withData(JsonWrap j) &&
        {
          auto ret = GetPresenceJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetPresenceJob GetPresenceJob::withData(JsonWrap j) const &
        {
          auto ret = GetPresenceJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetPresenceJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetPresenceResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("presence"s)
          ;
          }


    
    std::string GetPresenceResponse::presence() const
    {
    if (jsonBody().get()
    .contains("presence"s)) {
    return
    jsonBody().get()["presence"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }

    
    std::optional<int> GetPresenceResponse::lastActiveAgo() const
    {
    if (jsonBody().get()
    .contains("last_active_ago"s)) {
    return
    jsonBody().get()["last_active_ago"s]
    .template get<int>();}
    else { return std::optional<int>(  );}
    }

    
    Variant GetPresenceResponse::statusMsg() const
    {
    if (jsonBody().get()
    .contains("status_msg"s)) {
    return
    jsonBody().get()["status_msg"s]
    .template get<Variant>();}
    else { return Variant(  );}
    }

    
    std::optional<bool> GetPresenceResponse::currentlyActive() const
    {
    if (jsonBody().get()
    .contains("currently_active"s)) {
    return
    jsonBody().get()["currently_active"s]
    .template get<bool>();}
    else { return std::optional<bool>(  );}
    }

}
