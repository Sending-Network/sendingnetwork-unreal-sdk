/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "profile.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SetDisplayNameJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetDisplayNameJob::buildBody(std::string userId, std::optional<std::string> displayname)
      {
      // ignore unused param
      (void)(userId);(void)(displayname);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "displayname"s, displayname);
        return BaseJob::JsonBody(_data);
        

      };

      

SetDisplayNameJob::SetDisplayNameJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::optional<std::string> displayname
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/profile/" + userId + "/displayname",
          PUT,
          std::string("SetDisplayName"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, displayname)
              , buildQuery()
                , {}

)
        {
        }

        SetDisplayNameJob SetDisplayNameJob::withData(JsonWrap j) &&
        {
          auto ret = SetDisplayNameJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetDisplayNameJob SetDisplayNameJob::withData(JsonWrap j) const &
        {
          auto ret = SetDisplayNameJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetDisplayNameJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetDisplayNameResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetDisplayNameJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetDisplayNameJob::buildBody(std::string userId)
      {
      // ignore unused param
      (void)(userId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetDisplayNameJob::GetDisplayNameJob(
        std::string serverUrl
        
            ,
        std::string userId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/profile/" + userId + "/displayname",
          GET,
          std::string("GetDisplayName"),
           {} ,
          ReturnType::Json,
            buildBody(userId)
              , buildQuery()
                , {}

)
        {
        }

        GetDisplayNameJob GetDisplayNameJob::withData(JsonWrap j) &&
        {
          auto ret = GetDisplayNameJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetDisplayNameJob GetDisplayNameJob::withData(JsonWrap j) const &
        {
          auto ret = GetDisplayNameJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetDisplayNameJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetDisplayNameResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> GetDisplayNameResponse::displayname() const
    {
    if (jsonBody().get()
    .contains("displayname"s)) {
    return
    jsonBody().get()["displayname"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }


  
BaseJob::Query SetAvatarUrlJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetAvatarUrlJob::buildBody(std::string userId, std::optional<std::string> avatarUrl)
      {
      // ignore unused param
      (void)(userId);(void)(avatarUrl);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "avatar_url"s, avatarUrl);
        return BaseJob::JsonBody(_data);
        

      };

      

SetAvatarUrlJob::SetAvatarUrlJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::optional<std::string> avatarUrl
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/profile/" + userId + "/avatar_url",
          PUT,
          std::string("SetAvatarUrl"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, avatarUrl)
              , buildQuery()
                , {}

)
        {
        }

        SetAvatarUrlJob SetAvatarUrlJob::withData(JsonWrap j) &&
        {
          auto ret = SetAvatarUrlJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetAvatarUrlJob SetAvatarUrlJob::withData(JsonWrap j) const &
        {
          auto ret = SetAvatarUrlJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetAvatarUrlJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetAvatarUrlResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetAvatarUrlJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetAvatarUrlJob::buildBody(std::string userId)
      {
      // ignore unused param
      (void)(userId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetAvatarUrlJob::GetAvatarUrlJob(
        std::string serverUrl
        
            ,
        std::string userId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/profile/" + userId + "/avatar_url",
          GET,
          std::string("GetAvatarUrl"),
           {} ,
          ReturnType::Json,
            buildBody(userId)
              , buildQuery()
                , {}

)
        {
        }

        GetAvatarUrlJob GetAvatarUrlJob::withData(JsonWrap j) &&
        {
          auto ret = GetAvatarUrlJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetAvatarUrlJob GetAvatarUrlJob::withData(JsonWrap j) const &
        {
          auto ret = GetAvatarUrlJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetAvatarUrlJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetAvatarUrlResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> GetAvatarUrlResponse::avatarUrl() const
    {
    if (jsonBody().get()
    .contains("avatar_url"s)) {
    return
    jsonBody().get()["avatar_url"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }


  
BaseJob::Query GetUserProfileJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetUserProfileJob::buildBody(std::string userId)
      {
      // ignore unused param
      (void)(userId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetUserProfileJob::GetUserProfileJob(
        std::string serverUrl
        
            ,
        std::string userId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/profile/" + userId,
          GET,
          std::string("GetUserProfile"),
           {} ,
          ReturnType::Json,
            buildBody(userId)
              , buildQuery()
                , {}

)
        {
        }

        GetUserProfileJob GetUserProfileJob::withData(JsonWrap j) &&
        {
          auto ret = GetUserProfileJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetUserProfileJob GetUserProfileJob::withData(JsonWrap j) const &
        {
          auto ret = GetUserProfileJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetUserProfileJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetUserProfileResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> GetUserProfileResponse::avatarUrl() const
    {
    if (jsonBody().get()
    .contains("avatar_url"s)) {
    return
    jsonBody().get()["avatar_url"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> GetUserProfileResponse::displayname() const
    {
    if (jsonBody().get()
    .contains("displayname"s)) {
    return
    jsonBody().get()["displayname"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

}
