/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "pusher.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetPushersJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetPushersJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetPushersJob::GetPushersJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/pushers",
          GET,
          std::string("GetPushers"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetPushersJob GetPushersJob::withData(JsonWrap j) &&
        {
          auto ret = GetPushersJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetPushersJob GetPushersJob::withData(JsonWrap j) const &
        {
          auto ret = GetPushersJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetPushersJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetPushersResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    immer::array<GetPushersJob::Pusher> GetPushersResponse::pushers() const
    {
    if (jsonBody().get()
    .contains("pushers"s)) {
    return
    jsonBody().get()["pushers"s]
    .template get<immer::array<Pusher>>();}
    else { return immer::array<Pusher>(  );}
    }


  
BaseJob::Query PostPusherJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body PostPusherJob::buildBody(std::string pushkey, std::string kind, std::string appId, std::string appDisplayName, std::string deviceDisplayName, std::string lang, PusherData data, std::optional<std::string> profileTag, std::optional<bool> append)
      {
      // ignore unused param
      (void)(pushkey);(void)(kind);(void)(appId);(void)(appDisplayName);(void)(deviceDisplayName);(void)(lang);(void)(data);(void)(profileTag);(void)(append);
      
        json _data
        ;
        
            _data["pushkey"s] = pushkey;
          
            _data["kind"s] = kind;
          
            _data["app_id"s] = appId;
          
            _data["app_display_name"s] = appDisplayName;
          
            _data["device_display_name"s] = deviceDisplayName;
          
          
            addToJsonIfNeeded(_data, "profile_tag"s, profileTag);
            _data["lang"s] = lang;
          
            _data["data"s] = data;
          
          
            addToJsonIfNeeded(_data, "append"s, append);
        return BaseJob::JsonBody(_data);
        

      };

      

PostPusherJob::PostPusherJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string pushkey, std::string kind, std::string appId, std::string appDisplayName, std::string deviceDisplayName, std::string lang, PusherData data, std::optional<std::string> profileTag, std::optional<bool> append
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/pushers/set",
          POST,
          std::string("PostPusher"),
          _accessToken,
          ReturnType::Json,
            buildBody(pushkey, kind, appId, appDisplayName, deviceDisplayName, lang, data, profileTag, append)
              , buildQuery()
                , {}

)
        {
        }

        PostPusherJob PostPusherJob::withData(JsonWrap j) &&
        {
          auto ret = PostPusherJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        PostPusherJob PostPusherJob::withData(JsonWrap j) const &
        {
          auto ret = PostPusherJob(*this);
          ret.attachData(j);
          return ret;
        }

        PostPusherJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool PostPusherResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
