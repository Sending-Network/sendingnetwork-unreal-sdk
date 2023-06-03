/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "login.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetLoginFlowsJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetLoginFlowsJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetLoginFlowsJob::GetLoginFlowsJob(
        std::string serverUrl
        
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/login",
          GET,
          std::string("GetLoginFlows"),
           {} ,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetLoginFlowsJob GetLoginFlowsJob::withData(JsonWrap j) &&
        {
          auto ret = GetLoginFlowsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetLoginFlowsJob GetLoginFlowsJob::withData(JsonWrap j) const &
        {
          auto ret = GetLoginFlowsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetLoginFlowsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetLoginFlowsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    immer::array<GetLoginFlowsJob::LoginFlow> GetLoginFlowsResponse::flows() const
    {
    if (jsonBody().get()
    .contains("flows"s)) {
    return
    jsonBody().get()["flows"s]
    .template get<immer::array<LoginFlow>>();}
    else { return immer::array<LoginFlow>(  );}
    }


  
BaseJob::Query LoginJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body LoginJob::buildBody(std::string type, std::optional<UserIdentifier> identifier, std::optional<std::string> password, std::optional<std::string> token, std::optional<std::string> deviceId, std::optional<std::string> initialDeviceDisplayName)
      {
      // ignore unused param
      (void)(type);(void)(identifier);(void)(password);(void)(token);(void)(deviceId);(void)(initialDeviceDisplayName);
      
        json _data
        ;
        
            _data["type"s] = type;
          
          
            addToJsonIfNeeded(_data, "identifier"s, identifier);
          
            addToJsonIfNeeded(_data, "password"s, password);
          
            addToJsonIfNeeded(_data, "token"s, token);
          
            addToJsonIfNeeded(_data, "device_id"s, deviceId);
          
            addToJsonIfNeeded(_data, "initial_device_display_name"s, initialDeviceDisplayName);
        return BaseJob::JsonBody(_data);
        

      };

      

LoginJob::LoginJob(
        std::string serverUrl
        
            ,
        std::string type, std::optional<UserIdentifier> identifier, std::optional<std::string> password, std::optional<std::string> token, std::optional<std::string> deviceId, std::optional<std::string> initialDeviceDisplayName
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/login",
          POST,
          std::string("Login"),
           {} ,
          ReturnType::Json,
            buildBody(type, identifier, password, token, deviceId, initialDeviceDisplayName)
              , buildQuery()
                , {}

)
        {
        }

        LoginJob LoginJob::withData(JsonWrap j) &&
        {
          auto ret = LoginJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        LoginJob LoginJob::withData(JsonWrap j) const &
        {
          auto ret = LoginJob(*this);
          ret.attachData(j);
          return ret;
        }

        LoginJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool LoginResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> LoginResponse::userId() const
    {
    if (jsonBody().get()
    .contains("user_id"s)) {
    return
    jsonBody().get()["user_id"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> LoginResponse::accessToken() const
    {
    if (jsonBody().get()
    .contains("access_token"s)) {
    return
    jsonBody().get()["access_token"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> LoginResponse::node() const
    {
    if (jsonBody().get()
    .contains("home_server"s)) {
    return
    jsonBody().get()["home_server"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> LoginResponse::deviceId() const
    {
    if (jsonBody().get()
    .contains("device_id"s)) {
    return
    jsonBody().get()["device_id"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<DiscoveryInformation> LoginResponse::wellKnown() const
    {
    if (jsonBody().get()
    .contains("well_known"s)) {
    return
    jsonBody().get()["well_known"s]
    .template get<DiscoveryInformation>();}
    else { return std::optional<DiscoveryInformation>(  );}
    }

}
