/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "registration.hpp"

namespace Kazv::Api
{

  
BaseJob::Query RegisterJob::buildQuery(
std::string kind)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "kind"s, kind);
return _q;
}

    BaseJob::Body RegisterJob::buildBody(std::string kind, std::optional<AuthenticationData> auth, std::optional<std::string> username, std::optional<std::string> password, std::optional<std::string> deviceId, std::optional<std::string> initialDeviceDisplayName, std::optional<bool> inhibitLogin)
      {
      // ignore unused param
      (void)(kind);(void)(auth);(void)(username);(void)(password);(void)(deviceId);(void)(initialDeviceDisplayName);(void)(inhibitLogin);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "auth"s, auth);
          
            addToJsonIfNeeded(_data, "username"s, username);
          
            addToJsonIfNeeded(_data, "password"s, password);
          
            addToJsonIfNeeded(_data, "device_id"s, deviceId);
          
            addToJsonIfNeeded(_data, "initial_device_display_name"s, initialDeviceDisplayName);
          
            addToJsonIfNeeded(_data, "inhibit_login"s, inhibitLogin);
        return BaseJob::JsonBody(_data);
        

      };

      

RegisterJob::RegisterJob(
        std::string serverUrl
        
            ,
        std::string kind, std::optional<AuthenticationData> auth, std::optional<std::string> username, std::optional<std::string> password, std::optional<std::string> deviceId, std::optional<std::string> initialDeviceDisplayName, std::optional<bool> inhibitLogin
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/register",
          POST,
          std::string("Register"),
           {} ,
          ReturnType::Json,
            buildBody(kind, auth, username, password, deviceId, initialDeviceDisplayName, inhibitLogin)
              , buildQuery(kind)
                , {}

)
        {
        }

        RegisterJob RegisterJob::withData(JsonWrap j) &&
        {
          auto ret = RegisterJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RegisterJob RegisterJob::withData(JsonWrap j) const &
        {
          auto ret = RegisterJob(*this);
          ret.attachData(j);
          return ret;
        }

        RegisterJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool RegisterResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("user_id"s)
          ;
          }


    
    std::string RegisterResponse::userId() const
    {
    if (jsonBody().get()
    .contains("user_id"s)) {
    return
    jsonBody().get()["user_id"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }

    
    std::optional<std::string> RegisterResponse::accessToken() const
    {
    if (jsonBody().get()
    .contains("access_token"s)) {
    return
    jsonBody().get()["access_token"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> RegisterResponse::node() const
    {
    if (jsonBody().get()
    .contains("home_server"s)) {
    return
    jsonBody().get()["home_server"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    std::optional<std::string> RegisterResponse::deviceId() const
    {
    if (jsonBody().get()
    .contains("device_id"s)) {
    return
    jsonBody().get()["device_id"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }


  
BaseJob::Query RequestTokenToRegisterEmailJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body RequestTokenToRegisterEmailJob::buildBody(EmailValidationData body)
      {
      // ignore unused param
      (void)(body);
        return 
          JsonBody(body);
      
          

      };

      

RequestTokenToRegisterEmailJob::RequestTokenToRegisterEmailJob(
        std::string serverUrl
        
            ,
        EmailValidationData body
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/register/email/requestToken",
          POST,
          std::string("RequestTokenToRegisterEmail"),
           {} ,
          ReturnType::Json,
            buildBody(body)
              , buildQuery()
                , {}

)
        {
        }

        RequestTokenToRegisterEmailJob RequestTokenToRegisterEmailJob::withData(JsonWrap j) &&
        {
          auto ret = RequestTokenToRegisterEmailJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RequestTokenToRegisterEmailJob RequestTokenToRegisterEmailJob::withData(JsonWrap j) const &
        {
          auto ret = RequestTokenToRegisterEmailJob(*this);
          ret.attachData(j);
          return ret;
        }

        RequestTokenToRegisterEmailJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool RequestTokenToRegisterEmailResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query RequestTokenToRegisterMSISDNJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body RequestTokenToRegisterMSISDNJob::buildBody(MsisdnValidationData body)
      {
      // ignore unused param
      (void)(body);
        return 
          JsonBody(body);
      
          

      };

      

RequestTokenToRegisterMSISDNJob::RequestTokenToRegisterMSISDNJob(
        std::string serverUrl
        
            ,
        MsisdnValidationData body
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/register/msisdn/requestToken",
          POST,
          std::string("RequestTokenToRegisterMSISDN"),
           {} ,
          ReturnType::Json,
            buildBody(body)
              , buildQuery()
                , {}

)
        {
        }

        RequestTokenToRegisterMSISDNJob RequestTokenToRegisterMSISDNJob::withData(JsonWrap j) &&
        {
          auto ret = RequestTokenToRegisterMSISDNJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RequestTokenToRegisterMSISDNJob RequestTokenToRegisterMSISDNJob::withData(JsonWrap j) const &
        {
          auto ret = RequestTokenToRegisterMSISDNJob(*this);
          ret.attachData(j);
          return ret;
        }

        RequestTokenToRegisterMSISDNJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool RequestTokenToRegisterMSISDNResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query ChangePasswordJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body ChangePasswordJob::buildBody(std::string newPassword, std::optional<bool> logoutDevices, std::optional<AuthenticationData> auth)
      {
      // ignore unused param
      (void)(newPassword);(void)(logoutDevices);(void)(auth);
      
        json _data
        ;
        
            _data["new_password"s] = newPassword;
          
          
            addToJsonIfNeeded(_data, "logout_devices"s, logoutDevices);
          
            addToJsonIfNeeded(_data, "auth"s, auth);
        return BaseJob::JsonBody(_data);
        

      };

      

ChangePasswordJob::ChangePasswordJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string newPassword, std::optional<bool> logoutDevices, std::optional<AuthenticationData> auth
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/password",
          POST,
          std::string("ChangePassword"),
          _accessToken,
          ReturnType::Json,
            buildBody(newPassword, logoutDevices, auth)
              , buildQuery()
                , {}

)
        {
        }

        ChangePasswordJob ChangePasswordJob::withData(JsonWrap j) &&
        {
          auto ret = ChangePasswordJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        ChangePasswordJob ChangePasswordJob::withData(JsonWrap j) const &
        {
          auto ret = ChangePasswordJob(*this);
          ret.attachData(j);
          return ret;
        }

        ChangePasswordJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool ChangePasswordResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query RequestTokenToResetPasswordEmailJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body RequestTokenToResetPasswordEmailJob::buildBody(EmailValidationData body)
      {
      // ignore unused param
      (void)(body);
        return 
          JsonBody(body);
      
          

      };

      

RequestTokenToResetPasswordEmailJob::RequestTokenToResetPasswordEmailJob(
        std::string serverUrl
        
            ,
        EmailValidationData body
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/password/email/requestToken",
          POST,
          std::string("RequestTokenToResetPasswordEmail"),
           {} ,
          ReturnType::Json,
            buildBody(body)
              , buildQuery()
                , {}

)
        {
        }

        RequestTokenToResetPasswordEmailJob RequestTokenToResetPasswordEmailJob::withData(JsonWrap j) &&
        {
          auto ret = RequestTokenToResetPasswordEmailJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RequestTokenToResetPasswordEmailJob RequestTokenToResetPasswordEmailJob::withData(JsonWrap j) const &
        {
          auto ret = RequestTokenToResetPasswordEmailJob(*this);
          ret.attachData(j);
          return ret;
        }

        RequestTokenToResetPasswordEmailJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool RequestTokenToResetPasswordEmailResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query RequestTokenToResetPasswordMSISDNJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body RequestTokenToResetPasswordMSISDNJob::buildBody(MsisdnValidationData body)
      {
      // ignore unused param
      (void)(body);
        return 
          JsonBody(body);
      
          

      };

      

RequestTokenToResetPasswordMSISDNJob::RequestTokenToResetPasswordMSISDNJob(
        std::string serverUrl
        
            ,
        MsisdnValidationData body
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/password/msisdn/requestToken",
          POST,
          std::string("RequestTokenToResetPasswordMSISDN"),
           {} ,
          ReturnType::Json,
            buildBody(body)
              , buildQuery()
                , {}

)
        {
        }

        RequestTokenToResetPasswordMSISDNJob RequestTokenToResetPasswordMSISDNJob::withData(JsonWrap j) &&
        {
          auto ret = RequestTokenToResetPasswordMSISDNJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RequestTokenToResetPasswordMSISDNJob RequestTokenToResetPasswordMSISDNJob::withData(JsonWrap j) const &
        {
          auto ret = RequestTokenToResetPasswordMSISDNJob(*this);
          ret.attachData(j);
          return ret;
        }

        RequestTokenToResetPasswordMSISDNJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool RequestTokenToResetPasswordMSISDNResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query DeactivateAccountJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body DeactivateAccountJob::buildBody(std::optional<AuthenticationData> auth, std::optional<std::string> idServer)
      {
      // ignore unused param
      (void)(auth);(void)(idServer);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "auth"s, auth);
          
            addToJsonIfNeeded(_data, "id_server"s, idServer);
        return BaseJob::JsonBody(_data);
        

      };

      

DeactivateAccountJob::DeactivateAccountJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::optional<AuthenticationData> auth, std::optional<std::string> idServer
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/deactivate",
          POST,
          std::string("DeactivateAccount"),
          _accessToken,
          ReturnType::Json,
            buildBody(auth, idServer)
              , buildQuery()
                , {}

)
        {
        }

        DeactivateAccountJob DeactivateAccountJob::withData(JsonWrap j) &&
        {
          auto ret = DeactivateAccountJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        DeactivateAccountJob DeactivateAccountJob::withData(JsonWrap j) const &
        {
          auto ret = DeactivateAccountJob(*this);
          ret.attachData(j);
          return ret;
        }

        DeactivateAccountJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool DeactivateAccountResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("id_server_unbind_result"s)
          ;
          }


    
    std::string DeactivateAccountResponse::idServerUnbindResult() const
    {
    if (jsonBody().get()
    .contains("id_server_unbind_result"s)) {
    return
    jsonBody().get()["id_server_unbind_result"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }


  
BaseJob::Query CheckUsernameAvailabilityJob::buildQuery(
std::string username)
{
BaseJob::Query _q;
    addToQuery(_q, "username"s, username);
  
return _q;
}

    BaseJob::Body CheckUsernameAvailabilityJob::buildBody(std::string username)
      {
      // ignore unused param
      (void)(username);
      
      
              return BaseJob::EmptyBody{};

      };

      

CheckUsernameAvailabilityJob::CheckUsernameAvailabilityJob(
        std::string serverUrl
        
            ,
        std::string username
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/register/available",
          GET,
          std::string("CheckUsernameAvailability"),
           {} ,
          ReturnType::Json,
            buildBody(username)
              , buildQuery(username)
                , {}

)
        {
        }

        CheckUsernameAvailabilityJob CheckUsernameAvailabilityJob::withData(JsonWrap j) &&
        {
          auto ret = CheckUsernameAvailabilityJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        CheckUsernameAvailabilityJob CheckUsernameAvailabilityJob::withData(JsonWrap j) const &
        {
          auto ret = CheckUsernameAvailabilityJob(*this);
          ret.attachData(j);
          return ret;
        }

        CheckUsernameAvailabilityJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool CheckUsernameAvailabilityResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<bool> CheckUsernameAvailabilityResponse::available() const
    {
    if (jsonBody().get()
    .contains("available"s)) {
    return
    jsonBody().get()["available"s]
    .template get<bool>();}
    else { return std::optional<bool>(  );}
    }

}
