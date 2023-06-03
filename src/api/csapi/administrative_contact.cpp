/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "administrative_contact.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetAccount3PIDsJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetAccount3PIDsJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetAccount3PIDsJob::GetAccount3PIDsJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/3pid",
          GET,
          std::string("GetAccount3PIDs"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetAccount3PIDsJob GetAccount3PIDsJob::withData(JsonWrap j) &&
        {
          auto ret = GetAccount3PIDsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetAccount3PIDsJob GetAccount3PIDsJob::withData(JsonWrap j) const &
        {
          auto ret = GetAccount3PIDsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetAccount3PIDsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetAccount3PIDsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    immer::array<GetAccount3PIDsJob::ThirdPartyIdentifier> GetAccount3PIDsResponse::threepids() const
    {
    if (jsonBody().get()
    .contains("threepids"s)) {
    return
    jsonBody().get()["threepids"s]
    .template get<immer::array<ThirdPartyIdentifier>>();}
    else { return immer::array<ThirdPartyIdentifier>(  );}
    }


  
BaseJob::Query Post3PIDsJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body Post3PIDsJob::buildBody(ThreePidCredentials threePidCreds)
      {
      // ignore unused param
      (void)(threePidCreds);
      
        json _data
        ;
        
            _data["three_pid_creds"s] = threePidCreds;
          
        return BaseJob::JsonBody(_data);
        

      };

      

Post3PIDsJob::Post3PIDsJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        ThreePidCredentials threePidCreds
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/3pid",
          POST,
          std::string("Post3PIDs"),
          _accessToken,
          ReturnType::Json,
            buildBody(threePidCreds)
              , buildQuery()
                , {}

)
        {
        }

        Post3PIDsJob Post3PIDsJob::withData(JsonWrap j) &&
        {
          auto ret = Post3PIDsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        Post3PIDsJob Post3PIDsJob::withData(JsonWrap j) const &
        {
          auto ret = Post3PIDsJob(*this);
          ret.attachData(j);
          return ret;
        }

        Post3PIDsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool Post3PIDsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query Add3PIDJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body Add3PIDJob::buildBody(std::string clientSecret, std::string sid, std::optional<AuthenticationData> auth)
      {
      // ignore unused param
      (void)(clientSecret);(void)(sid);(void)(auth);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "auth"s, auth);
            _data["client_secret"s] = clientSecret;
          
            _data["sid"s] = sid;
          
        return BaseJob::JsonBody(_data);
        

      };

      

Add3PIDJob::Add3PIDJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string clientSecret, std::string sid, std::optional<AuthenticationData> auth
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/3pid/add",
          POST,
          std::string("Add3PID"),
          _accessToken,
          ReturnType::Json,
            buildBody(clientSecret, sid, auth)
              , buildQuery()
                , {}

)
        {
        }

        Add3PIDJob Add3PIDJob::withData(JsonWrap j) &&
        {
          auto ret = Add3PIDJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        Add3PIDJob Add3PIDJob::withData(JsonWrap j) const &
        {
          auto ret = Add3PIDJob(*this);
          ret.attachData(j);
          return ret;
        }

        Add3PIDJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool Add3PIDResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query Bind3PIDJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body Bind3PIDJob::buildBody(std::string clientSecret, std::string idServer, std::string idAccessToken, std::string sid)
      {
      // ignore unused param
      (void)(clientSecret);(void)(idServer);(void)(idAccessToken);(void)(sid);
      
        json _data
        ;
        
            _data["client_secret"s] = clientSecret;
          
            _data["id_server"s] = idServer;
          
            _data["id_access_token"s] = idAccessToken;
          
            _data["sid"s] = sid;
          
        return BaseJob::JsonBody(_data);
        

      };

      

Bind3PIDJob::Bind3PIDJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string clientSecret, std::string idServer, std::string idAccessToken, std::string sid
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/3pid/bind",
          POST,
          std::string("Bind3PID"),
          _accessToken,
          ReturnType::Json,
            buildBody(clientSecret, idServer, idAccessToken, sid)
              , buildQuery()
                , {}

)
        {
        }

        Bind3PIDJob Bind3PIDJob::withData(JsonWrap j) &&
        {
          auto ret = Bind3PIDJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        Bind3PIDJob Bind3PIDJob::withData(JsonWrap j) const &
        {
          auto ret = Bind3PIDJob(*this);
          ret.attachData(j);
          return ret;
        }

        Bind3PIDJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool Bind3PIDResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query Delete3pidFromAccountJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body Delete3pidFromAccountJob::buildBody(std::string medium, std::string address, std::optional<std::string> idServer)
      {
      // ignore unused param
      (void)(medium);(void)(address);(void)(idServer);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "id_server"s, idServer);
            _data["medium"s] = medium;
          
            _data["address"s] = address;
          
        return BaseJob::JsonBody(_data);
        

      };

      

Delete3pidFromAccountJob::Delete3pidFromAccountJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string medium, std::string address, std::optional<std::string> idServer
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/3pid/delete",
          POST,
          std::string("Delete3pidFromAccount"),
          _accessToken,
          ReturnType::Json,
            buildBody(medium, address, idServer)
              , buildQuery()
                , {}

)
        {
        }

        Delete3pidFromAccountJob Delete3pidFromAccountJob::withData(JsonWrap j) &&
        {
          auto ret = Delete3pidFromAccountJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        Delete3pidFromAccountJob Delete3pidFromAccountJob::withData(JsonWrap j) const &
        {
          auto ret = Delete3pidFromAccountJob(*this);
          ret.attachData(j);
          return ret;
        }

        Delete3pidFromAccountJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool Delete3pidFromAccountResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("id_server_unbind_result"s)
          ;
          }


    
    std::string Delete3pidFromAccountResponse::idServerUnbindResult() const
    {
    if (jsonBody().get()
    .contains("id_server_unbind_result"s)) {
    return
    jsonBody().get()["id_server_unbind_result"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }


  
BaseJob::Query Unbind3pidFromAccountJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body Unbind3pidFromAccountJob::buildBody(std::string medium, std::string address, std::optional<std::string> idServer)
      {
      // ignore unused param
      (void)(medium);(void)(address);(void)(idServer);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "id_server"s, idServer);
            _data["medium"s] = medium;
          
            _data["address"s] = address;
          
        return BaseJob::JsonBody(_data);
        

      };

      

Unbind3pidFromAccountJob::Unbind3pidFromAccountJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string medium, std::string address, std::optional<std::string> idServer
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/3pid/unbind",
          POST,
          std::string("Unbind3pidFromAccount"),
          _accessToken,
          ReturnType::Json,
            buildBody(medium, address, idServer)
              , buildQuery()
                , {}

)
        {
        }

        Unbind3pidFromAccountJob Unbind3pidFromAccountJob::withData(JsonWrap j) &&
        {
          auto ret = Unbind3pidFromAccountJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        Unbind3pidFromAccountJob Unbind3pidFromAccountJob::withData(JsonWrap j) const &
        {
          auto ret = Unbind3pidFromAccountJob(*this);
          ret.attachData(j);
          return ret;
        }

        Unbind3pidFromAccountJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool Unbind3pidFromAccountResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("id_server_unbind_result"s)
          ;
          }


    
    std::string Unbind3pidFromAccountResponse::idServerUnbindResult() const
    {
    if (jsonBody().get()
    .contains("id_server_unbind_result"s)) {
    return
    jsonBody().get()["id_server_unbind_result"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }


  
BaseJob::Query RequestTokenTo3PIDEmailJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body RequestTokenTo3PIDEmailJob::buildBody(EmailValidationData body)
      {
      // ignore unused param
      (void)(body);
        return 
          JsonBody(body);
      
          

      };

      

RequestTokenTo3PIDEmailJob::RequestTokenTo3PIDEmailJob(
        std::string serverUrl
        
            ,
        EmailValidationData body
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/3pid/email/requestToken",
          POST,
          std::string("RequestTokenTo3PIDEmail"),
           {} ,
          ReturnType::Json,
            buildBody(body)
              , buildQuery()
                , {}

)
        {
        }

        RequestTokenTo3PIDEmailJob RequestTokenTo3PIDEmailJob::withData(JsonWrap j) &&
        {
          auto ret = RequestTokenTo3PIDEmailJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RequestTokenTo3PIDEmailJob RequestTokenTo3PIDEmailJob::withData(JsonWrap j) const &
        {
          auto ret = RequestTokenTo3PIDEmailJob(*this);
          ret.attachData(j);
          return ret;
        }

        RequestTokenTo3PIDEmailJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool RequestTokenTo3PIDEmailResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query RequestTokenTo3PIDMSISDNJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body RequestTokenTo3PIDMSISDNJob::buildBody(MsisdnValidationData body)
      {
      // ignore unused param
      (void)(body);
        return 
          JsonBody(body);
      
          

      };

      

RequestTokenTo3PIDMSISDNJob::RequestTokenTo3PIDMSISDNJob(
        std::string serverUrl
        
            ,
        MsisdnValidationData body
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/3pid/msisdn/requestToken",
          POST,
          std::string("RequestTokenTo3PIDMSISDN"),
           {} ,
          ReturnType::Json,
            buildBody(body)
              , buildQuery()
                , {}

)
        {
        }

        RequestTokenTo3PIDMSISDNJob RequestTokenTo3PIDMSISDNJob::withData(JsonWrap j) &&
        {
          auto ret = RequestTokenTo3PIDMSISDNJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RequestTokenTo3PIDMSISDNJob RequestTokenTo3PIDMSISDNJob::withData(JsonWrap j) const &
        {
          auto ret = RequestTokenTo3PIDMSISDNJob(*this);
          ret.attachData(j);
          return ret;
        }

        RequestTokenTo3PIDMSISDNJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool RequestTokenTo3PIDMSISDNResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
