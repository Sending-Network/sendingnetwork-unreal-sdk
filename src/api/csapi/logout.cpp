/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "logout.hpp"

namespace Kazv::Api
{

  
BaseJob::Query LogoutJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body LogoutJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

LogoutJob::LogoutJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/logout",
          POST,
          std::string("Logout"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        LogoutJob LogoutJob::withData(JsonWrap j) &&
        {
          auto ret = LogoutJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        LogoutJob LogoutJob::withData(JsonWrap j) const &
        {
          auto ret = LogoutJob(*this);
          ret.attachData(j);
          return ret;
        }

        LogoutJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool LogoutResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query LogoutAllJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body LogoutAllJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

LogoutAllJob::LogoutAllJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/logout/all",
          POST,
          std::string("LogoutAll"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        LogoutAllJob LogoutAllJob::withData(JsonWrap j) &&
        {
          auto ret = LogoutAllJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        LogoutAllJob LogoutAllJob::withData(JsonWrap j) const &
        {
          auto ret = LogoutAllJob(*this);
          ret.attachData(j);
          return ret;
        }

        LogoutAllJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool LogoutAllResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
