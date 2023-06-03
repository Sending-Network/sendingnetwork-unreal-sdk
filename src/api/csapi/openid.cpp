/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "openid.hpp"

namespace Kazv::Api
{

  
BaseJob::Query RequestOpenIdTokenJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body RequestOpenIdTokenJob::buildBody(std::string userId, JsonWrap body)
      {
      // ignore unused param
      (void)(userId);(void)(body);
        return 
          JsonBody(body);
      
          

      };

      

RequestOpenIdTokenJob::RequestOpenIdTokenJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, JsonWrap body
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user/" + userId + "/openid/request_token",
          POST,
          std::string("RequestOpenIdToken"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, body)
              , buildQuery()
                , {}

)
        {
        }

        RequestOpenIdTokenJob RequestOpenIdTokenJob::withData(JsonWrap j) &&
        {
          auto ret = RequestOpenIdTokenJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RequestOpenIdTokenJob RequestOpenIdTokenJob::withData(JsonWrap j) const &
        {
          auto ret = RequestOpenIdTokenJob(*this);
          ret.attachData(j);
          return ret;
        }

        RequestOpenIdTokenJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool RequestOpenIdTokenResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
