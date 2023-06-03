/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "whoami.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetTokenOwnerJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetTokenOwnerJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetTokenOwnerJob::GetTokenOwnerJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/account/whoami",
          GET,
          std::string("GetTokenOwner"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetTokenOwnerJob GetTokenOwnerJob::withData(JsonWrap j) &&
        {
          auto ret = GetTokenOwnerJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetTokenOwnerJob GetTokenOwnerJob::withData(JsonWrap j) const &
        {
          auto ret = GetTokenOwnerJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetTokenOwnerJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetTokenOwnerResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("user_id"s)
          ;
          }


    
    std::string GetTokenOwnerResponse::userId() const
    {
    if (jsonBody().get()
    .contains("user_id"s)) {
    return
    jsonBody().get()["user_id"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }

}
