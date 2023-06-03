/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "voip.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetTurnServerJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetTurnServerJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetTurnServerJob::GetTurnServerJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/voip/turnServer",
          GET,
          std::string("GetTurnServer"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetTurnServerJob GetTurnServerJob::withData(JsonWrap j) &&
        {
          auto ret = GetTurnServerJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetTurnServerJob GetTurnServerJob::withData(JsonWrap j) const &
        {
          auto ret = GetTurnServerJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetTurnServerJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetTurnServerResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
