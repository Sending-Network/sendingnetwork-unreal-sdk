/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "wellknown.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetWellknownJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetWellknownJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetWellknownJob::GetWellknownJob(
        std::string serverUrl
        
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/.well-known") + "/sdn/client",
          GET,
          std::string("GetWellknown"),
           {} ,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetWellknownJob GetWellknownJob::withData(JsonWrap j) &&
        {
          auto ret = GetWellknownJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetWellknownJob GetWellknownJob::withData(JsonWrap j) const &
        {
          auto ret = GetWellknownJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetWellknownJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetWellknownResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
