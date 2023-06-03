/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "capabilities.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetCapabilitiesJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetCapabilitiesJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetCapabilitiesJob::GetCapabilitiesJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/capabilities",
          GET,
          std::string("GetCapabilities"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetCapabilitiesJob GetCapabilitiesJob::withData(JsonWrap j) &&
        {
          auto ret = GetCapabilitiesJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetCapabilitiesJob GetCapabilitiesJob::withData(JsonWrap j) const &
        {
          auto ret = GetCapabilitiesJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetCapabilitiesJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetCapabilitiesResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("capabilities"s)
          ;
          }


    
    GetCapabilitiesJob::Capabilities GetCapabilitiesResponse::capabilities() const
    {
    if (jsonBody().get()
    .contains("capabilities"s)) {
    return
    jsonBody().get()["capabilities"s]
    .template get<Capabilities>();}
    else { return Capabilities(  );}
    }

}
