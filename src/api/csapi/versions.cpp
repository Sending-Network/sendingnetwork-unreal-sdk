/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "versions.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetVersionsJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetVersionsJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetVersionsJob::GetVersionsJob(
        std::string serverUrl
        
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client") + "/versions",
          GET,
          std::string("GetVersions"),
           {} ,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetVersionsJob GetVersionsJob::withData(JsonWrap j) &&
        {
          auto ret = GetVersionsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetVersionsJob GetVersionsJob::withData(JsonWrap j) const &
        {
          auto ret = GetVersionsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetVersionsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetVersionsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("versions"s)
          ;
          }


    
    immer::array<std::string> GetVersionsResponse::versions() const
    {
    if (jsonBody().get()
    .contains("versions"s)) {
    return
    jsonBody().get()["versions"s]
    .template get<immer::array<std::string>>();}
    else { return immer::array<std::string>(  );}
    }

    
    immer::map<std::string, bool> GetVersionsResponse::unstableFeatures() const
    {
    if (jsonBody().get()
    .contains("unstable_features"s)) {
    return
    jsonBody().get()["unstable_features"s]
    .template get<immer::map<std::string, bool>>();}
    else { return immer::map<std::string, bool>(  );}
    }

}
