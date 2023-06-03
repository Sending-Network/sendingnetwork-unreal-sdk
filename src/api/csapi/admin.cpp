/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "admin.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetWhoIsJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetWhoIsJob::buildBody(std::string userId)
      {
      // ignore unused param
      (void)(userId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetWhoIsJob::GetWhoIsJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/admin/whois/" + userId,
          GET,
          std::string("GetWhoIs"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId)
              , buildQuery()
                , {}

)
        {
        }

        GetWhoIsJob GetWhoIsJob::withData(JsonWrap j) &&
        {
          auto ret = GetWhoIsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetWhoIsJob GetWhoIsJob::withData(JsonWrap j) const &
        {
          auto ret = GetWhoIsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetWhoIsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetWhoIsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::string> GetWhoIsResponse::userId() const
    {
    if (jsonBody().get()
    .contains("user_id"s)) {
    return
    jsonBody().get()["user_id"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }

    
    immer::map<std::string, GetWhoIsJob::DeviceInfo> GetWhoIsResponse::devices() const
    {
    if (jsonBody().get()
    .contains("devices"s)) {
    return
    jsonBody().get()["devices"s]
    .template get<immer::map<std::string, DeviceInfo>>();}
    else { return immer::map<std::string, DeviceInfo>(  );}
    }

}
