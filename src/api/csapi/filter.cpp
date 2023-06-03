/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "filter.hpp"

namespace Kazv::Api
{

  
BaseJob::Query DefineFilterJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body DefineFilterJob::buildBody(std::string userId, Filter filter)
      {
      // ignore unused param
      (void)(userId);(void)(filter);
        return 
          JsonBody(filter);
      
          

      };

      

DefineFilterJob::DefineFilterJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, Filter filter
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user/" + userId + "/filter",
          POST,
          std::string("DefineFilter"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, filter)
              , buildQuery()
                , {}

)
        {
        }

        DefineFilterJob DefineFilterJob::withData(JsonWrap j) &&
        {
          auto ret = DefineFilterJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        DefineFilterJob DefineFilterJob::withData(JsonWrap j) const &
        {
          auto ret = DefineFilterJob(*this);
          ret.attachData(j);
          return ret;
        }

        DefineFilterJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool DefineFilterResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("filter_id"s)
          ;
          }


    
    std::string DefineFilterResponse::filterId() const
    {
    if (jsonBody().get()
    .contains("filter_id"s)) {
    return
    jsonBody().get()["filter_id"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }


  
BaseJob::Query GetFilterJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetFilterJob::buildBody(std::string userId, std::string filterId)
      {
      // ignore unused param
      (void)(userId);(void)(filterId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetFilterJob::GetFilterJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::string filterId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user/" + userId + "/filter/" + filterId,
          GET,
          std::string("GetFilter"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, filterId)
              , buildQuery()
                , {}

)
        {
        }

        GetFilterJob GetFilterJob::withData(JsonWrap j) &&
        {
          auto ret = GetFilterJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetFilterJob GetFilterJob::withData(JsonWrap j) const &
        {
          auto ret = GetFilterJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetFilterJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetFilterResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
