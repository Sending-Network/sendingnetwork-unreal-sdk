/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "users.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SearchUserDirectoryJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SearchUserDirectoryJob::buildBody(std::string searchTerm, std::optional<int> limit)
      {
      // ignore unused param
      (void)(searchTerm);(void)(limit);
      
        json _data
        ;
        
            _data["search_term"s] = searchTerm;
          
          
            addToJsonIfNeeded(_data, "limit"s, limit);
        return BaseJob::JsonBody(_data);
        

      };

      

SearchUserDirectoryJob::SearchUserDirectoryJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string searchTerm, std::optional<int> limit
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user_directory/search",
          POST,
          std::string("SearchUserDirectory"),
          _accessToken,
          ReturnType::Json,
            buildBody(searchTerm, limit)
              , buildQuery()
                , {}

)
        {
        }

        SearchUserDirectoryJob SearchUserDirectoryJob::withData(JsonWrap j) &&
        {
          auto ret = SearchUserDirectoryJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SearchUserDirectoryJob SearchUserDirectoryJob::withData(JsonWrap j) const &
        {
          auto ret = SearchUserDirectoryJob(*this);
          ret.attachData(j);
          return ret;
        }

        SearchUserDirectoryJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SearchUserDirectoryResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("results"s)
            && jsonBody().get().contains("limited"s)
          ;
          }


    
    immer::array<SearchUserDirectoryJob::User> SearchUserDirectoryResponse::results() const
    {
    if (jsonBody().get()
    .contains("results"s)) {
    return
    jsonBody().get()["results"s]
    .template get<immer::array<User>>();}
    else { return immer::array<User>(  );}
    }

    
    bool SearchUserDirectoryResponse::limited() const
    {
    if (jsonBody().get()
    .contains("limited"s)) {
    return
    jsonBody().get()["limited"s]
    .template get<bool>();}
    else { return bool(  );}
    }

}
