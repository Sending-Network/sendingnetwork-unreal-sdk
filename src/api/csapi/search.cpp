/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "search.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SearchJob::buildQuery(
std::optional<std::string> nextBatch)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "next_batch"s, nextBatch);
return _q;
}

    BaseJob::Body SearchJob::buildBody(Categories searchCategories, std::optional<std::string> nextBatch)
      {
      // ignore unused param
      (void)(searchCategories);(void)(nextBatch);
      
        json _data
        ;
        
            _data["search_categories"s] = searchCategories;
          
        return BaseJob::JsonBody(_data);
        

      };

      

SearchJob::SearchJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        Categories searchCategories, std::optional<std::string> nextBatch
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/search",
          POST,
          std::string("Search"),
          _accessToken,
          ReturnType::Json,
            buildBody(searchCategories, nextBatch)
              , buildQuery(nextBatch)
                , {}

)
        {
        }

        SearchJob SearchJob::withData(JsonWrap j) &&
        {
          auto ret = SearchJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SearchJob SearchJob::withData(JsonWrap j) const &
        {
          auto ret = SearchJob(*this);
          ret.attachData(j);
          return ret;
        }

        SearchJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SearchResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("search_categories"s)
          ;
          }


    
    SearchJob::ResultCategories SearchResponse::searchCategories() const
    {
    if (jsonBody().get()
    .contains("search_categories"s)) {
    return
    jsonBody().get()["search_categories"s]
    .template get<ResultCategories>();}
    else { return ResultCategories(  );}
    }

}
