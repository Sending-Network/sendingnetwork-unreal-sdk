/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>
#include <string>
#include <iostream>

#include "sync.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SyncJob::buildQuery(
std::optional<std::string> filter, std::optional<std::string> since, std::optional<bool> fullState, std::optional<std::string> setPresence, std::optional<int> timeout)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "filter"s, filter);
  
    addToQueryIfNeeded(_q, "since"s, since);
  
    addToQueryIfNeeded(_q, "full_state"s, fullState);
  
    addToQueryIfNeeded(_q, "set_presence"s, setPresence);
  
    addToQueryIfNeeded(_q, "timeout"s, timeout);
return _q;
}

    BaseJob::Body SyncJob::buildBody(std::optional<std::string> filter, std::optional<std::string> since, std::optional<bool> fullState, std::optional<std::string> setPresence, std::optional<int> timeout)
      {
      // ignore unused param
      (void)(filter);(void)(since);(void)(fullState);(void)(setPresence);(void)(timeout);
      
      
              return BaseJob::EmptyBody{};

      };

      

SyncJob::SyncJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::optional<std::string> filter, std::optional<std::string> since, std::optional<bool> fullState, std::optional<std::string> setPresence, std::optional<int> timeout
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/sync",
          GET,
          std::string("Sync"),
          _accessToken,
          ReturnType::Json,
            buildBody(filter, since, fullState, setPresence, timeout)
              , buildQuery(filter, since, fullState, setPresence, timeout)
                , {}

)
        {
        }

        SyncJob SyncJob::withData(JsonWrap j) &&
        {
          auto ret = SyncJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SyncJob SyncJob::withData(JsonWrap j) const &
        {
          auto ret = SyncJob(*this);
          ret.attachData(j);
          return ret;
        }

        SyncJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SyncResponse::success() const
          {
            std::cout << "sync success response:" << jsonBody().get().dump() << std::endl;
            return Response::success()

              && isBodyJson(body)
            && jsonBody().get().contains("next_batch"s)
          ;
          }


    
    std::string SyncResponse::nextBatch() const
    {
    if (jsonBody().get()
    .contains("next_batch"s)) {
      std::cout << "next_batch:" << jsonBody().get()["next_batch"s] << std::endl;
    return
    jsonBody().get()["next_batch"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }

    
    std::optional<SyncJob::Rooms> SyncResponse::rooms() const
    {
    if (jsonBody().get()
    .contains("rooms"s)) {
      std::cout << "rooms:" << jsonBody().get()["rooms"s] << std::endl;
    return
    jsonBody().get()["rooms"s]
    .template get<Rooms>();}
    else { return std::optional<Rooms>(  );}
    }

    
    std::optional<EventBatch> SyncResponse::presence() const
    {
    if (jsonBody().get()
    .contains("presence"s)) {
    return
    jsonBody().get()["presence"s]
    .template get<EventBatch>();}
    else { return std::optional<EventBatch>(  );}
    }

    
    std::optional<EventBatch> SyncResponse::accountData() const
    {
    if (jsonBody().get()
    .contains("account_data"s)) {
    return
    jsonBody().get()["account_data"s]
    .template get<EventBatch>();}
    else { return std::optional<EventBatch>(  );}
    }

    
    JsonWrap SyncResponse::toDevice() const
    {
    if (jsonBody().get()
    .contains("to_device"s)) {
    return
    jsonBody().get()["to_device"s]
    .template get<JsonWrap>();}
    else { return JsonWrap(  );}
    }

    
    JsonWrap SyncResponse::deviceLists() const
    {
    if (jsonBody().get()
    .contains("device_lists"s)) {
    return
    jsonBody().get()["device_lists"s]
    .template get<JsonWrap>();}
    else { return JsonWrap(  );}
    }

    
    immer::map<std::string, int> SyncResponse::deviceOneTimeKeysCount() const
    {
    if (jsonBody().get()
    .contains("device_one_time_keys_count"s)) {
    return
    jsonBody().get()["device_one_time_keys_count"s]
    .template get<immer::map<std::string, int>>();}
    else { return immer::map<std::string, int>(  );}
    }

}
