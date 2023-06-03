/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "keys.hpp"

namespace Kazv::Api
{

  
BaseJob::Query UploadKeysJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body UploadKeysJob::buildBody(std::optional<DeviceKeys> deviceKeys, immer::map<std::string, Variant> oneTimeKeys)
      {
      // ignore unused param
      (void)(deviceKeys);(void)(oneTimeKeys);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "device_keys"s, deviceKeys);
          
            addToJsonIfNeeded(_data, "one_time_keys"s, oneTimeKeys);
        return BaseJob::JsonBody(_data);
        

      };

      

UploadKeysJob::UploadKeysJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::optional<DeviceKeys> deviceKeys, immer::map<std::string, Variant> oneTimeKeys
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/keys/upload",
          POST,
          std::string("UploadKeys"),
          _accessToken,
          ReturnType::Json,
            buildBody(deviceKeys, oneTimeKeys)
              , buildQuery()
                , {}

)
        {
        }

        UploadKeysJob UploadKeysJob::withData(JsonWrap j) &&
        {
          auto ret = UploadKeysJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        UploadKeysJob UploadKeysJob::withData(JsonWrap j) const &
        {
          auto ret = UploadKeysJob(*this);
          ret.attachData(j);
          return ret;
        }

        UploadKeysJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool UploadKeysResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("one_time_key_counts"s)
          ;
          }


    
    immer::map<std::string, int> UploadKeysResponse::oneTimeKeyCounts() const
    {
    if (jsonBody().get()
    .contains("one_time_key_counts"s)) {
    return
    jsonBody().get()["one_time_key_counts"s]
    .template get<immer::map<std::string, int>>();}
    else { return immer::map<std::string, int>(  );}
    }


  
BaseJob::Query QueryKeysJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body QueryKeysJob::buildBody(immer::map<std::string, immer::array<std::string>> deviceKeys, std::optional<int> timeout, std::optional<std::string> token)
      {
      // ignore unused param
      (void)(deviceKeys);(void)(timeout);(void)(token);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "timeout"s, timeout);
            _data["device_keys"s] = deviceKeys;
          
          
            addToJsonIfNeeded(_data, "token"s, token);
        return BaseJob::JsonBody(_data);
        

      };

      

QueryKeysJob::QueryKeysJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        immer::map<std::string, immer::array<std::string>> deviceKeys, std::optional<int> timeout, std::optional<std::string> token
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/keys/query",
          POST,
          std::string("QueryKeys"),
          _accessToken,
          ReturnType::Json,
            buildBody(deviceKeys, timeout, token)
              , buildQuery()
                , {}

)
        {
        }

        QueryKeysJob QueryKeysJob::withData(JsonWrap j) &&
        {
          auto ret = QueryKeysJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        QueryKeysJob QueryKeysJob::withData(JsonWrap j) const &
        {
          auto ret = QueryKeysJob(*this);
          ret.attachData(j);
          return ret;
        }

        QueryKeysJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool QueryKeysResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    immer::map<std::string, JsonWrap> QueryKeysResponse::failures() const
    {
    if (jsonBody().get()
    .contains("failures"s)) {
    return
    jsonBody().get()["failures"s]
    .template get<immer::map<std::string, JsonWrap>>();}
    else { return immer::map<std::string, JsonWrap>(  );}
    }

    
    immer::map<std::string, immer::map<std::string, QueryKeysJob::DeviceInformation>> QueryKeysResponse::deviceKeys() const
    {
    if (jsonBody().get()
    .contains("device_keys"s)) {
    return
    jsonBody().get()["device_keys"s]
    .template get<immer::map<std::string, immer::map<std::string, DeviceInformation>>>();}
    else { return immer::map<std::string, immer::map<std::string, DeviceInformation>>(  );}
    }


  
BaseJob::Query ClaimKeysJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body ClaimKeysJob::buildBody(immer::map<std::string, immer::map<std::string, std::string>> oneTimeKeys, std::optional<int> timeout)
      {
      // ignore unused param
      (void)(oneTimeKeys);(void)(timeout);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "timeout"s, timeout);
            _data["one_time_keys"s] = oneTimeKeys;
          
        return BaseJob::JsonBody(_data);
        

      };

      

ClaimKeysJob::ClaimKeysJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        immer::map<std::string, immer::map<std::string, std::string>> oneTimeKeys, std::optional<int> timeout
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/keys/claim",
          POST,
          std::string("ClaimKeys"),
          _accessToken,
          ReturnType::Json,
            buildBody(oneTimeKeys, timeout)
              , buildQuery()
                , {}

)
        {
        }

        ClaimKeysJob ClaimKeysJob::withData(JsonWrap j) &&
        {
          auto ret = ClaimKeysJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        ClaimKeysJob ClaimKeysJob::withData(JsonWrap j) const &
        {
          auto ret = ClaimKeysJob(*this);
          ret.attachData(j);
          return ret;
        }

        ClaimKeysJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool ClaimKeysResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("one_time_keys"s)
          ;
          }


    
    immer::map<std::string, JsonWrap> ClaimKeysResponse::failures() const
    {
    if (jsonBody().get()
    .contains("failures"s)) {
    return
    jsonBody().get()["failures"s]
    .template get<immer::map<std::string, JsonWrap>>();}
    else { return immer::map<std::string, JsonWrap>(  );}
    }

    
    immer::map<std::string, immer::map<std::string, Variant>> ClaimKeysResponse::oneTimeKeys() const
    {
    if (jsonBody().get()
    .contains("one_time_keys"s)) {
    return
    jsonBody().get()["one_time_keys"s]
    .template get<immer::map<std::string, immer::map<std::string, Variant>>>();}
    else { return immer::map<std::string, immer::map<std::string, Variant>>(  );}
    }


  
BaseJob::Query GetKeysChangesJob::buildQuery(
std::string from, std::string to)
{
BaseJob::Query _q;
    addToQuery(_q, "from"s, from);
  
    addToQuery(_q, "to"s, to);
  
return _q;
}

    BaseJob::Body GetKeysChangesJob::buildBody(std::string from, std::string to)
      {
      // ignore unused param
      (void)(from);(void)(to);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetKeysChangesJob::GetKeysChangesJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string from, std::string to
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/keys/changes",
          GET,
          std::string("GetKeysChanges"),
          _accessToken,
          ReturnType::Json,
            buildBody(from, to)
              , buildQuery(from, to)
                , {}

)
        {
        }

        GetKeysChangesJob GetKeysChangesJob::withData(JsonWrap j) &&
        {
          auto ret = GetKeysChangesJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetKeysChangesJob GetKeysChangesJob::withData(JsonWrap j) const &
        {
          auto ret = GetKeysChangesJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetKeysChangesJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetKeysChangesResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    immer::array<std::string> GetKeysChangesResponse::changed() const
    {
    if (jsonBody().get()
    .contains("changed"s)) {
    return
    jsonBody().get()["changed"s]
    .template get<immer::array<std::string>>();}
    else { return immer::array<std::string>(  );}
    }

    
    immer::array<std::string> GetKeysChangesResponse::left() const
    {
    if (jsonBody().get()
    .contains("left"s)) {
    return
    jsonBody().get()["left"s]
    .template get<immer::array<std::string>>();}
    else { return immer::array<std::string>(  );}
    }

}
