/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "third_party_lookup.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetProtocolsJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetProtocolsJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetProtocolsJob::GetProtocolsJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/thirdparty/protocols",
          GET,
          std::string("GetProtocols"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetProtocolsJob GetProtocolsJob::withData(JsonWrap j) &&
        {
          auto ret = GetProtocolsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetProtocolsJob GetProtocolsJob::withData(JsonWrap j) const &
        {
          auto ret = GetProtocolsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetProtocolsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetProtocolsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetProtocolMetadataJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetProtocolMetadataJob::buildBody(std::string protocol)
      {
      // ignore unused param
      (void)(protocol);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetProtocolMetadataJob::GetProtocolMetadataJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string protocol
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/thirdparty/protocol/" + protocol,
          GET,
          std::string("GetProtocolMetadata"),
          _accessToken,
          ReturnType::Json,
            buildBody(protocol)
              , buildQuery()
                , {}

)
        {
        }

        GetProtocolMetadataJob GetProtocolMetadataJob::withData(JsonWrap j) &&
        {
          auto ret = GetProtocolMetadataJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetProtocolMetadataJob GetProtocolMetadataJob::withData(JsonWrap j) const &
        {
          auto ret = GetProtocolMetadataJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetProtocolMetadataJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetProtocolMetadataResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query QueryLocationByProtocolJob::buildQuery(
std::optional<std::string> searchFields)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "searchFields"s, searchFields);
return _q;
}

    BaseJob::Body QueryLocationByProtocolJob::buildBody(std::string protocol, std::optional<std::string> searchFields)
      {
      // ignore unused param
      (void)(protocol);(void)(searchFields);
      
      
              return BaseJob::EmptyBody{};

      };

      

QueryLocationByProtocolJob::QueryLocationByProtocolJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string protocol, std::optional<std::string> searchFields
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/thirdparty/location/" + protocol,
          GET,
          std::string("QueryLocationByProtocol"),
          _accessToken,
          ReturnType::Json,
            buildBody(protocol, searchFields)
              , buildQuery(searchFields)
                , {}

)
        {
        }

        QueryLocationByProtocolJob QueryLocationByProtocolJob::withData(JsonWrap j) &&
        {
          auto ret = QueryLocationByProtocolJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        QueryLocationByProtocolJob QueryLocationByProtocolJob::withData(JsonWrap j) const &
        {
          auto ret = QueryLocationByProtocolJob(*this);
          ret.attachData(j);
          return ret;
        }

        QueryLocationByProtocolJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool QueryLocationByProtocolResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query QueryUserByProtocolJob::buildQuery(
std::optional<std::string> fields)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "fields..."s, fields);
return _q;
}

    BaseJob::Body QueryUserByProtocolJob::buildBody(std::string protocol, std::optional<std::string> fields)
      {
      // ignore unused param
      (void)(protocol);(void)(fields);
      
      
              return BaseJob::EmptyBody{};

      };

      

QueryUserByProtocolJob::QueryUserByProtocolJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string protocol, std::optional<std::string> fields
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/thirdparty/user/" + protocol,
          GET,
          std::string("QueryUserByProtocol"),
          _accessToken,
          ReturnType::Json,
            buildBody(protocol, fields)
              , buildQuery(fields)
                , {}

)
        {
        }

        QueryUserByProtocolJob QueryUserByProtocolJob::withData(JsonWrap j) &&
        {
          auto ret = QueryUserByProtocolJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        QueryUserByProtocolJob QueryUserByProtocolJob::withData(JsonWrap j) const &
        {
          auto ret = QueryUserByProtocolJob(*this);
          ret.attachData(j);
          return ret;
        }

        QueryUserByProtocolJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool QueryUserByProtocolResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query QueryLocationByAliasJob::buildQuery(
std::string alias)
{
BaseJob::Query _q;
    addToQuery(_q, "alias"s, alias);
  
return _q;
}

    BaseJob::Body QueryLocationByAliasJob::buildBody(std::string alias)
      {
      // ignore unused param
      (void)(alias);
      
      
              return BaseJob::EmptyBody{};

      };

      

QueryLocationByAliasJob::QueryLocationByAliasJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string alias
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/thirdparty/location",
          GET,
          std::string("QueryLocationByAlias"),
          _accessToken,
          ReturnType::Json,
            buildBody(alias)
              , buildQuery(alias)
                , {}

)
        {
        }

        QueryLocationByAliasJob QueryLocationByAliasJob::withData(JsonWrap j) &&
        {
          auto ret = QueryLocationByAliasJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        QueryLocationByAliasJob QueryLocationByAliasJob::withData(JsonWrap j) const &
        {
          auto ret = QueryLocationByAliasJob(*this);
          ret.attachData(j);
          return ret;
        }

        QueryLocationByAliasJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool QueryLocationByAliasResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query QueryUserByIDJob::buildQuery(
std::string userid)
{
BaseJob::Query _q;
    addToQuery(_q, "userid"s, userid);
  
return _q;
}

    BaseJob::Body QueryUserByIDJob::buildBody(std::string userid)
      {
      // ignore unused param
      (void)(userid);
      
      
              return BaseJob::EmptyBody{};

      };

      

QueryUserByIDJob::QueryUserByIDJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userid
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/thirdparty/user",
          GET,
          std::string("QueryUserByID"),
          _accessToken,
          ReturnType::Json,
            buildBody(userid)
              , buildQuery(userid)
                , {}

)
        {
        }

        QueryUserByIDJob QueryUserByIDJob::withData(JsonWrap j) &&
        {
          auto ret = QueryUserByIDJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        QueryUserByIDJob QueryUserByIDJob::withData(JsonWrap j) const &
        {
          auto ret = QueryUserByIDJob(*this);
          ret.attachData(j);
          return ret;
        }

        QueryUserByIDJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool QueryUserByIDResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
