/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "account-data.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SetAccountDataJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetAccountDataJob::buildBody(std::string userId, std::string type, JsonWrap content)
      {
      // ignore unused param
      (void)(userId);(void)(type);(void)(content);
        return 
          JsonBody(content);
      
          

      };

      

SetAccountDataJob::SetAccountDataJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::string type, JsonWrap content
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user/" + userId + "/account_data/" + type,
          PUT,
          std::string("SetAccountData"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, type, content)
              , buildQuery()
                , {}

)
        {
        }

        SetAccountDataJob SetAccountDataJob::withData(JsonWrap j) &&
        {
          auto ret = SetAccountDataJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetAccountDataJob SetAccountDataJob::withData(JsonWrap j) const &
        {
          auto ret = SetAccountDataJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetAccountDataJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetAccountDataResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetAccountDataJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetAccountDataJob::buildBody(std::string userId, std::string type)
      {
      // ignore unused param
      (void)(userId);(void)(type);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetAccountDataJob::GetAccountDataJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::string type
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user/" + userId + "/account_data/" + type,
          GET,
          std::string("GetAccountData"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, type)
              , buildQuery()
                , {}

)
        {
        }

        GetAccountDataJob GetAccountDataJob::withData(JsonWrap j) &&
        {
          auto ret = GetAccountDataJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetAccountDataJob GetAccountDataJob::withData(JsonWrap j) const &
        {
          auto ret = GetAccountDataJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetAccountDataJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetAccountDataResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query SetAccountDataPerRoomJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetAccountDataPerRoomJob::buildBody(std::string userId, std::string roomId, std::string type, JsonWrap content)
      {
      // ignore unused param
      (void)(userId);(void)(roomId);(void)(type);(void)(content);
        return 
          JsonBody(content);
      
          

      };

      

SetAccountDataPerRoomJob::SetAccountDataPerRoomJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::string roomId, std::string type, JsonWrap content
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user/" + userId + "/rooms/" + roomId + "/account_data/" + type,
          PUT,
          std::string("SetAccountDataPerRoom"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, roomId, type, content)
              , buildQuery()
                , {}

)
        {
        }

        SetAccountDataPerRoomJob SetAccountDataPerRoomJob::withData(JsonWrap j) &&
        {
          auto ret = SetAccountDataPerRoomJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetAccountDataPerRoomJob SetAccountDataPerRoomJob::withData(JsonWrap j) const &
        {
          auto ret = SetAccountDataPerRoomJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetAccountDataPerRoomJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetAccountDataPerRoomResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetAccountDataPerRoomJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetAccountDataPerRoomJob::buildBody(std::string userId, std::string roomId, std::string type)
      {
      // ignore unused param
      (void)(userId);(void)(roomId);(void)(type);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetAccountDataPerRoomJob::GetAccountDataPerRoomJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string userId, std::string roomId, std::string type
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/user/" + userId + "/rooms/" + roomId + "/account_data/" + type,
          GET,
          std::string("GetAccountDataPerRoom"),
          _accessToken,
          ReturnType::Json,
            buildBody(userId, roomId, type)
              , buildQuery()
                , {}

)
        {
        }

        GetAccountDataPerRoomJob GetAccountDataPerRoomJob::withData(JsonWrap j) &&
        {
          auto ret = GetAccountDataPerRoomJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetAccountDataPerRoomJob GetAccountDataPerRoomJob::withData(JsonWrap j) const &
        {
          auto ret = GetAccountDataPerRoomJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetAccountDataPerRoomJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetAccountDataPerRoomResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
