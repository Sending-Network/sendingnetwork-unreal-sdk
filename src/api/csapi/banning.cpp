/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "banning.hpp"

namespace Kazv::Api
{

  
BaseJob::Query BanJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body BanJob::buildBody(std::string roomId, std::string userId, std::optional<std::string> reason)
      {
      // ignore unused param
      (void)(roomId);(void)(userId);(void)(reason);
      
        json _data
        ;
        
            _data["user_id"s] = userId;
          
          
            addToJsonIfNeeded(_data, "reason"s, reason);
        return BaseJob::JsonBody(_data);
        

      };

      

BanJob::BanJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string userId, std::optional<std::string> reason
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/ban",
          POST,
          std::string("Ban"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, userId, reason)
              , buildQuery()
                , {}

)
        {
        }

        BanJob BanJob::withData(JsonWrap j) &&
        {
          auto ret = BanJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        BanJob BanJob::withData(JsonWrap j) const &
        {
          auto ret = BanJob(*this);
          ret.attachData(j);
          return ret;
        }

        BanJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool BanResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query UnbanJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body UnbanJob::buildBody(std::string roomId, std::string userId)
      {
      // ignore unused param
      (void)(roomId);(void)(userId);
      
        json _data
        ;
        
            _data["user_id"s] = userId;
          
        return BaseJob::JsonBody(_data);
        

      };

      

UnbanJob::UnbanJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string userId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/unban",
          POST,
          std::string("Unban"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, userId)
              , buildQuery()
                , {}

)
        {
        }

        UnbanJob UnbanJob::withData(JsonWrap j) &&
        {
          auto ret = UnbanJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        UnbanJob UnbanJob::withData(JsonWrap j) const &
        {
          auto ret = UnbanJob(*this);
          ret.attachData(j);
          return ret;
        }

        UnbanJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool UnbanResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
