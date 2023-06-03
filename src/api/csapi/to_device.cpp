/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "to_device.hpp"

namespace Kazv::Api
{

  
BaseJob::Query SendToDeviceJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SendToDeviceJob::buildBody(std::string eventType, std::string txnId, immer::map<std::string, immer::map<std::string, JsonWrap>> messages)
      {
      // ignore unused param
      (void)(eventType);(void)(txnId);(void)(messages);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "messages"s, messages);
        return BaseJob::JsonBody(_data);
        

      };

      

SendToDeviceJob::SendToDeviceJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string eventType, std::string txnId, immer::map<std::string, immer::map<std::string, JsonWrap>> messages
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/sendToDevice/" + eventType + "/" + txnId,
          PUT,
          std::string("SendToDevice"),
          _accessToken,
          ReturnType::Json,
            buildBody(eventType, txnId, messages)
              , buildQuery()
                , {}

)
        {
        }

        SendToDeviceJob SendToDeviceJob::withData(JsonWrap j) &&
        {
          auto ret = SendToDeviceJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SendToDeviceJob SendToDeviceJob::withData(JsonWrap j) const &
        {
          auto ret = SendToDeviceJob(*this);
          ret.attachData(j);
          return ret;
        }

        SendToDeviceJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SendToDeviceResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
