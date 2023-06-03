/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "receipts.hpp"

namespace Kazv::Api
{

  
BaseJob::Query PostReceiptJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body PostReceiptJob::buildBody(std::string roomId, std::string receiptType, std::string eventId, JsonWrap receipt)
      {
      // ignore unused param
      (void)(roomId);(void)(receiptType);(void)(eventId);(void)(receipt);
        return 
          JsonBody(receipt);
      
          

      };

      

PostReceiptJob::PostReceiptJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string roomId, std::string receiptType, std::string eventId, JsonWrap receipt
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/rooms/" + roomId + "/receipt/" + receiptType + "/" + eventId,
          POST,
          std::string("PostReceipt"),
          _accessToken,
          ReturnType::Json,
            buildBody(roomId, receiptType, eventId, receipt)
              , buildQuery()
                , {}

)
        {
        }

        PostReceiptJob PostReceiptJob::withData(JsonWrap j) &&
        {
          auto ret = PostReceiptJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        PostReceiptJob PostReceiptJob::withData(JsonWrap j) const &
        {
          auto ret = PostReceiptJob(*this);
          ret.attachData(j);
          return ret;
        }

        PostReceiptJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool PostReceiptResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
