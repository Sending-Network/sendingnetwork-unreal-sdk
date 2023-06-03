/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Reports an event as inappropriate.
 *
 * Reports an event as inappropriate to the server, which may then notify
 * the appropriate people.
 */
class ReportContentJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Reports an event as inappropriate.
 *
    * \param roomId
    *   The room in which the event being reported is located.
    * 
    * \param eventId
    *   The event to report.
    * 
    * \param score
    *   The score to rate this content as where -100 is most offensive
    *   and 0 is inoffensive.
    * 
    * \param reason
    *   The reason the content is being reported. May be blank.
    */
    explicit ReportContentJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string eventId , int score , std::string reason 
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::string eventId, int score, std::string reason);

        

        

      ReportContentJob withData(JsonWrap j) &&;
      ReportContentJob withData(JsonWrap j) const &;
      };
      using ReportContentResponse = ReportContentJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
