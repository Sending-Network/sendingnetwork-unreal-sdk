/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Informs the server that the user has started or stopped typing.
 *
 * This tells the server that the user is typing for the next N
 * milliseconds where N is the value specified in the ``timeout`` key.
 * Alternatively, if ``typing`` is ``false``, it tells the server that the
 * user has stopped typing.
 */
class SetTypingJob : public BaseJob {
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

  /*! \brief Informs the server that the user has started or stopped typing.
 *
    * \param userId
    *   The user who has started to type.
    * 
    * \param roomId
    *   The room in which the user is typing.
    * 
    * \param typing
    *   Whether the user is typing or not. If ``false``, the ``timeout``
    *   key can be omitted.
    * 
    * \param timeout
    *   The length of time in milliseconds to mark this user as typing.
    */
    explicit SetTypingJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , std::string roomId , bool typing , std::optional<int> timeout  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId, std::string roomId, bool typing, std::optional<int> timeout);

        

        

      SetTypingJob withData(JsonWrap j) &&;
      SetTypingJob withData(JsonWrap j) const &;
      };
      using SetTypingResponse = SetTypingJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
