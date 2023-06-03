/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Set the position of the read marker for a room.
 *
 * Sets the position of the read marker for a given room, and optionally
 * the read receipt's location.
 */
class SetReadMarkerJob : public BaseJob {
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

  /*! \brief Set the position of the read marker for a room.
 *
    * \param roomId
    *   The room ID to set the read marker in for the user.
    * 
    * \param mFullyRead
    *   The event ID the read marker should be located at. The
    *   event MUST belong to the room.
    * 
    * \param mRead
    *   The event ID to set the read receipt location at. This is
    *   equivalent to calling ``/receipt/m.read/$elsewhere:example.org``
    *   and is provided here to save that extra call.
    */
    explicit SetReadMarkerJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string mFullyRead , std::optional<std::string> mRead  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::string mFullyRead, std::optional<std::string> mRead);

        

        

      SetReadMarkerJob withData(JsonWrap j) &&;
      SetReadMarkerJob withData(JsonWrap j) const &;
      };
      using SetReadMarkerResponse = SetReadMarkerJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
