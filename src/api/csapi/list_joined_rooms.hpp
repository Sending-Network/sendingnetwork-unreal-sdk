/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Lists the user's current rooms.
 *
 * This API returns a list of the user's current rooms.
 */
class GetJoinedRoomsJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The ID of each room in which the user has ``joined`` membership.
immer::array<std::string> joinedRooms() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

    /// Lists the user's current rooms.
    explicit GetJoinedRoomsJob(std::string serverUrl
    , std::string _accessToken
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      GetJoinedRoomsJob withData(JsonWrap j) &&;
      GetJoinedRoomsJob withData(JsonWrap j) const &;
      };
      using GetJoinedRoomsResponse = GetJoinedRoomsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
