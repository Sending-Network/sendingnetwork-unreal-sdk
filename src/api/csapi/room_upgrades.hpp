/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Upgrades a room to a new room version.
 *
 * Upgrades the given room to a particular room version.
 */
class UpgradeRoomJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The ID of the new room.
std::string replacementRoom() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Upgrades a room to a new room version.
 *
    * \param roomId
    *   The ID of the room to upgrade.
    * 
    * \param newVersion
    *   The new version for the room.
    */
    explicit UpgradeRoomJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string newVersion 
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::string newVersion);

        

        

      UpgradeRoomJob withData(JsonWrap j) &&;
      UpgradeRoomJob withData(JsonWrap j) const &;
      };
      using UpgradeRoomResponse = UpgradeRoomJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
