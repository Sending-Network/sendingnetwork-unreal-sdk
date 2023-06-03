/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Update this user's presence state.
 *
 * This API sets the given user's presence state. When setting the status,
 * the activity time is updated to reflect that activity; the client does
 * not need to specify the ``last_active_ago`` field. You cannot set the
 * presence state of another user.
 */
class SetPresenceJob : public BaseJob {
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

  /*! \brief Update this user's presence state.
 *
    * \param userId
    *   The user whose presence state to update.
    * 
    * \param presence
    *   The new presence state.
    * 
    * \param statusMsg
    *   The status message to attach to this state.
    */
    explicit SetPresenceJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , std::string presence , std::optional<std::string> statusMsg  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId, std::string presence, std::optional<std::string> statusMsg);

        

        

      SetPresenceJob withData(JsonWrap j) &&;
      SetPresenceJob withData(JsonWrap j) const &;
      };
      using SetPresenceResponse = SetPresenceJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get this user's presence state.
 *
 * Get the given user's presence state.
 */
class GetPresenceJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// This user's presence.
std::string presence() const;

    
/// The length of time in milliseconds since an action was performed
/// by this user.
std::optional<int> lastActiveAgo() const;

    
/// The state message for this user if one was set.
Variant statusMsg() const;

    
/// Whether the user is currently active
std::optional<bool> currentlyActive() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get this user's presence state.
 *
    * \param userId
    *   The user whose presence state to get.
    */
    explicit GetPresenceJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId);

        

        

      GetPresenceJob withData(JsonWrap j) &&;
      GetPresenceJob withData(JsonWrap j) const &;
      };
      using GetPresenceResponse = GetPresenceJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
