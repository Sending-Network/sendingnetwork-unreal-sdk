/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Invite a user to participate in a particular room.
 *
 * .. _invite-by-user-id-endpoint:
 * 
 * *Note that there are two forms of this API, which are documented separately.
 * This version of the API requires that the inviter knows the
 * identifier of the invitee. The other is documented in the*
 * `third party invites section`_.
 * 
 * This API invites a user to participate in a particular room.
 * They do not start participating in the room until they actually join the
 * room.
 * 
 * Only users currently in a particular room can invite other users to
 * join that room.
 * 
 * If the user was invited to the room, the node will append a
 * ``m.room.member`` event to the room.
 * 
 * .. _third party invites section: `invite-by-third-party-id-endpoint`_
 */
class InviteUserJob : public BaseJob {
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

  /*! \brief Invite a user to participate in a particular room.
 *
    * \param roomId
    *   The room identifier (not alias) to which to invite the user.
    * 
    * \param userId
    *   The fully qualified user ID of the invitee.
    */
    explicit InviteUserJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string userId 
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::string userId);

        

        

      InviteUserJob withData(JsonWrap j) &&;
      InviteUserJob withData(JsonWrap j) const &;
      };
      using InviteUserResponse = InviteUserJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
