/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Invite a user to participate in a particular room.
 *
 * .. _invite-by-third-party-id-endpoint:
 * 
 * *Note that there are two forms of this API, which are documented separately.
 * This version of the API does not require that the inviter know the SDN
 * identifier of the invitee, and instead relies on third party identifiers.
 * The node uses an identity server to perform the mapping from
 * third party identifier to a SDN identifier. The other is documented in the*
 * `joining rooms section`_.
 * 
 * This API invites a user to participate in a particular room.
 * They do not start participating in the room until they actually join the
 * room.
 * 
 * Only users currently in a particular room can invite other users to
 * join that room.
 * 
 * If the identity server did know the SDN user identifier for the
 * third party identifier, the node will append a ``m.room.member``
 * event to the room.
 * 
 * If the identity server does not know a SDN user identifier for the
 * passed third party identifier, the node will issue an invitation
 * which can be accepted upon providing proof of ownership of the third
 * party identifier. This is achieved by the identity server generating a
 * token, which it gives to the inviting node. The node will
 * add an ``m.room.third_party_invite`` event into the graph for the room,
 * containing that token.
 * 
 * When the invitee binds the invited third party identifier to a SDN
 * user ID, the identity server will give the user a list of pending
 * invitations, each containing:
 * 
 * - The room ID to which they were invited
 * 
 * - The token given to the node
 * 
 * - A signature of the token, signed with the identity server's private key
 * 
 * - The SDN user ID who invited them to the room
 * 
 * If a token is requested from the identity server, the node will
 * append a ``m.room.third_party_invite`` event to the room.
 * 
 * .. _joining rooms section: `invite-by-user-id-endpoint`_
 */
class InviteBy3PIDJob : public BaseJob {
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
    * \param idServer
    *   The hostname+port of the identity server which should be used for third party identifier lookups.
    * 
    * \param idAccessToken
    *   An access token previously registered with the identity server. Servers
    *   can treat this as optional to distinguish between r0.5-compatible clients
    *   and this specification version.
    * 
    * \param medium
    *   The kind of address being passed in the address field, for example ``email``.
    * 
    * \param address
    *   The invitee's third party identifier.
    */
    explicit InviteBy3PIDJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::string idServer , std::string idAccessToken , std::string medium , std::string address 
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::string idServer, std::string idAccessToken, std::string medium, std::string address);

        

        

      InviteBy3PIDJob withData(JsonWrap j) &&;
      InviteBy3PIDJob withData(JsonWrap j) const &;
      };
      using InviteBy3PIDResponse = InviteBy3PIDJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
