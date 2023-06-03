/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Stop the requesting user participating in a particular room.
 *
 * This API stops a user participating in a particular room.
 * 
 * If the user was already in the room, they will no longer be able to see
 * new events in the room. If the room requires an invite to join, they
 * will need to be re-invited before they can re-join.
 * 
 * If the user was invited to the room, but had not joined, this call
 * serves to reject the invite.
 * 
 * The user will still be allowed to retrieve history from the room which
 * they were previously allowed to see.
 */
class LeaveRoomJob : public BaseJob {
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

  /*! \brief Stop the requesting user participating in a particular room.
 *
    * \param roomId
    *   The room identifier to leave.
    */
    explicit LeaveRoomJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId);

        

        

      LeaveRoomJob withData(JsonWrap j) &&;
      LeaveRoomJob withData(JsonWrap j) const &;
      };
      using LeaveRoomResponse = LeaveRoomJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Stop the requesting user remembering about a particular room.
 *
 * This API stops a user remembering about a particular room.
 * 
 * In general, history is a first class citizen in SDN. After this API
 * is called, however, a user will no longer be able to retrieve history
 * for this room. If all users on a node forget a room, the room is
 * eligible for deletion from that node.
 * 
 * If the user is currently joined to the room, they must leave the room
 * before calling this API.
 */
class ForgetRoomJob : public BaseJob {
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

  /*! \brief Stop the requesting user remembering about a particular room.
 *
    * \param roomId
    *   The room identifier to forget.
    */
    explicit ForgetRoomJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId);

        

        

      ForgetRoomJob withData(JsonWrap j) &&;
      ForgetRoomJob withData(JsonWrap j) const &;
      };
      using ForgetRoomResponse = ForgetRoomJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
