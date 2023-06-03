/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Create a new mapping from room alias to room ID.
 *
 */
class SetRoomAliasJob : public BaseJob {
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

  /*! \brief Create a new mapping from room alias to room ID.
 *
    * \param roomAlias
    *   The room alias to set.
    * 
    * \param roomId
    *   The room ID to set.
    */
    explicit SetRoomAliasJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomAlias , std::string roomId 
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomAlias, std::string roomId);

        

        

      SetRoomAliasJob withData(JsonWrap j) &&;
      SetRoomAliasJob withData(JsonWrap j) const &;
      };
      using SetRoomAliasResponse = SetRoomAliasJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get the room ID corresponding to this room alias.
 *
 * Requests that the server resolve a room alias to a room ID.
 * 
 * The server will use the federation API to resolve the alias if the
 * domain part of the alias does not correspond to the server's own
 * domain.
 */
class GetRoomIdByAliasJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The room ID for this room alias.
std::optional<std::string> roomId() const;

    
/// A list of servers that are aware of this room alias.
immer::array<std::string> servers() const;

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Get the room ID corresponding to this room alias.
 *
    * \param roomAlias
    *   The room alias.
    */
    explicit GetRoomIdByAliasJob(std::string serverUrl
    
      ,
        std::string roomAlias 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomAlias);

        

        

      GetRoomIdByAliasJob withData(JsonWrap j) &&;
      GetRoomIdByAliasJob withData(JsonWrap j) const &;
      };
      using GetRoomIdByAliasResponse = GetRoomIdByAliasJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Remove a mapping of room alias to room ID.
 *
 * Remove a mapping of room alias to room ID.
 * 
 * Servers may choose to implement additional access control checks here, for instance that
 * room aliases can only be deleted by their creator or a server administrator.
 * 
 * .. Note::
 *    Servers may choose to update the ``alt_aliases`` for the ``m.room.canonical_alias``
 *    state event in the room when an alias is removed. Servers which choose to update the
 *    canonical alias event are recommended to, in addition to their other relevant permission
 *    checks, delete the alias and return a successful response even if the user does not
 *    have permission to update the ``m.room.canonical_alias`` event.
 */
class DeleteRoomAliasJob : public BaseJob {
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

  /*! \brief Remove a mapping of room alias to room ID.
 *
    * \param roomAlias
    *   The room alias to remove.
    */
    explicit DeleteRoomAliasJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomAlias 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomAlias);

        

        

      DeleteRoomAliasJob withData(JsonWrap j) &&;
      DeleteRoomAliasJob withData(JsonWrap j) const &;
      };
      using DeleteRoomAliasResponse = DeleteRoomAliasJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get a list of local aliases on a given room.
 *
 * Get a list of aliases maintained by the local server for the
 * given room.
 * 
 * This endpoint can be called by users who are in the room (external
 * users receive an ``M_FORBIDDEN`` error response). If the room's
 * ``m.room.history_visibility`` maps to ``world_readable``, any
 * user can call this endpoint.
 * 
 * Servers may choose to implement additional access control checks here,
 * such as allowing server administrators to view aliases regardless of
 * membership.
 * 
 * .. Note::
 *    Clients are recommended not to display this list of aliases prominently
 *    as they are not curated, unlike those listed in the ``m.room.canonical_alias``
 *    state event.
 */
class GetLocalAliasesJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The server's local aliases on the room. Can be empty.
immer::array<std::string> aliases() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get a list of local aliases on a given room.
 *
    * \param roomId
    *   The room ID to find local aliases of.
    */
    explicit GetLocalAliasesJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId);

        

        

      GetLocalAliasesJob withData(JsonWrap j) &&;
      GetLocalAliasesJob withData(JsonWrap j) const &;
      };
      using GetLocalAliasesResponse = GetLocalAliasesJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
