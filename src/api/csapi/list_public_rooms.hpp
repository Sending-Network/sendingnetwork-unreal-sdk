/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/public_rooms_response.hpp"

namespace Kazv::Api {

/*! \brief Gets the visibility of a room in the directory
 *
 * Gets the visibility of a given room on the server's public room directory.
 */
class GetRoomVisibilityOnDirectoryJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The visibility of the room in the directory.
std::optional<std::string> visibility() const;

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Gets the visibility of a room in the directory
 *
    * \param roomId
    *   The room ID.
    */
    explicit GetRoomVisibilityOnDirectoryJob(std::string serverUrl
    
      ,
        std::string roomId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId);

        

        

      GetRoomVisibilityOnDirectoryJob withData(JsonWrap j) &&;
      GetRoomVisibilityOnDirectoryJob withData(JsonWrap j) const &;
      };
      using GetRoomVisibilityOnDirectoryResponse = GetRoomVisibilityOnDirectoryJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Sets the visibility of a room in the room directory
 *
 * Sets the visibility of a given room in the server's public room
 * directory.
 * 
 * Servers may choose to implement additional access control checks
 * here, for instance that room visibility can only be changed by 
 * the room creator or a server administrator.
 */
class SetRoomVisibilityOnDirectoryJob : public BaseJob {
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

  /*! \brief Sets the visibility of a room in the room directory
 *
    * \param roomId
    *   The room ID.
    * 
    * \param visibility
    *   The new visibility setting for the room. 
    *   Defaults to 'public'.
    */
    explicit SetRoomVisibilityOnDirectoryJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId , std::optional<std::string> visibility  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId, std::optional<std::string> visibility);

        

        

      SetRoomVisibilityOnDirectoryJob withData(JsonWrap j) &&;
      SetRoomVisibilityOnDirectoryJob withData(JsonWrap j) const &;
      };
      using SetRoomVisibilityOnDirectoryResponse = SetRoomVisibilityOnDirectoryJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Lists the public rooms on the server.
 *
 * Lists the public rooms on the server.
 * 
 * This API returns paginated responses. The rooms are ordered by the number
 * of joined members, with the largest rooms first.
 */
class GetPublicRoomsJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// A paginated chunk of public rooms.
immer::array<PublicRoomsChunk> chunk() const;

    
/// A pagination token for the response. The absence of this token
/// means there are no more results to fetch and the client should
/// stop paginating.
std::optional<std::string> nextBatch() const;

    
/// A pagination token that allows fetching previous results. The
/// absence of this token means there are no results before this
/// batch, i.e. this is the first batch.
std::optional<std::string> prevBatch() const;

    
/// An estimate on the total number of public rooms, if the
/// server has an estimate.
std::optional<int> totalRoomCountEstimate() const;

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Lists the public rooms on the server.
 *
    * \param limit
    *   Limit the number of results returned.
    * 
    * \param since
    *   A pagination token from a previous request, allowing clients to
    *   get the next (or previous) batch of rooms.
    *   The direction of pagination is specified solely by which token
    *   is supplied, rather than via an explicit flag.
    * 
    * \param server
    *   The server to fetch the public room lists from. Defaults to the
    *   local server.
    */
    explicit GetPublicRoomsJob(std::string serverUrl
    
      ,
        std::optional<int> limit  = std::nullopt, std::optional<std::string> since  = std::nullopt, std::optional<std::string> server  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::optional<int> limit, std::optional<std::string> since, std::optional<std::string> server);

      static BaseJob::Body buildBody(std::optional<int> limit, std::optional<std::string> since, std::optional<std::string> server);

        

        

      GetPublicRoomsJob withData(JsonWrap j) &&;
      GetPublicRoomsJob withData(JsonWrap j) const &;
      };
      using GetPublicRoomsResponse = GetPublicRoomsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Lists the public rooms on the server with optional filter.
 *
 * Lists the public rooms on the server, with optional filter.
 * 
 * This API returns paginated responses. The rooms are ordered by the number
 * of joined members, with the largest rooms first.
 */
class QueryPublicRoomsJob : public BaseJob {
public:
  // Inner data structures

/// Filter to apply to the results.
    struct Filter
        {
/// A string to search for in the room metadata, e.g. name,
/// topic, canonical alias etc. (Optional).
          std::optional<std::string> genericSearchTerm;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// A paginated chunk of public rooms.
immer::array<PublicRoomsChunk> chunk() const;

    
/// A pagination token for the response. The absence of this token
/// means there are no more results to fetch and the client should
/// stop paginating.
std::optional<std::string> nextBatch() const;

    
/// A pagination token that allows fetching previous results. The
/// absence of this token means there are no results before this
/// batch, i.e. this is the first batch.
std::optional<std::string> prevBatch() const;

    
/// An estimate on the total number of public rooms, if the
/// server has an estimate.
std::optional<int> totalRoomCountEstimate() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Lists the public rooms on the server with optional filter.
 *
    * \param server
    *   The server to fetch the public room lists from. Defaults to the
    *   local server.
    * 
    * \param limit
    *   Limit the number of results returned.
    * 
    * \param since
    *   A pagination token from a previous request, allowing clients
    *   to get the next (or previous) batch of rooms.  The direction
    *   of pagination is specified solely by which token is supplied,
    *   rather than via an explicit flag.
    * 
    * \param filter
    *   Filter to apply to the results.
    * 
    * \param includeAllNetworks
    *   Whether or not to include all known networks/protocols from
    *   application services on the node. Defaults to false.
    * 
    * \param thirdPartyInstanceId
    *   The specific third party network/protocol to request from the
    *   node. Can only be used if ``include_all_networks`` is false.
    */
    explicit QueryPublicRoomsJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::optional<std::string> server  = std::nullopt, std::optional<int> limit  = std::nullopt, std::optional<std::string> since  = std::nullopt, std::optional<Filter> filter  = std::nullopt, std::optional<bool> includeAllNetworks  = std::nullopt, std::optional<std::string> thirdPartyInstanceId  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    std::optional<std::string> server);

      static BaseJob::Body buildBody(std::optional<std::string> server, std::optional<int> limit, std::optional<std::string> since, std::optional<Filter> filter, std::optional<bool> includeAllNetworks, std::optional<std::string> thirdPartyInstanceId);

        

        

      QueryPublicRoomsJob withData(JsonWrap j) &&;
      QueryPublicRoomsJob withData(JsonWrap j) const &;
      };
      using QueryPublicRoomsResponse = QueryPublicRoomsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<QueryPublicRoomsJob::Filter> {

  static void to_json(json& jo, const QueryPublicRoomsJob::Filter &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "generic_search_term"s, pod.genericSearchTerm);
  }

  static void from_json(const json &jo, QueryPublicRoomsJob::Filter& result)
  {
  
    if (jo.contains("generic_search_term"s)) {
      result.genericSearchTerm = jo.at("generic_search_term"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
