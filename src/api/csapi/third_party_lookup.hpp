/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/../application-service/definitions/user.hpp"
#include "csapi/../application-service/definitions/location.hpp"
#include "csapi/../application-service/definitions/protocol.hpp"

namespace Kazv::Api {

/*! \brief Retrieve metadata about all protocols that a node supports.
 *
 * Fetches the overall metadata about protocols supported by the
 * node. Includes both the available protocols and all fields
 * required for queries against each protocol.
 */
class GetProtocolsJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// The protocols supported by the node.
    
    immer::map<std::string, ThirdPartyProtocol> data() const
    {
    return
      std::move(jsonBody().get()).get<immer::map<std::string, ThirdPartyProtocol>>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

    /// Retrieve metadata about all protocols that a node supports.
    explicit GetProtocolsJob(std::string serverUrl
    , std::string _accessToken
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      GetProtocolsJob withData(JsonWrap j) &&;
      GetProtocolsJob withData(JsonWrap j) const &;
      };
      using GetProtocolsResponse = GetProtocolsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Retrieve metadata about a specific protocol that the node supports.
 *
 * Fetches the metadata from the node about a particular third party protocol.
 */
class GetProtocolMetadataJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// The protocol was found and metadata returned.
    
    ThirdPartyProtocol data() const
    {
    return
      std::move(jsonBody().get()).get<ThirdPartyProtocol>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Retrieve metadata about a specific protocol that the node supports.
 *
    * \param protocol
    *   The name of the protocol.
    */
    explicit GetProtocolMetadataJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string protocol 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string protocol);

        

        

      GetProtocolMetadataJob withData(JsonWrap j) &&;
      GetProtocolMetadataJob withData(JsonWrap j) const &;
      };
      using GetProtocolMetadataResponse = GetProtocolMetadataJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Retrieve SDN-side portals rooms leading to a third party location.
 *
 * Requesting this endpoint with a valid protocol name results in a list
 * of successful mapping results in a JSON array. Each result contains
 * objects to represent the SDN room or rooms that represent a portal
 * to this third party network. Each has the SDN room alias string,
 * an identifier for the particular third party network protocol, and an
 * object containing the network-specific fields that comprise this
 * identifier. It should attempt to canonicalise the identifier as much
 * as reasonably possible given the network type.
 */
class QueryLocationByProtocolJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// At least one portal room was found.
    
    immer::array<ThirdPartyLocation> data() const
    {
    return
      std::move(jsonBody().get()).get<immer::array<ThirdPartyLocation>>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Retrieve SDN-side portals rooms leading to a third party location.
 *
    * \param protocol
    *   The protocol used to communicate to the third party network.
    * 
    * \param searchFields
    *   One or more custom fields to help identify the third party
    *   location.
    */
    explicit QueryLocationByProtocolJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string protocol , std::optional<std::string> searchFields  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::optional<std::string> searchFields);

      static BaseJob::Body buildBody(std::string protocol, std::optional<std::string> searchFields);

        

        

      QueryLocationByProtocolJob withData(JsonWrap j) &&;
      QueryLocationByProtocolJob withData(JsonWrap j) const &;
      };
      using QueryLocationByProtocolResponse = QueryLocationByProtocolJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Retrieve the SDN User ID of a corresponding third party user.
 *
 * Retrieve a SDN User ID linked to a user on the third party service, given
 * a set of user parameters.
 */
class QueryUserByProtocolJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// The SDN User IDs found with the given parameters.
    
    immer::array<ThirdPartyUser> data() const
    {
    return
      std::move(jsonBody().get()).get<immer::array<ThirdPartyUser>>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Retrieve the SDN User ID of a corresponding third party user.
 *
    * \param protocol
    *   The name of the protocol.
    * 
    * \param fields
    *   One or more custom fields that are passed to the AS to help identify the user.
    */
    explicit QueryUserByProtocolJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string protocol , std::optional<std::string> fields  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::optional<std::string> fields);

      static BaseJob::Body buildBody(std::string protocol, std::optional<std::string> fields);

        

        

      QueryUserByProtocolJob withData(JsonWrap j) &&;
      QueryUserByProtocolJob withData(JsonWrap j) const &;
      };
      using QueryUserByProtocolResponse = QueryUserByProtocolJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Reverse-lookup third party locations given a SDN room alias.
 *
 * Retrieve an array of third party network locations from a SDN room
 * alias.
 */
class QueryLocationByAliasJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// All found third party locations.
    
    immer::array<ThirdPartyLocation> data() const
    {
    return
      std::move(jsonBody().get()).get<immer::array<ThirdPartyLocation>>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Reverse-lookup third party locations given a SDN room alias.
 *
    * \param alias
    *   The SDN room alias to look up.
    */
    explicit QueryLocationByAliasJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string alias 
        );


    static BaseJob::Query buildQuery(
    std::string alias);

      static BaseJob::Body buildBody(std::string alias);

        

        

      QueryLocationByAliasJob withData(JsonWrap j) &&;
      QueryLocationByAliasJob withData(JsonWrap j) const &;
      };
      using QueryLocationByAliasResponse = QueryLocationByAliasJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Reverse-lookup third party users given a SDN User ID.
 *
 * Retrieve an array of third party users from a SDN User ID.
 */
class QueryUserByIDJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// An array of third party users.
    
    immer::array<ThirdPartyUser> data() const
    {
    return
      std::move(jsonBody().get()).get<immer::array<ThirdPartyUser>>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Reverse-lookup third party users given a SDN User ID.
 *
    * \param userid
    *   The SDN User ID to look up.
    */
    explicit QueryUserByIDJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userid 
        );


    static BaseJob::Query buildQuery(
    std::string userid);

      static BaseJob::Body buildBody(std::string userid);

        

        

      QueryUserByIDJob withData(JsonWrap j) &&;
      QueryUserByIDJob withData(JsonWrap j) const &;
      };
      using QueryUserByIDResponse = QueryUserByIDJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
