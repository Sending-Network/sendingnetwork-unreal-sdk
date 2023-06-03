/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/sync_filter.hpp"

namespace Kazv::Api {

/*! \brief Upload a new filter.
 *
 * Uploads a new filter definition to the node.
 * Returns a filter ID that may be used in future requests to
 * restrict which events are returned to the client.
 */
class DefineFilterJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The ID of the filter that was created. Cannot start
/// with a ``{`` as this character is used to determine
/// if the filter provided is inline JSON or a previously
/// declared filter by nodes on some APIs.
std::string filterId() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Upload a new filter.
 *
    * \param userId
    *   The id of the user uploading the filter. The access token must be authorized to make requests for this user id.
    * 
    * \param filter
    *   The filter to upload.
    */
    explicit DefineFilterJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , Filter filter 
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId, Filter filter);

        

        

      DefineFilterJob withData(JsonWrap j) &&;
      DefineFilterJob withData(JsonWrap j) const &;
      };
      using DefineFilterResponse = DefineFilterJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Download a filter
 *
 */
class GetFilterJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// The filter definition.
    
    Filter data() const
    {
    return
      std::move(jsonBody().get()).get<Filter>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Download a filter
 *
    * \param userId
    *   The user ID to download a filter for.
    * 
    * \param filterId
    *   The filter ID to download.
    */
    explicit GetFilterJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , std::string filterId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId, std::string filterId);

        

        

      GetFilterJob withData(JsonWrap j) &&;
      GetFilterJob withData(JsonWrap j) const &;
      };
      using GetFilterResponse = GetFilterJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
