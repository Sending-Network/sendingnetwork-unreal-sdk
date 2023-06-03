/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/wellknown/full.hpp"

namespace Kazv::Api {

/*! \brief Gets SDN server discovery information about the domain.
 *
 * Gets discovery information about the domain. The file may include
 * additional keys, which MUST follow the Java package naming convention,
 * e.g. ``com.example.myapp.property``. This ensures property names are
 * suitably namespaced for each application and reduces the risk of
 * clashes.
 * 
 * Note that this endpoint is not necessarily handled by the node,
 * but by another webserver, to be used for discovering the node URL.
 */
class GetWellknownJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// Server discovery information.
    
    DiscoveryInformation data() const
    {
    return
      std::move(jsonBody().get()).get<DiscoveryInformation>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

    /// Gets SDN server discovery information about the domain.
    explicit GetWellknownJob(std::string serverUrl
    
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      GetWellknownJob withData(JsonWrap j) &&;
      GetWellknownJob withData(JsonWrap j) const &;
      };
      using GetWellknownResponse = GetWellknownJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
