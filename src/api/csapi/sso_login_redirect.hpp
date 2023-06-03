/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Redirect the user's browser to the SSO interface.
 *
 * A web-based SDN client should instruct the user's browser to
 * navigate to this endpoint in order to log in via SSO.
 * 
 * The server MUST respond with an HTTP redirect to the SSO interface.
 */
class RedirectToSSOJob : public BaseJob {
public:



          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Redirect the user's browser to the SSO interface.
 *
    * \param redirectUrl
    *   URI to which the user will be redirected after the node has
    *   authenticated the user with SSO.
    */
    explicit RedirectToSSOJob(std::string serverUrl
    
      ,
        std::string redirectUrl 
        );


    static BaseJob::Query buildQuery(
    std::string redirectUrl);

      static BaseJob::Body buildBody(std::string redirectUrl);

        

        

      RedirectToSSOJob withData(JsonWrap j) &&;
      RedirectToSSOJob withData(JsonWrap j) const &;
      };
      
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
