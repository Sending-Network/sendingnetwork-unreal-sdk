/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "sso_login_redirect.hpp"

namespace Kazv::Api
{

  
BaseJob::Query RedirectToSSOJob::buildQuery(
std::string redirectUrl)
{
BaseJob::Query _q;
    addToQuery(_q, "redirectUrl"s, redirectUrl);
  
return _q;
}

    BaseJob::Body RedirectToSSOJob::buildBody(std::string redirectUrl)
      {
      // ignore unused param
      (void)(redirectUrl);
      
      
              return BaseJob::EmptyBody{};

      };

      

RedirectToSSOJob::RedirectToSSOJob(
        std::string serverUrl
        
            ,
        std::string redirectUrl
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/login/sso/redirect",
          GET,
          std::string("RedirectToSSO"),
           {} ,
          ReturnType::Json,
            buildBody(redirectUrl)
              , buildQuery(redirectUrl)
                , {}

)
        {
        }

        RedirectToSSOJob RedirectToSSOJob::withData(JsonWrap j) &&
        {
          auto ret = RedirectToSSOJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        RedirectToSSOJob RedirectToSSOJob::withData(JsonWrap j) const &
        {
          auto ret = RedirectToSSOJob(*this);
          ret.attachData(j);
          return ret;
        }

        

}
