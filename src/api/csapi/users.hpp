/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Searches the user directory.
 *
 * Performs a search for users. The node may
 * determine which subset of users are searched, however the node
 * MUST at a minimum consider the users the requesting user shares a
 * room with and those who reside in public rooms (known to the node).
 * The search MUST consider local users to the node, and SHOULD
 * query remote users as part of the search.
 * 
 * The search is performed case-insensitively on user IDs and display
 * names preferably using a collation determined based upon the 
 * ``Accept-Language`` header provided in the request, if present.
 */
class SearchUserDirectoryJob : public BaseJob {
public:
  // Inner data structures

/// Performs a search for users. The node may
/// determine which subset of users are searched, however the node
/// MUST at a minimum consider the users the requesting user shares a
/// room with and those who reside in public rooms (known to the node).
/// The search MUST consider local users to the node, and SHOULD
/// query remote users as part of the search.
/// 
/// The search is performed case-insensitively on user IDs and display
/// names preferably using a collation determined based upon the 
/// ``Accept-Language`` header provided in the request, if present.
    struct User
        {
/// The user's SDN user ID.
          std::string userId;
/// The display name of the user, if one exists.
          std::optional<std::string> displayName;
/// The avatar url, as an MXC, if one exists.
          std::optional<std::string> avatarUrl;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// Ordered by rank and then whether or not profile info is available.
immer::array<User> results() const;

    
/// Indicates if the result list has been truncated by the limit.
bool limited() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Searches the user directory.
 *
    * \param searchTerm
    *   The term to search for
    * 
    * \param limit
    *   The maximum number of results to return. Defaults to 10.
    */
    explicit SearchUserDirectoryJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string searchTerm , std::optional<int> limit  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string searchTerm, std::optional<int> limit);

        

        

      SearchUserDirectoryJob withData(JsonWrap j) &&;
      SearchUserDirectoryJob withData(JsonWrap j) const &;
      };
      using SearchUserDirectoryResponse = SearchUserDirectoryJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<SearchUserDirectoryJob::User> {

  static void to_json(json& jo, const SearchUserDirectoryJob::User &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["user_id"s] = pod.userId;
    
    
    addToJsonIfNeeded(jo, "display_name"s, pod.displayName);
    
    addToJsonIfNeeded(jo, "avatar_url"s, pod.avatarUrl);
  }

  static void from_json(const json &jo, SearchUserDirectoryJob::User& result)
  {
  
    if (jo.contains("user_id"s)) {
      result.userId = jo.at("user_id"s);
    }
    if (jo.contains("display_name"s)) {
      result.displayName = jo.at("display_name"s);
    }
    if (jo.contains("avatar_url"s)) {
      result.avatarUrl = jo.at("avatar_url"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
