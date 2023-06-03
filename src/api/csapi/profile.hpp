/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Set the user's display name.
 *
 * This API sets the given user's display name. You must have permission to
 * set this user's display name, e.g. you need to have their ``access_token``.
 */
class SetDisplayNameJob : public BaseJob {
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

  /*! \brief Set the user's display name.
 *
    * \param userId
    *   The user whose display name to set.
    * 
    * \param displayname
    *   The new display name for this user.
    */
    explicit SetDisplayNameJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , std::optional<std::string> displayname  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId, std::optional<std::string> displayname);

        

        

      SetDisplayNameJob withData(JsonWrap j) &&;
      SetDisplayNameJob withData(JsonWrap j) const &;
      };
      using SetDisplayNameResponse = SetDisplayNameJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get the user's display name.
 *
 * Get the user's display name. This API may be used to fetch the user's
 * own displayname or to query the name of other users; either locally or
 * on remote nodes.
 */
class GetDisplayNameJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The user's display name if they have set one, otherwise not present.
std::optional<std::string> displayname() const;

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Get the user's display name.
 *
    * \param userId
    *   The user whose display name to get.
    */
    explicit GetDisplayNameJob(std::string serverUrl
    
      ,
        std::string userId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId);

        

        

      GetDisplayNameJob withData(JsonWrap j) &&;
      GetDisplayNameJob withData(JsonWrap j) const &;
      };
      using GetDisplayNameResponse = GetDisplayNameJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Set the user's avatar URL.
 *
 * This API sets the given user's avatar URL. You must have permission to
 * set this user's avatar URL, e.g. you need to have their ``access_token``.
 */
class SetAvatarUrlJob : public BaseJob {
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

  /*! \brief Set the user's avatar URL.
 *
    * \param userId
    *   The user whose avatar URL to set.
    * 
    * \param avatarUrl
    *   The new avatar URL for this user.
    */
    explicit SetAvatarUrlJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string userId , std::optional<std::string> avatarUrl  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId, std::optional<std::string> avatarUrl);

        

        

      SetAvatarUrlJob withData(JsonWrap j) &&;
      SetAvatarUrlJob withData(JsonWrap j) const &;
      };
      using SetAvatarUrlResponse = SetAvatarUrlJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get the user's avatar URL.
 *
 * Get the user's avatar URL. This API may be used to fetch the user's
 * own avatar URL or to query the URL of other users; either locally or
 * on remote nodes.
 */
class GetAvatarUrlJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The user's avatar URL if they have set one, otherwise not present.
std::optional<std::string> avatarUrl() const;

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Get the user's avatar URL.
 *
    * \param userId
    *   The user whose avatar URL to get.
    */
    explicit GetAvatarUrlJob(std::string serverUrl
    
      ,
        std::string userId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId);

        

        

      GetAvatarUrlJob withData(JsonWrap j) &&;
      GetAvatarUrlJob withData(JsonWrap j) const &;
      };
      using GetAvatarUrlResponse = GetAvatarUrlJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get this user's profile information.
 *
 * Get the combined profile information for this user. This API may be used
 * to fetch the user's own profile information or other users; either
 * locally or on remote nodes. This API may return keys which are not
 * limited to ``displayname`` or ``avatar_url``.
 */
class GetUserProfileJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The user's avatar URL if they have set one, otherwise not present.
std::optional<std::string> avatarUrl() const;

    
/// The user's display name if they have set one, otherwise not present.
std::optional<std::string> displayname() const;

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Get this user's profile information.
 *
    * \param userId
    *   The user whose profile information to get.
    */
    explicit GetUserProfileJob(std::string serverUrl
    
      ,
        std::string userId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string userId);

        

        

      GetUserProfileJob withData(JsonWrap j) &&;
      GetUserProfileJob withData(JsonWrap j) const &;
      };
      using GetUserProfileResponse = GetUserProfileJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
