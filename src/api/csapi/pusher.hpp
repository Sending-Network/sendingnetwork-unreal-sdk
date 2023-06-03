/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Gets the current pushers for the authenticated user
 *
 * Gets all currently active pushers for the authenticated user.
 */
class GetPushersJob : public BaseJob {
public:
  // Inner data structures

/// A dictionary of information for the pusher implementation
/// itself.
    struct PusherData
        {
/// Required if ``kind`` is ``http``. The URL to use to send
/// notifications to.
          std::optional<std::string> url;
/// The format to use when sending notifications to the Push
/// Gateway.
          std::optional<std::string> format;
        
        };

/// Gets all currently active pushers for the authenticated user.
    struct Pusher
        {
/// This is a unique identifier for this pusher. See ``/set`` for
/// more detail.
/// Max length, 512 bytes.
          std::string pushkey;
/// The kind of pusher. ``"http"`` is a pusher that
/// sends HTTP pokes.
          std::string kind;
/// This is a reverse-DNS style identifier for the application.
/// Max length, 64 chars.
          std::string appId;
/// A string that will allow the user to identify what application
/// owns this pusher.
          std::string appDisplayName;
/// A string that will allow the user to identify what device owns
/// this pusher.
          std::string deviceDisplayName;
/// This string determines which set of device specific rules this
/// pusher executes.
          std::optional<std::string> profileTag;
/// The preferred language for receiving notifications (e.g. 'en'
/// or 'en-US')
          std::string lang;
/// A dictionary of information for the pusher implementation
/// itself.
          PusherData data;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// An array containing the current pushers for the user
immer::array<Pusher> pushers() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

    /// Gets the current pushers for the authenticated user
    explicit GetPushersJob(std::string serverUrl
    , std::string _accessToken
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      GetPushersJob withData(JsonWrap j) &&;
      GetPushersJob withData(JsonWrap j) const &;
      };
      using GetPushersResponse = GetPushersJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<GetPushersJob::PusherData> {

  static void to_json(json& jo, const GetPushersJob::PusherData &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "url"s, pod.url);
    
    addToJsonIfNeeded(jo, "format"s, pod.format);
  }

  static void from_json(const json &jo, GetPushersJob::PusherData& result)
  {
  
    if (jo.contains("url"s)) {
      result.url = jo.at("url"s);
    }
    if (jo.contains("format"s)) {
      result.format = jo.at("format"s);
    }
  
  }

};
      template<>
      struct adl_serializer<GetPushersJob::Pusher> {

  static void to_json(json& jo, const GetPushersJob::Pusher &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["pushkey"s] = pod.pushkey;
    
    jo["kind"s] = pod.kind;
    
    jo["app_id"s] = pod.appId;
    
    jo["app_display_name"s] = pod.appDisplayName;
    
    jo["device_display_name"s] = pod.deviceDisplayName;
    
    
    addToJsonIfNeeded(jo, "profile_tag"s, pod.profileTag);
    jo["lang"s] = pod.lang;
    
    jo["data"s] = pod.data;
    
  }

  static void from_json(const json &jo, GetPushersJob::Pusher& result)
  {
  
    if (jo.contains("pushkey"s)) {
      result.pushkey = jo.at("pushkey"s);
    }
    if (jo.contains("kind"s)) {
      result.kind = jo.at("kind"s);
    }
    if (jo.contains("app_id"s)) {
      result.appId = jo.at("app_id"s);
    }
    if (jo.contains("app_display_name"s)) {
      result.appDisplayName = jo.at("app_display_name"s);
    }
    if (jo.contains("device_display_name"s)) {
      result.deviceDisplayName = jo.at("device_display_name"s);
    }
    if (jo.contains("profile_tag"s)) {
      result.profileTag = jo.at("profile_tag"s);
    }
    if (jo.contains("lang"s)) {
      result.lang = jo.at("lang"s);
    }
    if (jo.contains("data"s)) {
      result.data = jo.at("data"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

/*! \brief Modify a pusher for this user on the node.
 *
 * This endpoint allows the creation, modification and deletion of `pushers`_
 * for this user ID. The behaviour of this endpoint varies depending on the
 * values in the JSON body.
 */
class PostPusherJob : public BaseJob {
public:
  // Inner data structures

/// A dictionary of information for the pusher implementation
/// itself. If ``kind`` is ``http``, this should contain ``url``
/// which is the URL to use to send notifications to.
    struct PusherData
        {
/// Required if ``kind`` is ``http``. The URL to use to send
/// notifications to. MUST be an HTTPS URL with a path of 
/// ``/_api/push/v1/notify``.
          std::optional<std::string> url;
/// The format to send notifications in to Push Gateways if the
/// ``kind`` is ``http``. The details about what fields the
/// node should send to the push gateway are defined in the
/// `Push Gateway Specification`_. Currently the only format
/// available is 'event_id_only'.
          std::optional<std::string> format;
        
        };



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

  /*! \brief Modify a pusher for this user on the node.
 *
    * \param pushkey
    *   This is a unique identifier for this pusher. The value you
    *   should use for this is the routing or destination address
    *   information for the notification, for example, the APNS token
    *   for APNS or the Registration ID for GCM. If your notification
    *   client has no such concept, use any unique identifier.
    *   Max length, 512 bytes.
    *   
    *   If the ``kind`` is ``"email"``, this is the email address to
    *   send notifications to.
    * 
    * \param kind
    *   The kind of pusher to configure. ``"http"`` makes a pusher that
    *   sends HTTP pokes. ``"email"`` makes a pusher that emails the
    *   user with unread notifications. ``null`` deletes the pusher.
    * 
    * \param appId
    *   This is a reverse-DNS style identifier for the application.
    *   It is recommended that this end with the platform, such that
    *   different platform versions get different app identifiers.
    *   Max length, 64 chars.
    *   
    *   If the ``kind`` is ``"email"``, this is ``"m.email"``.
    * 
    * \param appDisplayName
    *   A string that will allow the user to identify what application
    *   owns this pusher.
    * 
    * \param deviceDisplayName
    *   A string that will allow the user to identify what device owns
    *   this pusher.
    * 
    * \param lang
    *   The preferred language for receiving notifications (e.g. 'en'
    *   or 'en-US').
    * 
    * \param data
    *   A dictionary of information for the pusher implementation
    *   itself. If ``kind`` is ``http``, this should contain ``url``
    *   which is the URL to use to send notifications to.
    * 
    * \param profileTag
    *   This string determines which set of device specific rules this
    *   pusher executes.
    * 
    * \param append
    *   If true, the node should add another pusher with the
    *   given pushkey and App ID in addition to any others with
    *   different user IDs. Otherwise, the node must remove any
    *   other pushers with the same App ID and pushkey for different
    *   users. The default is ``false``.
    */
    explicit PostPusherJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string pushkey , std::string kind , std::string appId , std::string appDisplayName , std::string deviceDisplayName , std::string lang , PusherData data , std::optional<std::string> profileTag  = std::nullopt, std::optional<bool> append  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string pushkey, std::string kind, std::string appId, std::string appDisplayName, std::string deviceDisplayName, std::string lang, PusherData data, std::optional<std::string> profileTag, std::optional<bool> append);

        

        

      PostPusherJob withData(JsonWrap j) &&;
      PostPusherJob withData(JsonWrap j) const &;
      };
      using PostPusherResponse = PostPusherJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<PostPusherJob::PusherData> {

  static void to_json(json& jo, const PostPusherJob::PusherData &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "url"s, pod.url);
    
    addToJsonIfNeeded(jo, "format"s, pod.format);
  }

  static void from_json(const json &jo, PostPusherJob::PusherData& result)
  {
  
    if (jo.contains("url"s)) {
      result.url = jo.at("url"s);
    }
    if (jo.contains("format"s)) {
      result.format = jo.at("format"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
