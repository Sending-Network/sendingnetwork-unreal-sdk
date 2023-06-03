/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Gets a list of events that the user has been notified about
 *
 * This API is used to paginate through the list of events that the
 * user has been, or would have been notified about.
 */
class GetNotificationsJob : public BaseJob {
public:
  // Inner data structures

/// This API is used to paginate through the list of events that the
/// user has been, or would have been notified about.
    struct Notification
        {
/// The action(s) to perform when the conditions for this rule are met.
/// See `Push Rules: API`_.
          immer::array<Variant> actions;
/// The Event object for the event that triggered the notification.
          JsonWrap event;
/// The profile tag of the rule that matched this event.
          std::optional<std::string> profileTag;
/// Indicates whether the user has sent a read receipt indicating
/// that they have read this message.
          bool read;
/// The ID of the room in which the event was posted.
          std::string roomId;
/// The unix timestamp at which the event notification was sent,
/// in milliseconds.
          int ts;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The token to supply in the ``from`` param of the next
/// ``/notifications`` request in order to request more
/// events. If this is absent, there are no more results.
std::optional<std::string> nextToken() const;

    
/// The list of events that triggered notifications.
immer::array<Notification> notifications() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Gets a list of events that the user has been notified about
 *
    * \param from
    *   Pagination token given to retrieve the next set of events.
    * 
    * \param limit
    *   Limit on the number of events to return in this request.
    * 
    * \param only
    *   Allows basic filtering of events returned. Supply ``highlight``
    *   to return only events where the notification had the highlight
    *   tweak set.
    */
    explicit GetNotificationsJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::optional<std::string> from  = std::nullopt, std::optional<int> limit  = std::nullopt, std::optional<std::string> only  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::optional<std::string> from, std::optional<int> limit, std::optional<std::string> only);

      static BaseJob::Body buildBody(std::optional<std::string> from, std::optional<int> limit, std::optional<std::string> only);

        

        

      GetNotificationsJob withData(JsonWrap j) &&;
      GetNotificationsJob withData(JsonWrap j) const &;
      };
      using GetNotificationsResponse = GetNotificationsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<GetNotificationsJob::Notification> {

  static void to_json(json& jo, const GetNotificationsJob::Notification &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["actions"s] = pod.actions;
    
    jo["event"s] = pod.event;
    
    
    addToJsonIfNeeded(jo, "profile_tag"s, pod.profileTag);
    jo["read"s] = pod.read;
    
    jo["room_id"s] = pod.roomId;
    
    jo["ts"s] = pod.ts;
    
  }

  static void from_json(const json &jo, GetNotificationsJob::Notification& result)
  {
  
    if (jo.contains("actions"s)) {
      result.actions = jo.at("actions"s);
    }
    if (jo.contains("event"s)) {
      result.event = jo.at("event"s);
    }
    if (jo.contains("profile_tag"s)) {
      result.profileTag = jo.at("profile_tag"s);
    }
    if (jo.contains("read"s)) {
      result.read = jo.at("read"s);
    }
    if (jo.contains("room_id"s)) {
      result.roomId = jo.at("room_id"s);
    }
    if (jo.contains("ts"s)) {
      result.ts = jo.at("ts"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
