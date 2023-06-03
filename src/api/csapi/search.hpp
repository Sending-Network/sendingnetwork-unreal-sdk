/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/room_event_filter.hpp"

namespace Kazv::Api {

/*! \brief Perform a server-side search.
 *
 * Performs a full text search across different categories.
 */
class SearchJob : public BaseJob {
public:
  // Inner data structures

/// Configures whether any context for the events
/// returned are included in the response.
    struct IncludeEventContext
        {
/// How many events before the result are
/// returned. By default, this is ``5``.
          std::optional<int> beforeLimit;
/// How many events after the result are
/// returned. By default, this is ``5``.
          std::optional<int> afterLimit;
/// Requests that the server returns the
/// historic profile information for the users
/// that sent the events that were returned.
/// By default, this is ``false``.
          std::optional<bool> includeProfile;
        
        };

/// Configuration for group.
    struct Group
        {
/// Key that defines the group.
          std::optional<std::string> key;
        
        };

/// Requests that the server partitions the result set
/// based on the provided list of keys.
    struct Groupings
        {
/// List of groups to request.
          immer::array<Group> groupBy;
        
        };

/// Mapping of category name to search criteria.
    struct RoomEventsCriteria
        {
/// The string to search events for
          std::string searchTerm;
/// The keys to search. Defaults to all.
          immer::array<std::string> keys;
/// This takes a `filter`_.
          RoomEventFilter filter;
/// The order in which to search for results.
/// By default, this is ``"rank"``.
          std::optional<std::string> orderBy;
/// Configures whether any context for the events
/// returned are included in the response.
          std::optional<IncludeEventContext> eventContext;
/// Requests the server return the current state for
/// each room returned.
          std::optional<bool> includeState;
/// Requests that the server partitions the result set
/// based on the provided list of keys.
          std::optional<Groupings> groupings;
        
        };

/// Describes which categories to search in and their criteria.
    struct Categories
        {
/// Mapping of category name to search criteria.
          std::optional<RoomEventsCriteria> roomEvents;
        
        };

/// Performs a full text search across different categories.
    struct UserProfile
        {
/// Performs a full text search across different categories.
          std::optional<std::string> displayname;
/// Performs a full text search across different categories.
          std::optional<std::string> avatarUrl;
        
        };

/// Context for result, if requested.
    struct EventContext
        {
/// Pagination token for the start of the chunk
          std::optional<std::string> start;
/// Pagination token for the end of the chunk
          std::optional<std::string> end;
/// The historic profile information of the
/// users that sent the events returned.
/// 
/// The ``string`` key is the user ID for which
/// the profile belongs to.
          immer::map<std::string, UserProfile> profileInfo;
/// Events just before the result.
          EventList eventsBefore;
/// Events just after the result.
          EventList eventsAfter;
        
        };

/// The result object.
    struct Result
        {
/// A number that describes how closely this result matches the search. Higher is closer.
          std::optional<double> rank;
/// The event that matched.
          JsonWrap result;
/// Context for result, if requested.
          std::optional<EventContext> context;
        
        };

/// The results for a particular group value.
    struct GroupValue
        {
/// Token that can be used to get the next batch
/// of results in the group, by passing as the
/// `next_batch` parameter to the next call. If
/// this field is absent, there are no more
/// results in this group.
          std::optional<std::string> nextBatch;
/// Key that can be used to order different
/// groups.
          std::optional<int> order;
/// Which results are in this group.
          immer::array<std::string> results;
        
        };

/// Mapping of category name to search criteria.
    struct ResultRoomEvents
        {
/// An approximate count of the total number of results found.
          std::optional<int> count;
/// List of words which should be highlighted, useful for stemming which may change the query terms.
          immer::array<std::string> highlights;
/// List of results in the requested order.
          immer::array<Result> results;
/// The current state for every room in the results.
/// This is included if the request had the
/// ``include_state`` key set with a value of ``true``.
/// 
/// The ``string`` key is the room ID for which the ``State
/// Event`` array belongs to.
          immer::map<std::string, EventList> state;
/// Any groups that were requested.
/// 
/// The outer ``string`` key is the group key requested (eg: ``room_id``
/// or ``sender``). The inner ``string`` key is the grouped value (eg:
/// a room's ID or a user's ID).
          immer::map<std::string, immer::map<std::string, GroupValue>> groups;
/// Token that can be used to get the next batch of
/// results, by passing as the `next_batch` parameter to
/// the next call. If this field is absent, there are no
/// more results.
          std::optional<std::string> nextBatch;
        
        };

/// Describes which categories to search in and their criteria.
    struct ResultCategories
        {
/// Mapping of category name to search criteria.
          std::optional<ResultRoomEvents> roomEvents;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// Describes which categories to search in and their criteria.
ResultCategories searchCategories() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Perform a server-side search.
 *
    * \param searchCategories
    *   Describes which categories to search in and their criteria.
    * 
    * \param nextBatch
    *   The point to return events from. If given, this should be a
    *   ``next_batch`` result from a previous call to this endpoint.
    */
    explicit SearchJob(std::string serverUrl
    , std::string _accessToken
      ,
        Categories searchCategories , std::optional<std::string> nextBatch  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    std::optional<std::string> nextBatch);

      static BaseJob::Body buildBody(Categories searchCategories, std::optional<std::string> nextBatch);

        

        

      SearchJob withData(JsonWrap j) &&;
      SearchJob withData(JsonWrap j) const &;
      };
      using SearchResponse = SearchJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<SearchJob::IncludeEventContext> {

  static void to_json(json& jo, const SearchJob::IncludeEventContext &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "before_limit"s, pod.beforeLimit);
    
    addToJsonIfNeeded(jo, "after_limit"s, pod.afterLimit);
    
    addToJsonIfNeeded(jo, "include_profile"s, pod.includeProfile);
  }

  static void from_json(const json &jo, SearchJob::IncludeEventContext& result)
  {
  
    if (jo.contains("before_limit"s)) {
      result.beforeLimit = jo.at("before_limit"s);
    }
    if (jo.contains("after_limit"s)) {
      result.afterLimit = jo.at("after_limit"s);
    }
    if (jo.contains("include_profile"s)) {
      result.includeProfile = jo.at("include_profile"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SearchJob::Group> {

  static void to_json(json& jo, const SearchJob::Group &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "key"s, pod.key);
  }

  static void from_json(const json &jo, SearchJob::Group& result)
  {
  
    if (jo.contains("key"s)) {
      result.key = jo.at("key"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SearchJob::Groupings> {

  static void to_json(json& jo, const SearchJob::Groupings &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "group_by"s, pod.groupBy);
  }

  static void from_json(const json &jo, SearchJob::Groupings& result)
  {
  
    if (jo.contains("group_by"s)) {
      result.groupBy = jo.at("group_by"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SearchJob::RoomEventsCriteria> {

  static void to_json(json& jo, const SearchJob::RoomEventsCriteria &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["search_term"s] = pod.searchTerm;
    
    
    addToJsonIfNeeded(jo, "keys"s, pod.keys);
    
    addToJsonIfNeeded(jo, "filter"s, pod.filter);
    
    addToJsonIfNeeded(jo, "order_by"s, pod.orderBy);
    
    addToJsonIfNeeded(jo, "event_context"s, pod.eventContext);
    
    addToJsonIfNeeded(jo, "include_state"s, pod.includeState);
    
    addToJsonIfNeeded(jo, "groupings"s, pod.groupings);
  }

  static void from_json(const json &jo, SearchJob::RoomEventsCriteria& result)
  {
  
    if (jo.contains("search_term"s)) {
      result.searchTerm = jo.at("search_term"s);
    }
    if (jo.contains("keys"s)) {
      result.keys = jo.at("keys"s);
    }
    if (jo.contains("filter"s)) {
      result.filter = jo.at("filter"s);
    }
    if (jo.contains("order_by"s)) {
      result.orderBy = jo.at("order_by"s);
    }
    if (jo.contains("event_context"s)) {
      result.eventContext = jo.at("event_context"s);
    }
    if (jo.contains("include_state"s)) {
      result.includeState = jo.at("include_state"s);
    }
    if (jo.contains("groupings"s)) {
      result.groupings = jo.at("groupings"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SearchJob::Categories> {

  static void to_json(json& jo, const SearchJob::Categories &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "room_events"s, pod.roomEvents);
  }

  static void from_json(const json &jo, SearchJob::Categories& result)
  {
  
    if (jo.contains("room_events"s)) {
      result.roomEvents = jo.at("room_events"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SearchJob::UserProfile> {

  static void to_json(json& jo, const SearchJob::UserProfile &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "displayname"s, pod.displayname);
    
    addToJsonIfNeeded(jo, "avatar_url"s, pod.avatarUrl);
  }

  static void from_json(const json &jo, SearchJob::UserProfile& result)
  {
  
    if (jo.contains("displayname"s)) {
      result.displayname = jo.at("displayname"s);
    }
    if (jo.contains("avatar_url"s)) {
      result.avatarUrl = jo.at("avatar_url"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SearchJob::EventContext> {

  static void to_json(json& jo, const SearchJob::EventContext &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "start"s, pod.start);
    
    addToJsonIfNeeded(jo, "end"s, pod.end);
    
    addToJsonIfNeeded(jo, "profile_info"s, pod.profileInfo);
    
    addToJsonIfNeeded(jo, "events_before"s, pod.eventsBefore);
    
    addToJsonIfNeeded(jo, "events_after"s, pod.eventsAfter);
  }

  static void from_json(const json &jo, SearchJob::EventContext& result)
  {
  
    if (jo.contains("start"s)) {
      result.start = jo.at("start"s);
    }
    if (jo.contains("end"s)) {
      result.end = jo.at("end"s);
    }
    if (jo.contains("profile_info"s)) {
      result.profileInfo = jo.at("profile_info"s);
    }
    if (jo.contains("events_before"s)) {
      result.eventsBefore = jo.at("events_before"s);
    }
    if (jo.contains("events_after"s)) {
      result.eventsAfter = jo.at("events_after"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SearchJob::Result> {

  static void to_json(json& jo, const SearchJob::Result &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "rank"s, pod.rank);
    
    addToJsonIfNeeded(jo, "result"s, pod.result);
    
    addToJsonIfNeeded(jo, "context"s, pod.context);
  }

  static void from_json(const json &jo, SearchJob::Result& result)
  {
  
    if (jo.contains("rank"s)) {
      result.rank = jo.at("rank"s);
    }
    if (jo.contains("result"s)) {
      result.result = jo.at("result"s);
    }
    if (jo.contains("context"s)) {
      result.context = jo.at("context"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SearchJob::GroupValue> {

  static void to_json(json& jo, const SearchJob::GroupValue &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "next_batch"s, pod.nextBatch);
    
    addToJsonIfNeeded(jo, "order"s, pod.order);
    
    addToJsonIfNeeded(jo, "results"s, pod.results);
  }

  static void from_json(const json &jo, SearchJob::GroupValue& result)
  {
  
    if (jo.contains("next_batch"s)) {
      result.nextBatch = jo.at("next_batch"s);
    }
    if (jo.contains("order"s)) {
      result.order = jo.at("order"s);
    }
    if (jo.contains("results"s)) {
      result.results = jo.at("results"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SearchJob::ResultRoomEvents> {

  static void to_json(json& jo, const SearchJob::ResultRoomEvents &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "count"s, pod.count);
    
    addToJsonIfNeeded(jo, "highlights"s, pod.highlights);
    
    addToJsonIfNeeded(jo, "results"s, pod.results);
    
    addToJsonIfNeeded(jo, "state"s, pod.state);
    
    addToJsonIfNeeded(jo, "groups"s, pod.groups);
    
    addToJsonIfNeeded(jo, "next_batch"s, pod.nextBatch);
  }

  static void from_json(const json &jo, SearchJob::ResultRoomEvents& result)
  {
  
    if (jo.contains("count"s)) {
      result.count = jo.at("count"s);
    }
    if (jo.contains("highlights"s)) {
      result.highlights = jo.at("highlights"s);
    }
    if (jo.contains("results"s)) {
      result.results = jo.at("results"s);
    }
    if (jo.contains("state"s)) {
      result.state = jo.at("state"s);
    }
    if (jo.contains("groups"s)) {
      result.groups = jo.at("groups"s);
    }
    if (jo.contains("next_batch"s)) {
      result.nextBatch = jo.at("next_batch"s);
    }
  
  }

};
      template<>
      struct adl_serializer<SearchJob::ResultCategories> {

  static void to_json(json& jo, const SearchJob::ResultCategories &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "room_events"s, pod.roomEvents);
  }

  static void from_json(const json &jo, SearchJob::ResultCategories& result)
  {
  
    if (jo.contains("room_events"s)) {
      result.roomEvents = jo.at("room_events"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
