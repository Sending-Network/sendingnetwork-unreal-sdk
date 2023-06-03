/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"


namespace Kazv::Api {

/*! \brief Snapshot the current state of a room and its most recent messages.
 *
 * Get a copy of the current state and the most recent messages in a room.
 * 
 * This endpoint was deprecated in r0 of this specification. There is no
 * direct replacement; the relevant information is returned by the
 * |/sync|_ API.
 */
class RoomInitialSyncJob : public BaseJob {
public:
  // Inner data structures

/// The pagination chunk for this room.
    struct PaginationChunk
        {
/// A token which correlates to the first value in ``chunk``.
/// Used for pagination.
          std::string start;
/// A token which correlates to the last value in ``chunk``.
/// Used for pagination.
          std::string end;
/// If the user is a member of the room this will be a
/// list of the most recent messages for this room. If
/// the user has left the room this will be the
/// messages that preceeded them leaving. This array
/// will consist of at most ``limit`` elements.
          EventList chunk;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The ID of this room.
std::string roomId() const;

    
/// The user's membership state in this room.
std::optional<std::string> membership() const;

    
/// The pagination chunk for this room.
std::optional<PaginationChunk> messages() const;

    
/// If the user is a member of the room this will be the
/// current state of the room as a list of events. If the
/// user has left the room this will be the state of the
/// room when they left it.
EventList state() const;

    
/// Whether this room is visible to the ``/publicRooms`` API
/// or not."
std::optional<std::string> visibility() const;

    
/// The private data that this user has attached to this room.
EventList accountData() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Snapshot the current state of a room and its most recent messages.
 *
    * \param roomId
    *   The room to get the data.
    */
    explicit RoomInitialSyncJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string roomId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string roomId);

        

        

      RoomInitialSyncJob withData(JsonWrap j) &&;
      RoomInitialSyncJob withData(JsonWrap j) const &;
      };
      using RoomInitialSyncResponse = RoomInitialSyncJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<RoomInitialSyncJob::PaginationChunk> {

  static void to_json(json& jo, const RoomInitialSyncJob::PaginationChunk &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    jo["start"s] = pod.start;
    
    jo["end"s] = pod.end;
    
    jo["chunk"s] = pod.chunk;
    
  }

  static void from_json(const json &jo, RoomInitialSyncJob::PaginationChunk& result)
  {
  
    if (jo.contains("start"s)) {
      result.start = jo.at("start"s);
    }
    if (jo.contains("end"s)) {
      result.end = jo.at("end"s);
    }
    if (jo.contains("chunk"s)) {
      result.chunk = jo.at("chunk"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
