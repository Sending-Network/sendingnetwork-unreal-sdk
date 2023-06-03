/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/device_keys.hpp"

namespace Kazv::Api {

/*! \brief Upload end-to-end encryption keys.
 *
 * Publishes end-to-end encryption keys for the device.
 */
class UploadKeysJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// For each key algorithm, the number of unclaimed one-time keys
/// of that type currently held on the server for this device.
immer::map<std::string, int> oneTimeKeyCounts() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Upload end-to-end encryption keys.
 *
    * \param deviceKeys
    *   Identity keys for the device. May be absent if no new
    *   identity keys are required.
    * 
    * \param oneTimeKeys
    *   One-time public keys for "pre-key" messages.  The names of
    *   the properties should be in the format
    *   ``<algorithm>:<key_id>``. The format of the key is determined
    *   by the `key algorithm <#key-algorithms>`_.
    *   
    *   May be absent if no new one-time keys are required.
    */
    explicit UploadKeysJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::optional<DeviceKeys> deviceKeys  = std::nullopt, immer::map<std::string, Variant> oneTimeKeys  = {}
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::optional<DeviceKeys> deviceKeys, immer::map<std::string, Variant> oneTimeKeys);

        

        

      UploadKeysJob withData(JsonWrap j) &&;
      UploadKeysJob withData(JsonWrap j) const &;
      };
      using UploadKeysResponse = UploadKeysJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Download device identity keys.
 *
 * Returns the current devices and identity keys for the given users.
 */
class QueryKeysJob : public BaseJob {
public:
  // Inner data structures

/// Additional data added to the device key information
/// by intermediate servers, and not covered by the
/// signatures.
    struct UnsignedDeviceInfo
        {
/// The display name which the user set on the device.
          std::optional<std::string> deviceDisplayName;
        
        };

/// Returns the current devices and identity keys for the given users.
    struct DeviceInformation :
      DeviceKeys
        {
/// Additional data added to the device key information
/// by intermediate servers, and not covered by the
/// signatures.
          std::optional<UnsignedDeviceInfo> unsignedData;
        
        };



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// If any remote nodes could not be reached, they are
/// recorded here. The names of the properties are the names of
/// the unreachable servers.
/// 
/// If the node could be reached, but the user or device
/// was unknown, no failure is recorded. Instead, the corresponding
/// user or device is missing from the ``device_keys`` result.
immer::map<std::string, JsonWrap> failures() const;

    
/// Information on the queried devices. A map from user ID, to a
/// map from device ID to device information.  For each device,
/// the information returned will be the same as uploaded via
/// ``/keys/upload``, with the addition of an ``unsigned``
/// property.
immer::map<std::string, immer::map<std::string, DeviceInformation>> deviceKeys() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Download device identity keys.
 *
    * \param deviceKeys
    *   The keys to be downloaded. A map from user ID, to a list of
    *   device IDs, or to an empty list to indicate all devices for the
    *   corresponding user.
    * 
    * \param timeout
    *   The time (in milliseconds) to wait when downloading keys from
    *   remote servers. 10 seconds is the recommended default.
    * 
    * \param token
    *   If the client is fetching keys as a result of a device update received
    *   in a sync request, this should be the 'since' token of that sync request,
    *   or any later sync token. This allows the server to ensure its response
    *   contains the keys advertised by the notification in that sync.
    */
    explicit QueryKeysJob(std::string serverUrl
    , std::string _accessToken
      ,
        immer::map<std::string, immer::array<std::string>> deviceKeys , std::optional<int> timeout  = std::nullopt, std::optional<std::string> token  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(immer::map<std::string, immer::array<std::string>> deviceKeys, std::optional<int> timeout, std::optional<std::string> token);

        

        

      QueryKeysJob withData(JsonWrap j) &&;
      QueryKeysJob withData(JsonWrap j) const &;
      };
      using QueryKeysResponse = QueryKeysJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
      template<>
      struct adl_serializer<QueryKeysJob::UnsignedDeviceInfo> {

  static void to_json(json& jo, const QueryKeysJob::UnsignedDeviceInfo &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
  
  
    
    addToJsonIfNeeded(jo, "device_display_name"s, pod.deviceDisplayName);
  }

  static void from_json(const json &jo, QueryKeysJob::UnsignedDeviceInfo& result)
  {
  
    if (jo.contains("device_display_name"s)) {
      result.deviceDisplayName = jo.at("device_display_name"s);
    }
  
  }

};
      template<>
      struct adl_serializer<QueryKeysJob::DeviceInformation> {

  static void to_json(json& jo, const QueryKeysJob::DeviceInformation &pod)
  {
  if (! jo.is_object()) { jo = json::object(); }
    jo = static_cast<const DeviceKeys &>(pod);
    //nlohmann::to_json(jo, static_cast<const DeviceKeys &>(pod));
  
    
    addToJsonIfNeeded(jo, "unsigned"s, pod.unsignedData);
  }

  static void from_json(const json &jo, QueryKeysJob::DeviceInformation& result)
  {
    static_cast<DeviceKeys &>(result) = jo;
    //nlohmann::from_json(jo, static_cast<const DeviceKeys &>(result));
    if (jo.contains("unsigned"s)) {
      result.unsignedData = jo.at("unsigned"s);
    }
  
  }

};
    }

    namespace Kazv::Api
    {

/*! \brief Claim one-time encryption keys.
 *
 * Claims one-time keys for use in pre-key messages.
 */
class ClaimKeysJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// If any remote nodes could not be reached, they are
/// recorded here. The names of the properties are the names of
/// the unreachable servers.
/// 
/// If the node could be reached, but the user or device
/// was unknown, no failure is recorded. Instead, the corresponding
/// user or device is missing from the ``one_time_keys`` result.
immer::map<std::string, JsonWrap> failures() const;

    
/// One-time keys for the queried devices. A map from user ID, to a
/// map from devices to a map from ``<algorithm>:<key_id>`` to the key object.
/// 
/// See the `key algorithms <#key-algorithms>`_ section for information
/// on the Key Object format.
immer::map<std::string, immer::map<std::string, Variant>> oneTimeKeys() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Claim one-time encryption keys.
 *
    * \param oneTimeKeys
    *   The keys to be claimed. A map from user ID, to a map from
    *   device ID to algorithm name.
    * 
    * \param timeout
    *   The time (in milliseconds) to wait when downloading keys from
    *   remote servers. 10 seconds is the recommended default.
    */
    explicit ClaimKeysJob(std::string serverUrl
    , std::string _accessToken
      ,
        immer::map<std::string, immer::map<std::string, std::string>> oneTimeKeys , std::optional<int> timeout  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(immer::map<std::string, immer::map<std::string, std::string>> oneTimeKeys, std::optional<int> timeout);

        

        

      ClaimKeysJob withData(JsonWrap j) &&;
      ClaimKeysJob withData(JsonWrap j) const &;
      };
      using ClaimKeysResponse = ClaimKeysJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Query users with recent device key updates.
 *
 * Gets a list of users who have updated their device identity keys since a
 * previous sync token.
 * 
 * The server should include in the results any users who:
 * 
 * * currently share a room with the calling user (ie, both users have
 *   membership state ``join``); *and*
 * * added new device identity keys or removed an existing device with
 *   identity keys, between ``from`` and ``to``.
 */
class GetKeysChangesJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The User IDs of all users who updated their device
/// identity keys.
immer::array<std::string> changed() const;

    
/// The User IDs of all users who may have left all
/// the end-to-end encrypted rooms they previously shared
/// with the user.
immer::array<std::string> left() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Query users with recent device key updates.
 *
    * \param from
    *   The desired start point of the list. Should be the ``next_batch`` field
    *   from a response to an earlier call to |/sync|. Users who have not
    *   uploaded new device identity keys since this point, nor deleted
    *   existing devices with identity keys since then, will be excluded
    *   from the results.
    * 
    * \param to
    *   The desired end point of the list. Should be the ``next_batch``
    *   field from a recent call to |/sync| - typically the most recent
    *   such call. This may be used by the server as a hint to check its
    *   caches are up to date.
    */
    explicit GetKeysChangesJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string from , std::string to 
        );


    static BaseJob::Query buildQuery(
    std::string from, std::string to);

      static BaseJob::Body buildBody(std::string from, std::string to);

        

        

      GetKeysChangesJob withData(JsonWrap j) &&;
      GetKeysChangesJob withData(JsonWrap j) const &;
      };
      using GetKeysChangesResponse = GetKeysChangesJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
