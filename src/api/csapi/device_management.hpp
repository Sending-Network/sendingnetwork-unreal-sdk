/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/auth_data.hpp"
#include "csapi/definitions/client_device.hpp"

namespace Kazv::Api {

/*! \brief List registered devices for the current user
 *
 * Gets information about all devices for the current user.
 */
class GetDevicesJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// A list of all registered devices for this user.
immer::array<Device> devices() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

    /// List registered devices for the current user
    explicit GetDevicesJob(std::string serverUrl
    , std::string _accessToken
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      GetDevicesJob withData(JsonWrap j) &&;
      GetDevicesJob withData(JsonWrap j) const &;
      };
      using GetDevicesResponse = GetDevicesJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get a single device
 *
 * Gets information on a single device, by device id.
 */
class GetDeviceJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// Device information
    
    Device data() const
    {
    return
      std::move(jsonBody().get()).get<Device>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get a single device
 *
    * \param deviceId
    *   The device to retrieve.
    */
    explicit GetDeviceJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string deviceId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string deviceId);

        

        

      GetDeviceJob withData(JsonWrap j) &&;
      GetDeviceJob withData(JsonWrap j) const &;
      };
      using GetDeviceResponse = GetDeviceJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Update a device
 *
 * Updates the metadata on the given device.
 */
class UpdateDeviceJob : public BaseJob {
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

  /*! \brief Update a device
 *
    * \param deviceId
    *   The device to update.
    * 
    * \param displayName
    *   The new display name for this device. If not given, the
    *   display name is unchanged.
    */
    explicit UpdateDeviceJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string deviceId , std::optional<std::string> displayName  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string deviceId, std::optional<std::string> displayName);

        

        

      UpdateDeviceJob withData(JsonWrap j) &&;
      UpdateDeviceJob withData(JsonWrap j) const &;
      };
      using UpdateDeviceResponse = UpdateDeviceJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Delete a device
 *
 * This API endpoint uses the `User-Interactive Authentication API`_.
 * 
 * Deletes the given device, and invalidates any access token associated with it.
 */
class DeleteDeviceJob : public BaseJob {
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

  /*! \brief Delete a device
 *
    * \param deviceId
    *   The device to delete.
    * 
    * \param auth
    *   Additional authentication information for the
    *   user-interactive authentication API.
    */
    explicit DeleteDeviceJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string deviceId , std::optional<AuthenticationData> auth  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string deviceId, std::optional<AuthenticationData> auth);

        

        

      DeleteDeviceJob withData(JsonWrap j) &&;
      DeleteDeviceJob withData(JsonWrap j) const &;
      };
      using DeleteDeviceResponse = DeleteDeviceJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Bulk deletion of devices
 *
 * This API endpoint uses the `User-Interactive Authentication API`_.
 * 
 * Deletes the given devices, and invalidates any access token associated with them.
 */
class DeleteDevicesJob : public BaseJob {
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

  /*! \brief Bulk deletion of devices
 *
    * \param devices
    *   The list of device IDs to delete.
    * 
    * \param auth
    *   Additional authentication information for the
    *   user-interactive authentication API.
    */
    explicit DeleteDevicesJob(std::string serverUrl
    , std::string _accessToken
      ,
        immer::array<std::string> devices , std::optional<AuthenticationData> auth  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(immer::array<std::string> devices, std::optional<AuthenticationData> auth);

        

        

      DeleteDevicesJob withData(JsonWrap j) &&;
      DeleteDevicesJob withData(JsonWrap j) const &;
      };
      using DeleteDevicesResponse = DeleteDevicesJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
