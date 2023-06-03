/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "device_management.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetDevicesJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetDevicesJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetDevicesJob::GetDevicesJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/devices",
          GET,
          std::string("GetDevices"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetDevicesJob GetDevicesJob::withData(JsonWrap j) &&
        {
          auto ret = GetDevicesJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetDevicesJob GetDevicesJob::withData(JsonWrap j) const &
        {
          auto ret = GetDevicesJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetDevicesJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetDevicesResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    immer::array<Device> GetDevicesResponse::devices() const
    {
    if (jsonBody().get()
    .contains("devices"s)) {
    return
    jsonBody().get()["devices"s]
    .template get<immer::array<Device>>();}
    else { return immer::array<Device>(  );}
    }


  
BaseJob::Query GetDeviceJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetDeviceJob::buildBody(std::string deviceId)
      {
      // ignore unused param
      (void)(deviceId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetDeviceJob::GetDeviceJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string deviceId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/devices/" + deviceId,
          GET,
          std::string("GetDevice"),
          _accessToken,
          ReturnType::Json,
            buildBody(deviceId)
              , buildQuery()
                , {}

)
        {
        }

        GetDeviceJob GetDeviceJob::withData(JsonWrap j) &&
        {
          auto ret = GetDeviceJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetDeviceJob GetDeviceJob::withData(JsonWrap j) const &
        {
          auto ret = GetDeviceJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetDeviceJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetDeviceResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query UpdateDeviceJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body UpdateDeviceJob::buildBody(std::string deviceId, std::optional<std::string> displayName)
      {
      // ignore unused param
      (void)(deviceId);(void)(displayName);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "display_name"s, displayName);
        return BaseJob::JsonBody(_data);
        

      };

      

UpdateDeviceJob::UpdateDeviceJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string deviceId, std::optional<std::string> displayName
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/devices/" + deviceId,
          PUT,
          std::string("UpdateDevice"),
          _accessToken,
          ReturnType::Json,
            buildBody(deviceId, displayName)
              , buildQuery()
                , {}

)
        {
        }

        UpdateDeviceJob UpdateDeviceJob::withData(JsonWrap j) &&
        {
          auto ret = UpdateDeviceJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        UpdateDeviceJob UpdateDeviceJob::withData(JsonWrap j) const &
        {
          auto ret = UpdateDeviceJob(*this);
          ret.attachData(j);
          return ret;
        }

        UpdateDeviceJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool UpdateDeviceResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query DeleteDeviceJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body DeleteDeviceJob::buildBody(std::string deviceId, std::optional<AuthenticationData> auth)
      {
      // ignore unused param
      (void)(deviceId);(void)(auth);
      
        json _data
        ;
        
          
            addToJsonIfNeeded(_data, "auth"s, auth);
        return BaseJob::JsonBody(_data);
        

      };

      

DeleteDeviceJob::DeleteDeviceJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string deviceId, std::optional<AuthenticationData> auth
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/devices/" + deviceId,
          DELETE,
          std::string("DeleteDevice"),
          _accessToken,
          ReturnType::Json,
            buildBody(deviceId, auth)
              , buildQuery()
                , {}

)
        {
        }

        DeleteDeviceJob DeleteDeviceJob::withData(JsonWrap j) &&
        {
          auto ret = DeleteDeviceJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        DeleteDeviceJob DeleteDeviceJob::withData(JsonWrap j) const &
        {
          auto ret = DeleteDeviceJob(*this);
          ret.attachData(j);
          return ret;
        }

        DeleteDeviceJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool DeleteDeviceResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query DeleteDevicesJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body DeleteDevicesJob::buildBody(immer::array<std::string> devices, std::optional<AuthenticationData> auth)
      {
      // ignore unused param
      (void)(devices);(void)(auth);
      
        json _data
        ;
        
            _data["devices"s] = devices;
          
          
            addToJsonIfNeeded(_data, "auth"s, auth);
        return BaseJob::JsonBody(_data);
        

      };

      

DeleteDevicesJob::DeleteDevicesJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        immer::array<std::string> devices, std::optional<AuthenticationData> auth
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/delete_devices",
          POST,
          std::string("DeleteDevices"),
          _accessToken,
          ReturnType::Json,
            buildBody(devices, auth)
              , buildQuery()
                , {}

)
        {
        }

        DeleteDevicesJob DeleteDevicesJob::withData(JsonWrap j) &&
        {
          auto ret = DeleteDevicesJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        DeleteDevicesJob DeleteDevicesJob::withData(JsonWrap j) const &
        {
          auto ret = DeleteDevicesJob(*this);
          ret.attachData(j);
          return ret;
        }

        DeleteDevicesJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool DeleteDevicesResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
