/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "content-repo.hpp"

namespace Kazv::Api
{

  std::map<std::string, std::string> UploadContentJob::buildHeader(std::optional<std::string> contentType)
    {
    std::map<std::string, std::string> h{};

        if (contentType.has_value()) {
          h.insert_or_assign( "Content-Type"s, contentType.value() );
        }
      
    return h;
    }
BaseJob::Query UploadContentJob::buildQuery(
std::optional<std::string> filename)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "filename"s, filename);
return _q;
}

    BaseJob::Body UploadContentJob::buildBody(FileDesc content, std::optional<std::string> filename, std::optional<std::string> contentType)
      {
      // ignore unused param
      (void)(content);(void)(filename);(void)(contentType);
        return FileDesc(content)
          ;
      
          

      };

      

UploadContentJob::UploadContentJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        FileDesc content, std::optional<std::string> filename, std::optional<std::string> contentType
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/media/r0") + "/upload",
          POST,
          std::string("UploadContent"),
          _accessToken,
          ReturnType::Json,
            buildBody(content, filename, contentType)
              , buildQuery(filename)
                , buildHeader(
                  contentType
                )

)
        {
        }

        UploadContentJob UploadContentJob::withData(JsonWrap j) &&
        {
          auto ret = UploadContentJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        UploadContentJob UploadContentJob::withData(JsonWrap j) const &
        {
          auto ret = UploadContentJob(*this);
          ret.attachData(j);
          return ret;
        }

        UploadContentJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool UploadContentResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("content_uri"s)
          ;
          }


    
    std::string UploadContentResponse::contentUri() const
    {
    if (jsonBody().get()
    .contains("content_uri"s)) {
    return
    jsonBody().get()["content_uri"s]
    .template get<std::string>();}
    else { return std::string(  );}
    }


  
BaseJob::Query GetContentJob::buildQuery(
bool allowRemote)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "allow_remote"s, allowRemote);
return _q;
}

    BaseJob::Body GetContentJob::buildBody(std::string serverName, std::string mediaId, bool allowRemote)
      {
      // ignore unused param
      (void)(serverName);(void)(mediaId);(void)(allowRemote);
      
      
              return BaseJob::EmptyBody{};

      };

        const immer::array<std::string> GetContentJob::expectedContentTypes{ "*/*" };

GetContentJob::GetContentJob(
        std::string serverUrl
        
            ,
        std::string serverName, std::string mediaId, bool allowRemote
        , std::optional<FileDesc> downloadTo)
      : BaseJob(std::move(serverUrl),
          std::string("/_api/media/r0") + "/download/" + serverName + "/" + mediaId,
          GET,
          std::string("GetContent"),
           {} ,
          ReturnType::File,
            buildBody(serverName, mediaId, allowRemote)
              , buildQuery(allowRemote)
                , {}
, downloadTo
)
        {
        }

        GetContentJob GetContentJob::withData(JsonWrap j) &&
        {
          auto ret = GetContentJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetContentJob GetContentJob::withData(JsonWrap j) const &
        {
          auto ret = GetContentJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetContentJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetContentResponse::success() const
          {
            return Response::success()
              && header.get().find("Content-Type") != header.get().end()
              && contentTypeMatches(expectedContentTypes, header.get().at("Content-Type"))
            
          ;
          }



  
BaseJob::Query GetContentOverrideNameJob::buildQuery(
bool allowRemote)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "allow_remote"s, allowRemote);
return _q;
}

    BaseJob::Body GetContentOverrideNameJob::buildBody(std::string serverName, std::string mediaId, std::string fileName, bool allowRemote)
      {
      // ignore unused param
      (void)(serverName);(void)(mediaId);(void)(fileName);(void)(allowRemote);
      
      
              return BaseJob::EmptyBody{};

      };

        const immer::array<std::string> GetContentOverrideNameJob::expectedContentTypes{ "*/*" };

GetContentOverrideNameJob::GetContentOverrideNameJob(
        std::string serverUrl
        
            ,
        std::string serverName, std::string mediaId, std::string fileName, bool allowRemote
        , std::optional<FileDesc> downloadTo)
      : BaseJob(std::move(serverUrl),
          std::string("/_api/media/r0") + "/download/" + serverName + "/" + mediaId + "/" + fileName,
          GET,
          std::string("GetContentOverrideName"),
           {} ,
          ReturnType::File,
            buildBody(serverName, mediaId, fileName, allowRemote)
              , buildQuery(allowRemote)
                , {}
, downloadTo
)
        {
        }

        GetContentOverrideNameJob GetContentOverrideNameJob::withData(JsonWrap j) &&
        {
          auto ret = GetContentOverrideNameJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetContentOverrideNameJob GetContentOverrideNameJob::withData(JsonWrap j) const &
        {
          auto ret = GetContentOverrideNameJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetContentOverrideNameJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetContentOverrideNameResponse::success() const
          {
            return Response::success()
              && header.get().find("Content-Type") != header.get().end()
              && contentTypeMatches(expectedContentTypes, header.get().at("Content-Type"))
            
          ;
          }



  
BaseJob::Query GetContentThumbnailJob::buildQuery(
int width, int height, std::optional<std::string> method, bool allowRemote)
{
BaseJob::Query _q;
    addToQuery(_q, "width"s, width);
  
    addToQuery(_q, "height"s, height);
  
  
    addToQueryIfNeeded(_q, "method"s, method);
  
    addToQueryIfNeeded(_q, "allow_remote"s, allowRemote);
return _q;
}

    BaseJob::Body GetContentThumbnailJob::buildBody(std::string serverName, std::string mediaId, int width, int height, std::optional<std::string> method, bool allowRemote)
      {
      // ignore unused param
      (void)(serverName);(void)(mediaId);(void)(width);(void)(height);(void)(method);(void)(allowRemote);
      
      
              return BaseJob::EmptyBody{};

      };

        const immer::array<std::string> GetContentThumbnailJob::expectedContentTypes{ "image/jpeg", "image/png" };

GetContentThumbnailJob::GetContentThumbnailJob(
        std::string serverUrl
        
            ,
        std::string serverName, std::string mediaId, int width, int height, std::optional<std::string> method, bool allowRemote
        , std::optional<FileDesc> downloadTo)
      : BaseJob(std::move(serverUrl),
          std::string("/_api/media/r0") + "/thumbnail/" + serverName + "/" + mediaId,
          GET,
          std::string("GetContentThumbnail"),
           {} ,
          ReturnType::File,
            buildBody(serverName, mediaId, width, height, method, allowRemote)
              , buildQuery(width, height, method, allowRemote)
                , {}
, downloadTo
)
        {
        }

        GetContentThumbnailJob GetContentThumbnailJob::withData(JsonWrap j) &&
        {
          auto ret = GetContentThumbnailJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetContentThumbnailJob GetContentThumbnailJob::withData(JsonWrap j) const &
        {
          auto ret = GetContentThumbnailJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetContentThumbnailJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetContentThumbnailResponse::success() const
          {
            return Response::success()
              && header.get().find("Content-Type") != header.get().end()
              && contentTypeMatches(expectedContentTypes, header.get().at("Content-Type"))
            
          ;
          }



  
BaseJob::Query GetUrlPreviewJob::buildQuery(
std::string url, std::optional<std::int_fast64_t> ts)
{
BaseJob::Query _q;
    addToQuery(_q, "url"s, url);
  
  
    addToQueryIfNeeded(_q, "ts"s, ts);
return _q;
}

    BaseJob::Body GetUrlPreviewJob::buildBody(std::string url, std::optional<std::int_fast64_t> ts)
      {
      // ignore unused param
      (void)(url);(void)(ts);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetUrlPreviewJob::GetUrlPreviewJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string url, std::optional<std::int_fast64_t> ts
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/media/r0") + "/preview_url",
          GET,
          std::string("GetUrlPreview"),
          _accessToken,
          ReturnType::Json,
            buildBody(url, ts)
              , buildQuery(url, ts)
                , {}

)
        {
        }

        GetUrlPreviewJob GetUrlPreviewJob::withData(JsonWrap j) &&
        {
          auto ret = GetUrlPreviewJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetUrlPreviewJob GetUrlPreviewJob::withData(JsonWrap j) const &
        {
          auto ret = GetUrlPreviewJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetUrlPreviewJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetUrlPreviewResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::int_fast64_t> GetUrlPreviewResponse::imageSize() const
    {
    if (jsonBody().get()
    .contains("image:size"s)) {
    return
    jsonBody().get()["image:size"s]
    .template get<std::int_fast64_t>();}
    else { return std::optional<std::int_fast64_t>(  );}
    }

    
    std::optional<std::string> GetUrlPreviewResponse::ogImage() const
    {
    if (jsonBody().get()
    .contains("og:image"s)) {
    return
    jsonBody().get()["og:image"s]
    .template get<std::string>();}
    else { return std::optional<std::string>(  );}
    }


  
BaseJob::Query GetConfigJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetConfigJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetConfigJob::GetConfigJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/media/r0") + "/config",
          GET,
          std::string("GetConfig"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetConfigJob GetConfigJob::withData(JsonWrap j) &&
        {
          auto ret = GetConfigJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetConfigJob GetConfigJob::withData(JsonWrap j) const &
        {
          auto ret = GetConfigJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetConfigJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetConfigResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


    
    std::optional<std::int_fast64_t> GetConfigResponse::uploadSize() const
    {
    if (jsonBody().get()
    .contains("m.upload.size"s)) {
    return
    jsonBody().get()["m.upload.size"s]
    .template get<std::int_fast64_t>();}
    else { return std::optional<std::int_fast64_t>(  );}
    }

}
