/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "file-desc.hpp"

namespace Kazv::Api {

/*! \brief Upload some content to the content repository.
 *
 */
class UploadContentJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The `MXC URI`_ to the uploaded content.
std::string contentUri() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Upload some content to the content repository.
 *
    * \param content
    *   The content to be uploaded.
    * 
    * \param filename
    *   The name of the file being uploaded
    * 
    * \param contentType
    *   The content type of the file being uploaded
    */
    explicit UploadContentJob(std::string serverUrl
    , std::string _accessToken
      ,
        FileDesc content , std::optional<std::string> filename  = std::nullopt, std::optional<std::string> contentType  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    std::optional<std::string> filename);

      static BaseJob::Body buildBody(FileDesc content, std::optional<std::string> filename, std::optional<std::string> contentType);

          static std::map<std::string, std::string> buildHeader(std::optional<std::string> contentType);

        

      UploadContentJob withData(JsonWrap j) &&;
      UploadContentJob withData(JsonWrap j) const &;
      };
      using UploadContentResponse = UploadContentJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Download content from the content repository.
 *
 */
class GetContentJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties

/// The content type of the file that was previously uploaded.
std::optional<std::string> contentType() const
    {
        auto it = header->find("Content-Type");
        if (it != header->end()) {
            return it->second;
        } else {
            return std::nullopt;
        }
    }

/// The name of the file that was previously uploaded, if set.
std::optional<std::string> contentDisposition() const
    {
        auto it = header->find("Content-Disposition");
        if (it != header->end()) {
            return it->second;
        } else {
            return std::nullopt;
        }
    }

/// The content that was previously uploaded.
    inline Body data() const
    {
    return body;
    }
    
        

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Download content from the content repository.
 *
    * \param serverName
    *   The server name from the ``mxc://`` URI (the authoritory component)
    * 
    * \param mediaId
    *   The media ID from the ``mxc://`` URI (the path component)
    * 
    * \param allowRemote
    *   Indicates to the server that it should not attempt to fetch the media if it is deemed
    *   remote. This is to prevent routing loops where the server contacts itself. Defaults to
    *   true if not provided.
    */
    explicit GetContentJob(std::string serverUrl
    
      ,
        std::string serverName , std::string mediaId , bool allowRemote  = true
        , std::optional<FileDesc> downloadTo = std::nullopt);


    static BaseJob::Query buildQuery(
    bool allowRemote);

      static BaseJob::Body buildBody(std::string serverName, std::string mediaId, bool allowRemote);

        

          static const immer::array<std::string> expectedContentTypes;

      GetContentJob withData(JsonWrap j) &&;
      GetContentJob withData(JsonWrap j) const &;
      };
      using GetContentResponse = GetContentJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Download content from the content repository overriding the file name
 *
 * This will download content from the content repository (same as
 * the previous endpoint) but replace the target file name with the one
 * provided by the caller.
 */
class GetContentOverrideNameJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties

/// The content type of the file that was previously uploaded.
std::optional<std::string> contentType() const
    {
        auto it = header->find("Content-Type");
        if (it != header->end()) {
            return it->second;
        } else {
            return std::nullopt;
        }
    }

/// The ``fileName`` requested or the name of the file that was previously
/// uploaded, if set.
std::optional<std::string> contentDisposition() const
    {
        auto it = header->find("Content-Disposition");
        if (it != header->end()) {
            return it->second;
        } else {
            return std::nullopt;
        }
    }

/// The content that was previously uploaded.
    inline Body data() const
    {
    return body;
    }
    
        

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Download content from the content repository overriding the file name
 *
    * \param serverName
    *   The server name from the ``mxc://`` URI (the authoritory component)
    * 
    * \param mediaId
    *   The media ID from the ``mxc://`` URI (the path component)
    * 
    * \param fileName
    *   A filename to give in the ``Content-Disposition`` header.
    * 
    * \param allowRemote
    *   Indicates to the server that it should not attempt to fetch the media if it is deemed
    *   remote. This is to prevent routing loops where the server contacts itself. Defaults to
    *   true if not provided.
    */
    explicit GetContentOverrideNameJob(std::string serverUrl
    
      ,
        std::string serverName , std::string mediaId , std::string fileName , bool allowRemote  = true
        , std::optional<FileDesc> downloadTo = std::nullopt);


    static BaseJob::Query buildQuery(
    bool allowRemote);

      static BaseJob::Body buildBody(std::string serverName, std::string mediaId, std::string fileName, bool allowRemote);

        

          static const immer::array<std::string> expectedContentTypes;

      GetContentOverrideNameJob withData(JsonWrap j) &&;
      GetContentOverrideNameJob withData(JsonWrap j) const &;
      };
      using GetContentOverrideNameResponse = GetContentOverrideNameJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Download a thumbnail of content from the content repository
 *
 * Download a thumbnail of content from the content repository.
 * See the `thumbnailing <#thumbnails>`_ section for more information.
 */
class GetContentThumbnailJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties

/// The content type of the thumbnail.
std::optional<std::string> contentType() const
    {
        auto it = header->find("Content-Type");
        if (it != header->end()) {
            return it->second;
        } else {
            return std::nullopt;
        }
    }

/// A thumbnail of the requested content.
    inline Body data() const
    {
    return body;
    }
    
        

};
          static constexpr auto needsAuth() {
          return 
            false;
              }


// Construction/destruction

  /*! \brief Download a thumbnail of content from the content repository
 *
    * \param serverName
    *   The server name from the ``mxc://`` URI (the authoritory component)
    * 
    * \param mediaId
    *   The media ID from the ``mxc://`` URI (the path component)
    * 
    * \param width
    *   The *desired* width of the thumbnail. The actual thumbnail may be
    *   larger than the size specified.
    * 
    * \param height
    *   The *desired* height of the thumbnail. The actual thumbnail may be
    *   larger than the size specified.
    * 
    * \param method
    *   The desired resizing method. See the `thumbnailing <#thumbnails>`_
    *   section for more information.
    * 
    * \param allowRemote
    *   Indicates to the server that it should not attempt to fetch
    *   the media if it is deemed remote. This is to prevent routing loops
    *   where the server contacts itself. Defaults to true if not provided.
    */
    explicit GetContentThumbnailJob(std::string serverUrl
    
      ,
        std::string serverName , std::string mediaId , int width , int height , std::optional<std::string> method  = std::nullopt, bool allowRemote  = true
        , std::optional<FileDesc> downloadTo = std::nullopt);


    static BaseJob::Query buildQuery(
    int width, int height, std::optional<std::string> method, bool allowRemote);

      static BaseJob::Body buildBody(std::string serverName, std::string mediaId, int width, int height, std::optional<std::string> method, bool allowRemote);

        

          static const immer::array<std::string> expectedContentTypes;

      GetContentThumbnailJob withData(JsonWrap j) &&;
      GetContentThumbnailJob withData(JsonWrap j) const &;
      };
      using GetContentThumbnailResponse = GetContentThumbnailJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get information about a URL for a client
 *
 * Get information about a URL for the client. Typically this is called when a
 * client sees a URL in a message and wants to render a preview for the user.
 * 
 * .. Note::
 *   Clients should consider avoiding this endpoint for URLs posted in encrypted
 *   rooms. Encrypted rooms often contain more sensitive information the users
 *   do not want to share with the node, and this can mean that the URLs
 *   being shared should also not be shared with the node.
 */
class GetUrlPreviewJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The byte-size of the image. Omitted if there is no image attached.
std::optional<std::int_fast64_t> imageSize() const;

    
/// An `MXC URI`_ to the image. Omitted if there is no image.
std::optional<std::string> ogImage() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get information about a URL for a client
 *
    * \param url
    *   The URL to get a preview of.
    * 
    * \param ts
    *   The preferred point in time to return a preview for. The server may
    *   return a newer version if it does not have the requested version
    *   available.
    */
    explicit GetUrlPreviewJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string url , std::optional<std::int_fast64_t> ts  = std::nullopt
        );


    static BaseJob::Query buildQuery(
    std::string url, std::optional<std::int_fast64_t> ts);

      static BaseJob::Body buildBody(std::string url, std::optional<std::int_fast64_t> ts);

        

        

      GetUrlPreviewJob withData(JsonWrap j) &&;
      GetUrlPreviewJob withData(JsonWrap j) const &;
      };
      using GetUrlPreviewResponse = GetUrlPreviewJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get the configuration for the content repository.
 *
 * This endpoint allows clients to retrieve the configuration of the content
 * repository, such as upload limitations.
 * Clients SHOULD use this as a guide when using content repository endpoints.
 * All values are intentionally left optional. Clients SHOULD follow
 * the advice given in the field description when the field is not available.
 * 
 * **NOTE:** Both clients and server administrators should be aware that proxies
 * between the client and the server may affect the apparent behaviour of content
 * repository APIs, for example, proxies may enforce a lower upload size limit
 * than is advertised by the server on this endpoint.
 */
class GetConfigJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The maximum size an upload can be in bytes.
/// Clients SHOULD use this as a guide when uploading content.
/// If not listed or null, the size limit should be treated as unknown.
std::optional<std::int_fast64_t> uploadSize() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

    /// Get the configuration for the content repository.
    explicit GetConfigJob(std::string serverUrl
    , std::string _accessToken
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      GetConfigJob withData(JsonWrap j) &&;
      GetConfigJob withData(JsonWrap j) const &;
      };
      using GetConfigResponse = GetConfigJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
