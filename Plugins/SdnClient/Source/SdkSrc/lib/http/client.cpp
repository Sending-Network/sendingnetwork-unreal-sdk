#include "sdnclient/http/client.hpp"
#include "sdn/log.hpp"
#include "sdnclient/http/client_impl.hpp"

#include <mutex>
#include <thread>

#include <nlohmann/json.hpp>

#include <coeurl/client.hpp>
#include <coeurl/request.hpp>
#include <utility>

#include "sdnclient/utils.hpp"

#include "sdn/log.hpp"
#include "sdn/requests.hpp"
#include "sdn/responses.hpp"

using namespace sdn::http;

namespace sdn::http {
struct ClientPrivate
{
    coeurl::Client client;
};

void
UIAHandler::next(const user_interactive::Auth &auth) const
{
    next_(*this, auth);
}
}

Client::Client(const std::string &server, uint16_t port)
  : p{new ClientPrivate}
{
    set_server(server);
    set_port(port);

    p->client.set_verify_peer(true);
    p->client.connection_timeout(60);
}

// call destuctor of work queue and ios first!
Client::~Client() { p.reset(); }

void
Client::shutdown()
{
    p->client.shutdown();
}

void
Client::alt_svc_cache_path(const std::string &path)
{
    p->client.alt_svc_cache_path(path);
}

coeurl::Headers
sdn::http::Client::prepare_headers(bool requires_auth)
{
    coeurl::Headers headers;
    headers["User-Agent"] = "sdnclient v0.9.2";

    if (requires_auth && !access_token_.empty())
        headers["Authorization"] = "Bearer " + access_token();

    return headers;
}

std::string
sdn::http::Client::endpoint_to_url(const std::string &endpoint, const char *endpoint_namespace)
{
    return protocol_ + "://" + server_ + ":" + std::to_string(port_) + endpoint_namespace +
           endpoint;
}

void
sdn::http::Client::post(const std::string &endpoint,
                        const std::string &req,
                        sdn::http::TypeErasedCallback cb,
                        bool requires_auth,
                        const std::string &content_type)
{
    p->client.post(
      endpoint_to_url(endpoint),
      req,
      content_type,
      [cb = std::move(cb)](const coeurl::Request &r) {
          cb(r.response_headers(), r.response(), r.error_code(), r.response_code());
      },
      prepare_headers(requires_auth));
}

void
sdn::http::Client::delete_(const std::string &endpoint, ErrCallback cb, bool requires_auth)
{
    p->client.delete_(
      endpoint_to_url(endpoint),
      [cb = std::move(cb)](const coeurl::Request &r) {
          sdn::http::ClientError client_error;
          if (r.error_code()) {
              client_error.error_code = r.error_code();
              return cb(client_error);
          }

          client_error.status_code = r.response_code();

          // We only count 2xx status codes as success.
          if (client_error.status_code < 200 || client_error.status_code >= 300) {
              // The homeserver should return an error struct.
              try {
                  nlohmann::json json_error = nlohmann::json::parse(r.response());
                  client_error.sdn_error = json_error.get<sdn::errors::Error>();
              } catch (const nlohmann::json::exception &e) {
                  client_error.parse_error =
                    std::string(e.what()) + ": " + std::string(r.response());
              }
              return cb(client_error);
          }
          return cb({});
      },
      prepare_headers(requires_auth));
}

void
sdn::http::Client::put(const std::string &endpoint,
                       const std::string &req,
                       sdn::http::TypeErasedCallback cb,
                       bool requires_auth)
{
    p->client.put(
      endpoint_to_url(endpoint),
      req,
      "application/json",
      [cb = std::move(cb)](const coeurl::Request &r) {
          cb(r.response_headers(), r.response(), r.error_code(), r.response_code());
      },
      prepare_headers(requires_auth));
}

void
sdn::http::Client::get(const std::string &endpoint,
                       sdn::http::TypeErasedCallback cb,
                       bool requires_auth,
                       const std::string &endpoint_namespace,
                       int num_redirects)
{
    p->client.get(
      endpoint_to_url(endpoint, endpoint_namespace.c_str()),
      [cb = std::move(cb)](const coeurl::Request &r) {
          cb(r.response_headers(), r.response(), r.error_code(), r.response_code());
      },
      prepare_headers(requires_auth),
      num_redirects);
}

void
Client::verify_certificates(bool enabled)
{
    p->client.set_verify_peer(enabled);
}

void
Client::set_server(const std::string &server)
{
    std::string_view server_name = server;
    std::uint16_t port           = 443;
    this->protocol_              = "https";
    // Remove https prefix, if it exists
    if (server_name.substr(0, 8) == "https://") {
        server_name.remove_prefix(8);
        port = 443;
    }
    if (server_name.substr(0, 7) == "http://") {
        server_name.remove_prefix(7);
        port            = 80;
        this->protocol_ = "http";
    }
    if (server_name.size() > 0 && server_name.back() == '/')
        server_name.remove_suffix(1);

    if (std::count(server_name.begin(), server_name.end(), ':') == 1) {
        auto colon_offset = server_name.find(':');
        server_           = std::string(server_name.substr(0, colon_offset));

        auto tmp = std::string(server_name.substr(colon_offset + 1));
        if (sdn::client::utils::is_number(tmp)) {
            port_ = static_cast<std::uint16_t>(std::stoul(tmp));
            return;
        }
    }

    server_ = std::string(server_name);
    port_   = port;
}

void
Client::close(bool force)
{
    p->client.close(force);
}

//
// Client API endpoints
//

void
Client::login(const std::string &user,
              const std::string &password,
              const std::string &device_name,
              Callback<sdn::responses::Login> callback)
{
    sdn::requests::Login req;
    req.identifier                  = sdn::requests::login_identifier::User{user};
    req.password                    = password;
    req.initial_device_display_name = device_name;

    login(req, std::move(callback));
}

void
Client::login(const std::string &user,
              const std::string &password,
              Callback<sdn::responses::Login> callback)
{
    sdn::requests::Login req;
    req.identifier = sdn::requests::login_identifier::User{user};
    req.password   = password;

    login(req, std::move(callback));
}

void
Client::login(const sdn::requests::Login &req, Callback<sdn::responses::Login> callback)
{
    post<sdn::requests::Login, sdn::responses::Login>(
      "/client/v3/did/login",
      req,
      [_this    = shared_from_this(),
       callback = std::move(callback)](const sdn::responses::Login &resp, RequestErr err) {
          if (!err && resp.access_token.size()) {
              _this->user_id_      = resp.user_id;
              _this->device_id_    = resp.device_id;
              _this->access_token_ = resp.access_token;
          }
          callback(resp, err);
      },
      false);
}

void
Client::pre_login(const std::string address, Callback<sdn::responses::PreLogin> cb)
{

    get<sdn::responses::QueryDID>(
      "/client/v3/address/" + address,
      [_this = shared_from_this(), cb = std::move(cb), address = std::move(address)](const sdn::responses::QueryDID &res, HeaderFields, RequestErr err) {
          sdn::requests::PreLogin req;
        if (res.data.size() > 0) {
            req.did = res.data.at(0);
        } else {
            req.address = address;
        }
        _this->post<sdn::requests::PreLogin, sdn::responses::PreLogin>("/client/v3/did/pre_login1", req, cb, false);
      },
      false);
}

void
Client::get_login(Callback<sdn::responses::LoginFlows> cb)
{
    get<sdn::responses::LoginFlows>(
      "/client/v3/login",
      [cb = std::move(cb)](const sdn::responses::LoginFlows &res, HeaderFields, RequestErr err) {
          cb(res, err);
      },
      false);
}

std::string
Client::login_sso_redirect(std::string redirectUrl, const std::string &idp)
{
    const std::string idp_suffix = idp.empty() ? idp : ("/" + sdn::client::utils::url_encode(idp));
    return protocol_ + "://" + server() + ":" + std::to_string(port()) +
           "/_api/client/v3/login/sso/redirect" + idp_suffix + "?" +
           sdn::client::utils::query_params({{"redirectUrl", redirectUrl}});
}

void
Client::well_known(Callback<sdn::responses::WellKnown> callback)
{
    get<sdn::responses::WellKnown>(
      "/_api/client",
      [cb = std::move(callback)](
        const sdn::responses::WellKnown &res, HeaderFields, RequestErr err) { cb(res, err); },
      false,
      "/.well-known",
      30);
}

void
Client::logout(Callback<sdn::responses::Logout> callback)
{
    sdn::requests::Logout req;

    post<sdn::requests::Logout, sdn::responses::Logout>(
      "/client/v3/logout",
      req,
      [_this    = shared_from_this(),
       callback = std::move(callback)](const sdn::responses::Logout &res, RequestErr err) {
          if (!err) {
              // Clear the now invalid access token when logout is successful
              _this->clear();
          }
          // Pass up response and error to supplied callback
          callback(res, err);
      });
}

void
Client::notifications(uint64_t limit,
                      const std::string &from,
                      const std::string &only,
                      Callback<sdn::responses::Notifications> cb)
{
    std::map<std::string, std::string> params;
    params.emplace("limit", std::to_string(limit));

    if (!from.empty()) {
        params.emplace("from", from);
    }

    if (!only.empty()) {
        params.emplace("only", only);
    }

    get<sdn::responses::Notifications>(
      "/client/v3/notifications?" + sdn::client::utils::query_params(params),
      [cb = std::move(cb)](const sdn::responses::Notifications &res, HeaderFields, RequestErr err) {
          cb(res, err);
      });
}

void
Client::get_pushrules(Callback<sdn::pushrules::GlobalRuleset> cb)
{
    get<sdn::pushrules::GlobalRuleset>(
      "/client/v3/pushrules/",
      [cb = std::move(cb)](const sdn::pushrules::GlobalRuleset &res, HeaderFields, RequestErr err) {
          cb(res, err);
      });
}

void
Client::get_pushrules(const std::string &scope,
                      const std::string &kind,
                      const std::string &ruleId,
                      Callback<sdn::pushrules::PushRule> cb)
{
    get<sdn::pushrules::PushRule>(
      "/client/v3/pushrules/" + sdn::client::utils::url_encode(scope) + "/" +
        sdn::client::utils::url_encode(kind) + "/" + sdn::client::utils::url_encode(ruleId),
      [cb = std::move(cb)](const sdn::pushrules::PushRule &res, HeaderFields, RequestErr err) {
          cb(res, err);
      });
}

void
Client::delete_pushrules(const std::string &scope,
                         const std::string &kind,
                         const std::string &ruleId,
                         ErrCallback cb)
{
    delete_("/client/v3/pushrules/" + sdn::client::utils::url_encode(scope) + "/" +
              sdn::client::utils::url_encode(kind) + "/" + sdn::client::utils::url_encode(ruleId),
            std::move(cb));
}

void
Client::put_pushrules(const std::string &scope,
                      const std::string &kind,
                      const std::string &ruleId,
                      const sdn::pushrules::PushRule &rule,
                      ErrCallback cb,
                      const std::string &before,
                      const std::string &after)
{
    std::map<std::string, std::string> params;

    if (!before.empty())
        params.emplace("before", before);

    if (!after.empty())
        params.emplace("after", after);

    std::string path = "/client/v3/pushrules/" + sdn::client::utils::url_encode(scope) + "/" +
                       sdn::client::utils::url_encode(kind) + "/" +
                       sdn::client::utils::url_encode(ruleId);
    if (!params.empty())
        path += "?" + sdn::client::utils::query_params(params);
    put<sdn::pushrules::PushRule>(path, rule, std::move(cb));
}

void
Client::get_pushrules_enabled(const std::string &scope,
                              const std::string &kind,
                              const std::string &ruleId,
                              Callback<sdn::pushrules::Enabled> cb)
{
    get<sdn::pushrules::Enabled>("/client/v3/pushrules/" + sdn::client::utils::url_encode(scope) +
                                   "/" + sdn::client::utils::url_encode(kind) + "/" +
                                   sdn::client::utils::url_encode(ruleId) + "/enabled",
                                 [cb = std::move(cb)](const sdn::pushrules::Enabled &res,
                                                      HeaderFields,
                                                      RequestErr err) { cb(res, err); });
}

void
Client::put_pushrules_enabled(const std::string &scope,
                              const std::string &kind,
                              const std::string &ruleId,
                              bool enabled,
                              ErrCallback cb)
{
    put<sdn::pushrules::Enabled>("/client/v3/pushrules/" + sdn::client::utils::url_encode(scope) +
                                   "/" + sdn::client::utils::url_encode(kind) + "/" +
                                   sdn::client::utils::url_encode(ruleId) + "/enabled",
                                 {enabled},
                                 std::move(cb));
}

void
Client::get_pushrules_actions(const std::string &scope,
                              const std::string &kind,
                              const std::string &ruleId,
                              Callback<sdn::pushrules::actions::Actions> cb)
{
    get<sdn::pushrules::actions::Actions>(
      "/client/v3/pushrules/" + sdn::client::utils::url_encode(scope) + "/" +
        sdn::client::utils::url_encode(kind) + "/" + sdn::client::utils::url_encode(ruleId) +
        "/actions",
      [cb = std::move(cb)](const sdn::pushrules::actions::Actions &res,
                           HeaderFields,
                           RequestErr err) { cb(res, err); });
}

void
Client::put_pushrules_actions(const std::string &scope,
                              const std::string &kind,
                              const std::string &ruleId,
                              const sdn::pushrules::actions::Actions &actions,
                              ErrCallback cb)
{
    put<sdn::pushrules::actions::Actions>("/client/v3/pushrules/" +
                                            sdn::client::utils::url_encode(scope) + "/" +
                                            sdn::client::utils::url_encode(kind) + "/" +
                                            sdn::client::utils::url_encode(ruleId) + "/actions",
                                          actions,
                                          std::move(cb));
}

void
Client::set_avatar_url(const std::string &avatar_url, ErrCallback callback)
{
    sdn::requests::AvatarUrl req;
    req.avatar_url = avatar_url;

    put<sdn::requests::AvatarUrl>(
      "/client/v3/profile/" + sdn::client::utils::url_encode(user_id_.to_string()) + "/avatar_url",
      req,
      std::move(callback));
}

void
Client::set_displayname(const std::string &displayname, ErrCallback callback)
{
    sdn::requests::DisplayName req;
    req.displayname = displayname;

    put<sdn::requests::DisplayName>(
      "/client/v3/profile/" + sdn::client::utils::url_encode(user_id_.to_string()) + "/displayname",
      req,
      std::move(callback));
}

void
Client::get_profile(const std::string &user_id, Callback<sdn::responses::Profile> callback)
{
    get<sdn::responses::Profile>(
      "/client/v3/profile/" + sdn::client::utils::url_encode(user_id),
      [callback = std::move(callback)](
        const sdn::responses::Profile &res, HeaderFields, RequestErr err) { callback(res, err); });
}

void
Client::get_avatar_url(const std::string &user_id, Callback<sdn::responses::AvatarUrl> callback)
{
    get<sdn::responses::AvatarUrl>(
      "/client/v3/profile/" + sdn::client::utils::url_encode(user_id) + "/avatar_url",
      [callback = std::move(callback)](const sdn::responses::AvatarUrl &res,
                                       HeaderFields,
                                       RequestErr err) { callback(res, err); });
}

void
Client::get_tags(const std::string &room_id, Callback<sdn::events::account_data::Tags> cb)
{
    get<sdn::events::account_data::Tags>(
      "/client/v3/user/" + sdn::client::utils::url_encode(user_id_.to_string()) + "/rooms/" +
        sdn::client::utils::url_encode(room_id) + "/tags",
      [cb = std::move(cb)](const sdn::events::account_data::Tags &res,
                           HeaderFields,
                           RequestErr err) { cb(res, err); });
}
void
Client::put_tag(const std::string &room_id,
                const std::string &tag_name,
                const sdn::events::account_data::Tag &tag,
                ErrCallback cb)
{
    put<sdn::events::account_data::Tag>("/client/v3/user/" +
                                          sdn::client::utils::url_encode(user_id_.to_string()) +
                                          "/rooms/" + sdn::client::utils::url_encode(room_id) +
                                          "/tags/" + sdn::client::utils::url_encode(tag_name),
                                        tag,
                                        std::move(cb));
}
void
Client::delete_tag(const std::string &room_id, const std::string &tag_name, ErrCallback cb)
{
    delete_("/client/v3/user/" + sdn::client::utils::url_encode(user_id_.to_string()) + "/rooms/" +
              sdn::client::utils::url_encode(room_id) + "/tags/" +
              sdn::client::utils::url_encode(tag_name),
            std::move(cb));
}

void
Client::create_room(const sdn::requests::CreateRoom &room_options,
                    Callback<sdn::responses::CreateRoom> callback)
{
    post<sdn::requests::CreateRoom, sdn::responses::CreateRoom>(
      "/client/v3/createRoom", room_options, std::move(callback));
}

void
Client::join_room(const std::string &room, Callback<sdn::responses::RoomId> callback)
{
    join_room(room, {}, std::move(callback));
}

void
Client::join_room(const std::string &room,
                  const std::vector<std::string> &via,
                  Callback<sdn::responses::RoomId> callback,
                  const std::string &reason)
{
    using sdn::client::utils::url_encode;
    std::string query;
    if (!via.empty()) {
        query = "?server_name=" + url_encode(via[0]);
        for (size_t i = 1; i < via.size(); i++) {
            query += "&server_name=" + url_encode(via[i]);
        }
    }
    auto api_path = "/client/v3/join/" + url_encode(room) + query;

    auto body = nlohmann::json::object();
    if (!reason.empty())
        body["reason"] = reason;

    post<std::string, sdn::responses::RoomId>(api_path, body.dump(), std::move(callback));
}

void
Client::knock_room(const std::string &room,
                   const std::vector<std::string> &via,
                   Callback<sdn::responses::RoomId> cb,
                   const std::string &reason)
{
    using sdn::client::utils::url_encode;
    std::string query;
    if (!via.empty()) {
        query = "?server_name=" + url_encode(via[0]);
        for (size_t i = 1; i < via.size(); i++) {
            query += "&server_name=" + url_encode(via[i]);
        }
    }
    auto api_path = "/client/v3/knock/" + url_encode(room) + query;

    auto body = nlohmann::json::object();
    if (!reason.empty())
        body["reason"] = reason;

    post<std::string, sdn::responses::RoomId>(api_path, body.dump(), std::move(cb));
}

void
Client::leave_room(const std::string &room_id,
                   Callback<sdn::responses::Empty> callback,
                   const std::string &reason)
{
    auto api_path = "/client/v3/rooms/" + sdn::client::utils::url_encode(room_id) + "/leave";

    auto body = nlohmann::json::object();
    if (!reason.empty())
        body["reason"] = reason;

    post<std::string, sdn::responses::Empty>(api_path, body.dump(), std::move(callback));
}

void
Client::invite_user(const std::string &room_id,
                    const std::string &user_id,
                    Callback<sdn::responses::RoomInvite> callback,
                    const std::string &reason)
{
    sdn::requests::RoomMembershipChange req;
    req.user_id = user_id;
    req.reason  = reason;

    auto api_path = "/client/v3/rooms/" + sdn::client::utils::url_encode(room_id) + "/invite";

    post<sdn::requests::RoomMembershipChange, sdn::responses::RoomInvite>(
      api_path, req, std::move(callback));
}

void
Client::kick_user(const std::string &room_id,
                  const std::string &user_id,
                  Callback<sdn::responses::Empty> callback,
                  const std::string &reason)
{
    sdn::requests::RoomMembershipChange req;
    req.user_id = user_id;
    req.reason  = reason;

    auto api_path = "/client/v3/rooms/" + sdn::client::utils::url_encode(room_id) + "/kick";

    post<sdn::requests::RoomMembershipChange, sdn::responses::Empty>(
      api_path, req, std::move(callback));
}

void
Client::ban_user(const std::string &room_id,
                 const std::string &user_id,
                 Callback<sdn::responses::Empty> callback,
                 const std::string &reason)
{
    sdn::requests::RoomMembershipChange req;
    req.user_id = user_id;
    req.reason  = reason;

    auto api_path = "/client/v3/rooms/" + sdn::client::utils::url_encode(room_id) + "/ban";

    post<sdn::requests::RoomMembershipChange, sdn::responses::Empty>(
      api_path, req, std::move(callback));
}

void
Client::unban_user(const std::string &room_id,
                   const std::string &user_id,
                   Callback<sdn::responses::Empty> callback,
                   const std::string &reason)
{
    sdn::requests::RoomMembershipChange req;
    req.user_id = user_id;
    req.reason  = reason;

    auto api_path = "/client/v3/rooms/" + sdn::client::utils::url_encode(room_id) + "/unban";

    post<sdn::requests::RoomMembershipChange, sdn::responses::Empty>(
      api_path, req, std::move(callback));
}

void
Client::sync(const SyncOpts &opts, Callback<sdn::responses::Sync> callback)
{
    std::map<std::string, std::string> params;

    if (!opts.filter.empty())
        params.emplace("filter", opts.filter);

    if (!opts.since.empty())
        params.emplace("since", opts.since);

    if (opts.full_state)
        params.emplace("full_state", "true");

    if (opts.set_presence)
        params.emplace("set_presence", sdn::presence::to_string(opts.set_presence.value()));

    params.emplace("timeout", std::to_string(opts.timeout));

    get<sdn::responses::Sync>(
      "/client/v3/sync?" + sdn::client::utils::query_params(params),
      [callback = std::move(callback)](
        const sdn::responses::Sync &res, HeaderFields, RequestErr err) { callback(res, err); });
}

void
Client::versions(Callback<sdn::responses::Versions> callback)
{
    get<sdn::responses::Versions>(
      "/client/versions",
      [callback = std::move(callback)](
        const sdn::responses::Versions &res, HeaderFields, RequestErr err) { callback(res, err); });
}

void
Client::capabilities(Callback<sdn::responses::capabilities::Capabilities> callback)
{
    get<sdn::responses::capabilities::Capabilities>(
      "/client/v3/capabilities",
      [callback = std::move(callback)](const sdn::responses::capabilities::Capabilities &res,
                                       HeaderFields,
                                       RequestErr err) { callback(res, err); });
}

void
Client::upload(const std::string &data,
               const std::string &content_type,
               const std::string &filename,
               Callback<sdn::responses::ContentURI> cb)
{
    std::map<std::string, std::string> params = {{"filename", filename}};

    const auto api_path = "/media/v3/upload?" + client::utils::query_params(params);
    post<std::string, sdn::responses::ContentURI>(
      api_path, data, std::move(cb), true, content_type);
}

std::string
sdn::http::Client::mxc_to_download_url(const std::string &mxc_url)
{
    auto url = sdn::client::utils::parse_mxc_url(mxc_url);
    return endpoint_to_url("/media/v3/download/" + url.server + "/" + url.media_id);
}

void
Client::download(const std::string &mxc_url,
                 std::function<void(const std::string &res,
                                    const std::string &content_type,
                                    const std::string &original_filename,
                                    RequestErr err)> callback)
{
    auto url = sdn::client::utils::parse_mxc_url(mxc_url);
    download(url.server, url.media_id, std::move(callback));
}

void
Client::get_thumbnail(const ThumbOpts &opts, Callback<std::string> callback, bool try_download)
{
    std::map<std::string, std::string> params;
    params.emplace("width", std::to_string(opts.width));
    params.emplace("height", std::to_string(opts.height));
    params.emplace("method", opts.method);

    auto mxc            = sdn::client::utils::parse_mxc_url(opts.mxc_url);
    const auto api_path = "/media/v3/thumbnail/" + mxc.server + "/" + mxc.media_id + "?" +
                          client::utils::query_params(params);
    get<std::string>(
      api_path,
      [callback = std::move(callback),
       try_download,
       mxc   = std::move(mxc),
       _this = shared_from_this()](const std::string &res, HeaderFields, RequestErr err) {
          if (err && try_download) {
              const int status_code = static_cast<int>(err->status_code);

              if (status_code == 404) {
                  _this->download(mxc.server,
                                  mxc.media_id,
                                  [callback](const std::string &res,
                                             const std::string &, // content_type
                                             const std::string &, // original_filename
                                             RequestErr err) { callback(res, err); });
                  return;
              }
          }

          callback(res, err);
      });
}

void
Client::download(const std::string &server,
                 const std::string &media_id,
                 std::function<void(const std::string &res,
                                    const std::string &content_type,
                                    const std::string &original_filename,
                                    RequestErr err)> callback)
{
    const auto api_path = "/media/v3/download/" + server + "/" + media_id;
    get<std::string>(
      api_path,
      [callback =
         std::move(callback)](const std::string &res, HeaderFields fields, RequestErr err) {
          std::string content_type, original_filename;

          if (fields) {
              if (fields->find("Content-Type") != fields->end())
                  content_type = fields->at("Content-Type");
              if (fields->find("Content-Disposition") != fields->end()) {
                  auto value = fields->at("Content-Disposition");

                  if (auto pos = value.find("filename"); pos != std::string::npos) {
                      if (auto start = value.find('"', pos); start != std::string::npos) {
                          auto end          = value.find('"', start + 1);
                          original_filename = value.substr(start + 1, end - start - 2);
                      } else if (start = value.find('='); start != std::string::npos) {
                          original_filename = value.substr(start + 1);
                      }
                  }
              }
          }

          callback(res, content_type, original_filename, err);
      });
}

void
Client::start_typing(const std::string &room_id, uint64_t timeout, ErrCallback callback)
{
    using sdn::client::utils::url_encode;
    const auto api_path =
      "/client/v3/rooms/" + url_encode(room_id) + "/typing/" + url_encode(user_id_.to_string());

    sdn::requests::TypingNotification req;
    req.typing  = true;
    req.timeout = timeout;

    put<sdn::requests::TypingNotification>(api_path, req, std::move(callback));
}

void
Client::stop_typing(const std::string &room_id, ErrCallback callback)
{
    using sdn::client::utils::url_encode;
    const auto api_path =
      "/client/v3/rooms/" + url_encode(room_id) + "/typing/" + url_encode(user_id_.to_string());

    sdn::requests::TypingNotification req;
    req.typing = false;

    put<sdn::requests::TypingNotification>(api_path, req, std::move(callback));
}

void
Client::presence_status(const std::string &user_id,
                        Callback<sdn::events::presence::Presence> callback)
{
    using sdn::client::utils::url_encode;
    const auto api_path = "/client/v3/presence/" + url_encode(user_id) + "/status";
    get<sdn::events::presence::Presence>(
      api_path,
      [callback = std::move(callback)](const sdn::events::presence::Presence &res,
                                       HeaderFields,
                                       RequestErr err) { callback(res, err); });
}
void
Client::put_presence_status(sdn::presence::PresenceState state,
                            std::optional<std::string> status_msg,
                            ErrCallback cb)
{
    using sdn::client::utils::url_encode;
    const auto api_path = "/client/v3/presence/" + url_encode(user_id_.to_string()) + "/status";

    nlohmann::json body;
    body["presence"] = sdn::presence::to_string(state);
    if (status_msg)
        body["status_msg"] = *status_msg;

    put<nlohmann::json>(api_path, body, std::move(cb));
}

void
Client::get_event(const std::string &room_id,
                  const std::string &event_id,
                  Callback<sdn::events::collections::TimelineEvents> callback)
{
    using namespace sdn::client::utils;
    const auto api_path =
      "/client/v3/rooms/" + url_encode(room_id) + "/event/" + url_encode(event_id);

    get<sdn::events::collections::TimelineEvents>(
      api_path,
      [callback = std::move(callback)](const sdn::events::collections::TimelineEvents &res,
                                       HeaderFields,
                                       RequestErr err) { callback(res, err); });
}

void
Client::members(const std::string &room_id,
                Callback<sdn::responses::Members> cb,
                const std::string &at,
                std::optional<sdn::events::state::Membership> membership,
                std::optional<sdn::events::state::Membership> not_membership)
{
    std::map<std::string, std::string> params;

    std::string query;

    if (!at.empty())
        params.emplace("at", at);
    if (membership)
        params.emplace("membership", events::state::membershipToString(*membership));
    if (not_membership)
        params.emplace("not_membership", events::state::membershipToString(*not_membership));

    const auto api_path = "/client/v3/rooms/" + sdn::client::utils::url_encode(room_id) +
                          "/members?" + client::utils::query_params(params);

    get<sdn::responses::Members>(api_path,
                                 [cb = std::move(cb)](const sdn::responses::Members &res,
                                                      HeaderFields,
                                                      RequestErr err) { cb(res, err); });
}

void
Client::messages(const MessagesOpts &opts, Callback<sdn::responses::Messages> callback)
{
    std::map<std::string, std::string> params;

    params.emplace("dir", to_string(opts.dir));

    if (!opts.from.empty())
        params.emplace("from", opts.from);
    if (!opts.to.empty())
        params.emplace("to", opts.to);
    if (opts.limit > 0)
        params.emplace("limit", std::to_string(opts.limit));
    if (!opts.filter.empty())
        params.emplace("filter", opts.filter);

    const auto api_path = "/client/v3/rooms/" + sdn::client::utils::url_encode(opts.room_id) +
                          "/messages?" + client::utils::query_params(params);

    get<sdn::responses::Messages>(
      api_path,
      [callback = std::move(callback)](
        const sdn::responses::Messages &res, HeaderFields, RequestErr err) { callback(res, err); });
}

void
Client::upload_filter(const nlohmann::json &j, Callback<sdn::responses::FilterId> callback)
{
    const auto api_path =
      "/client/v3/user/" + sdn::client::utils::url_encode(user_id_.to_string()) + "/filter";

    post<nlohmann::json, sdn::responses::FilterId>(api_path, j, std::move(callback));
}

void
Client::read_event(const std::string &room_id,
                   const std::string &event_id,
                   ErrCallback callback,
                   bool hidden)
{
    const auto api_path =
      "/client/v3/rooms/" + sdn::client::utils::url_encode(room_id) + "/read_markers";

    nlohmann::json body = {
      {"m.fully_read", event_id},
      {"org.matrix.msc2285.read.private", event_id},
      {"m.read.private", event_id},
    };

    if (!hidden)
        body["m.read"] = event_id;

    post<nlohmann::json, sdn::responses::Empty>(
      api_path,
      body,
      [callback = std::move(callback)](const sdn::responses::Empty, RequestErr err) {
          callback(err);
      });
}

void
Client::redact_event(const std::string &room_id,
                     const std::string &event_id,
                     Callback<sdn::responses::EventId> callback,
                     const std::string &reason)
{
    const auto api_path = "/client/v3/rooms/" + sdn::client::utils::url_encode(room_id) +
                          "/redact/" + sdn::client::utils::url_encode(event_id) + "/" +
                          sdn::client::utils::url_encode(sdn::client::utils::random_token());

    nlohmann::json body = nlohmann::json::object();
    if (!reason.empty()) {
        body["reason"] = reason;
    }

    put<nlohmann::json, sdn::responses::EventId>(api_path, body, std::move(callback));
}

void
Client::registration(const std::string &user,
                     const std::string &pass,
                     UIAHandler uia_handler,
                     Callback<sdn::responses::Register> cb,
                     const std::string &initial_device_display_name)
{
    nlohmann::json req = {{"username", user}, {"password", pass}};

    if (!initial_device_display_name.empty())
        req["initial_device_display_name"] = initial_device_display_name;

    uia_handler.next_ = [this, req, cb = std::move(cb)](const UIAHandler &h,
                                                        const nlohmann::json &auth) {
        auto request = req;
        if (!auth.empty())
            request["auth"] = auth;

        post<nlohmann::json, sdn::responses::Register>(
          "/client/v3/register",
          request,
          [this, cb, h](auto &r, RequestErr e) {
              if (e && e->status_code == 401) {
                  sdn::utils::log::log()->debug("{}", e);
                  h.prompt(h, e->sdn_error.unauthorized);
              } else {
                  if (!e && !r.access_token.empty()) {
                      this->user_id_      = r.user_id;
                      this->device_id_    = r.device_id;
                      this->access_token_ = r.access_token;
                  }
                  cb(r, e);
              }
          },
          false);
    };

    uia_handler.next_(uia_handler, {});
}

void
Client::registration(Callback<sdn::responses::Register> cb)
{
    post<nlohmann::json, sdn::responses::Register>(
      "/client/v3/register", nlohmann::json::object(), std::move(cb), false);
}

void
Client::registration_token_validity(const std::string token,
                                    Callback<sdn::responses::RegistrationTokenValidity> cb)
{
    const auto api_path = "/client/v1/register/m.login.registration_token/validity?" +
                          sdn::client::utils::query_params({{"token", token}});

    get<sdn::responses::RegistrationTokenValidity>(
      api_path,
      [cb = std::move(cb)](const sdn::responses::RegistrationTokenValidity &res,
                           HeaderFields,
                           RequestErr err) { cb(res, err); });
}

void
Client::register_email_request_token(const requests::RequestEmailToken &r,
                                     Callback<sdn::responses::RequestToken> cb)
{
    post("/client/v3/register/email/requestToken", r, std::move(cb));
}

void
Client::register_username_available(const std::string &username,
                                    Callback<sdn::responses::Available> cb)
{
    get<sdn::responses::Available>(
      "/client/v3/register/available?username=" + sdn::client::utils::url_encode(username),
      [cb = std::move(cb)](const sdn::responses::Available &res, HeaderFields, RequestErr err) {
          cb(res, err);
      });
}

void
Client::verify_email_request_token(const requests::RequestEmailToken &r,
                                   Callback<sdn::responses::RequestToken> cb)
{
    post("/client/v3/account/password/email/requestToken", r, std::move(cb));
}

void
Client::register_phone_request_token(const requests::RequestMSISDNToken &r,
                                     Callback<sdn::responses::RequestToken> cb)
{
    post("/client/v3/register/msisdn/requestToken", r, std::move(cb));
}
void
Client::verify_phone_request_token(const requests::RequestMSISDNToken &r,
                                   Callback<sdn::responses::RequestToken> cb)
{
    post("/client/v3/account/password/msisdn/requestToken", r, std::move(cb));
}

void
Client::validate_submit_token(const std::string &url,
                              const requests::IdentitySubmitToken &r,
                              Callback<sdn::responses::Success> cb)
{
    // some dancing to send to an arbitrary, server provided url
    auto callback = prepare_callback<sdn::responses::Success>(
      [cb = std::move(cb)](const sdn::responses::Success &res, HeaderFields, RequestErr err) {
          cb(res, err);
      });
    p->client.post(
      url,
      nlohmann::json(r).dump(),
      "application/json",
      [callback = std::move(callback)](const coeurl::Request &r) {
          callback(r.response_headers(), r.response(), r.error_code(), r.response_code());
      },
      prepare_headers(false));
}

void
Client::send_state_event(const std::string &room_id,
                         const std::string &event_type,
                         const std::string &state_key,
                         const nlohmann::json &payload,
                         Callback<sdn::responses::EventId> callback)
{
    const auto api_path = "/client/v3/rooms/" + sdn::client::utils::url_encode(room_id) +
                          "/state/" + sdn::client::utils::url_encode(event_type) + "/" +
                          sdn::client::utils::url_encode(state_key);

    put<nlohmann::json, sdn::responses::EventId>(api_path, payload, std::move(callback));
}

void
Client::send_to_device(const std::string &event_type,
                       const std::string &txn_id,
                       const nlohmann::json &body,
                       ErrCallback callback)
{
    const auto api_path = "/client/v3/sendToDevice/" + sdn::client::utils::url_encode(event_type) +
                          "/" + sdn::client::utils::url_encode(txn_id);

    put<nlohmann::json>(api_path, body, std::move(callback));
}

void
Client::resolve_room_alias(const std::string &alias, Callback<sdn::responses::RoomId> cb)
{
    const auto api_path = "/client/v3/directory/room/" + sdn::client::utils::url_encode(alias);

    get<sdn::responses::RoomId>(api_path,
                                [cb = std::move(cb)](const sdn::responses::RoomId &res,
                                                     HeaderFields,
                                                     RequestErr err) { cb(res, err); });
}
void
Client::add_room_alias(const std::string &alias, const std::string &roomid, ErrCallback cb)
{
    const auto api_path = "/client/v3/directory/room/" + sdn::client::utils::url_encode(alias);
    auto body           = nlohmann::json::object();
    body["room_id"]     = roomid;
    put<nlohmann::json>(api_path, body, std::move(cb));
}

void
Client::delete_room_alias(const std::string &alias, ErrCallback cb)
{
    delete_("/client/v3/directory/room/" + sdn::client::utils::url_encode(alias), std::move(cb));
}

void
Client::list_room_aliases(const std::string &room_id, Callback<sdn::responses::Aliases> cb)
{
    const auto api_path =
      "/client/v3/rooms/" + sdn::client::utils::url_encode(room_id) + "/aliases";

    get<sdn::responses::Aliases>(api_path,
                                 [cb = std::move(cb)](const sdn::responses::Aliases &res,
                                                      HeaderFields,
                                                      RequestErr err) { cb(res, err); });
}

void
Client::get_room_visibility(const std::string &room_id,
                            Callback<sdn::responses::PublicRoomVisibility> cb)
{
    const auto api_path =
      "/client/v3/directory/list/room/" + sdn::client::utils::url_encode(room_id);

    get<sdn::responses::PublicRoomVisibility>(
      api_path,
      [cb = std::move(cb)](const sdn::responses::PublicRoomVisibility &res,
                           HeaderFields,
                           RequestErr err) { cb(res, err); });
}

void
Client::put_room_visibility(const std::string &room_id,
                            const sdn::requests::PublicRoomVisibility &req,
                            ErrCallback cb)
{
    const auto api_path =
      "/client/v3/directory/list/room/" + sdn::client::utils::url_encode(room_id);
    put<sdn::requests::PublicRoomVisibility>(api_path, req, std::move(cb));
}

void
Client::post_public_rooms(const sdn::requests::PublicRooms &req,
                          Callback<sdn::responses::PublicRooms> cb,
                          const std::string &server)
{
    std::string api_path = "/client/v3/publicRooms";

    if (!server.empty())
        api_path += "?" + sdn::client::utils::query_params({{"server", server}});
    post<sdn::requests::PublicRooms, sdn::responses::PublicRooms>(api_path, req, std::move(cb));
}

void
Client::get_public_rooms(Callback<sdn::responses::PublicRooms> cb,
                         const std::string &server,
                         size_t limit,
                         const std::string &since)
{
    std::string api_path = "/client/v3/publicRooms";

    std::map<std::string, std::string> params;
    if (!server.empty())
        params["server"] = server;
    if (limit > 0)
        params["limit"] = std::to_string(limit);
    if (!since.empty())
        params["since"] = since;

    if (!params.empty())
        api_path += "?" + sdn::client::utils::query_params(params);

    get<sdn::responses::PublicRooms>(api_path,
                                     [cb = std::move(cb)](const sdn::responses::PublicRooms &res,
                                                          HeaderFields,
                                                          RequestErr err) { cb(res, err); });
}

void
Client::get_hierarchy(const std::string &room_id,
                      Callback<sdn::responses::HierarchyRooms> cb,
                      const std::string &from,
                      size_t limit,
                      size_t max_depth,
                      bool suggested_only)
{
    std::string api_path =
      "/client/v1/rooms/" + sdn::client::utils::url_encode(room_id) + "/hierarchy";

    std::map<std::string, std::string> params;
    if (limit > 0)
        params["limit"] = std::to_string(limit);
    if (max_depth > 0)
        params["max_depth"] = std::to_string(max_depth);
    if (suggested_only)
        params["suggested_only"] = "true";
    if (!from.empty())
        params["from"] = from;

    if (!params.empty())
        api_path += "?" + sdn::client::utils::query_params(params);

    get<sdn::responses::HierarchyRooms>(
      api_path,
      [cb = std::move(cb)](
        const sdn::responses::HierarchyRooms &res, HeaderFields, RequestErr err) { cb(res, err); });
}

void
Client::get_summary(const std::string &room_id,
                    Callback<sdn::responses::PublicRoomsChunk> cb,
                    std::vector<std::string> via)
{
    std::string query;
    if (!via.empty()) {
        query = "?via=" + sdn::client::utils::url_encode(via[0]);
        for (size_t i = 1; i < via.size(); i++) {
            query += "&via=" + sdn::client::utils::url_encode(via[i]);
        }
    }
    std::string api_path = "/client/unstable/im.nheko.summary/rooms/" +
                           sdn::client::utils::url_encode(room_id) + "/summary" + query;

    get<sdn::responses::PublicRoomsChunk>(
      api_path,
      [this, room_id, cb = std::move(cb)](
        const sdn::responses::PublicRoomsChunk &res, HeaderFields, RequestErr err) {
          if (!err || !(err->status_code == 404 || err->status_code == 400))
              cb(res, err);
          else if (!room_id.empty() && room_id[0] == '#')
              resolve_room_alias(
                room_id, [this, cb](const sdn::responses::RoomId &room, RequestErr err) {
                    if (room.room_id.empty())
                        cb({}, err);
                    else
                        get_hierarchy(
                          room.room_id,
                          [cb](const sdn::responses::HierarchyRooms &res, RequestErr err) {
                              if (res.rooms.empty())
                                  cb({}, err);
                              else
                                  cb(res.rooms.front(), err);
                          },
                          "",
                          1);
                });
          else
              get_hierarchy(
                room_id,
                [cb](const sdn::responses::HierarchyRooms &res, RequestErr err) {
                    if (res.rooms.empty())
                        cb({}, err);
                    else
                        cb(res.rooms.front(), err);
                },
                "",
                1);
      });
}

//
// Device related endpoints
//

void
Client::query_devices(Callback<sdn::responses::QueryDevices> cb)
{
    get<sdn::responses::QueryDevices>("/client/v3/devices",
                                      [cb = std::move(cb)](const sdn::responses::QueryDevices &res,
                                                           HeaderFields,
                                                           RequestErr err) { cb(res, err); });
}

void
Client::get_device(const std::string &device_id, Callback<sdn::responses::Device> cb)
{
    get<sdn::responses::Device>("/client/v3/devices/" + sdn::client::utils::url_encode(device_id),
                                [cb = std::move(cb)](const sdn::responses::Device &res,
                                                     HeaderFields,
                                                     RequestErr err) { cb(res, err); });
}

void
Client::set_device_name(const std::string &device_id,
                        const std::string &display_name,
                        ErrCallback callback)
{
    sdn::requests::DeviceUpdate req;
    req.display_name = display_name;

    put<sdn::requests::DeviceUpdate>(
      "/client/v3/devices/" + sdn::client::utils::url_encode(device_id), req, std::move(callback));
}

void
Client::delete_device(const std::string &device_id, UIAHandler uia_handler, ErrCallback cb)
{
    nlohmann::json req;
    req["devices"] = {device_id};

    uia_handler.next_ = [this, req, cb = std::move(cb)](const UIAHandler &h,
                                                        const nlohmann::json &auth) {
        auto request = req;
        if (!auth.empty())
            request["auth"] = auth;

        post<nlohmann::json, sdn::responses::Empty>(
          "/client/v3/delete_devices", request, [cb, h](auto &, RequestErr e) {
              if (e && e->status_code == 401 && !e->sdn_error.unauthorized.flows.empty())
                  h.prompt(h, e->sdn_error.unauthorized);
              else
                  cb(e);
          });
    };

    uia_handler.next_(uia_handler, {});
}

void
Client::delete_devices(const std::vector<std::string> &device_ids,
                       UIAHandler uia_handler,
                       ErrCallback cb)
{
    nlohmann::json req;
    req["devices"] = device_ids;

    uia_handler.next_ = [this, req = std::move(req), cb = std::move(cb)](
                          const UIAHandler &h, const nlohmann::json &auth) {
        auto request = req;
        if (!auth.empty())
            request["auth"] = auth;

        post<nlohmann::json, sdn::responses::Empty>(
          "/client/v3/delete_devices", request, [cb, h](auto &, RequestErr e) {
              if (e && e->status_code == 401 && !e->sdn_error.unauthorized.flows.empty())
                  h.prompt(h, e->sdn_error.unauthorized);
              else
                  cb(e);
          });
    };

    uia_handler.next_(uia_handler, {});
}

//
// Encryption related endpoints
//

void
Client::upload_keys(const sdn::requests::UploadKeys &req,
                    Callback<sdn::responses::UploadKeys> callback)
{
    post<sdn::requests::UploadKeys, sdn::responses::UploadKeys>(
      "/client/v3/keys/upload", req, std::move(callback));
}

void
Client::keys_signatures_upload(const sdn::requests::KeySignaturesUpload &req,
                               Callback<sdn::responses::KeySignaturesUpload> cb)
{
    post<sdn::requests::KeySignaturesUpload, sdn::responses::KeySignaturesUpload>(
      "/client/v3/keys/signatures/upload", req, std::move(cb));
}

void
Client::device_signing_upload(const sdn::requests::DeviceSigningUpload &deviceKeys,
                              UIAHandler uia_handler,
                              ErrCallback cb)
{
    nlohmann::json req = deviceKeys;

    uia_handler.next_ = [this, req = std::move(req), cb = std::move(cb)](
                          const UIAHandler &h, const nlohmann::json &auth) {
        auto request = req;
        if (!auth.empty())
            request["auth"] = auth;

        post<nlohmann::json, sdn::responses::Empty>(
          "/client/v3/keys/device_signing/upload", request, [cb, h](auto &, RequestErr e) {
              if (e && e->status_code == 401 && !e->sdn_error.unauthorized.flows.empty())
                  h.prompt(h, e->sdn_error.unauthorized);
              else
                  cb(e);
          });
    };

    uia_handler.next_(uia_handler, {});
}

void
Client::query_keys(const sdn::requests::QueryKeys &req,
                   Callback<sdn::responses::QueryKeys> callback)
{
    post<sdn::requests::QueryKeys, sdn::responses::QueryKeys>(
      "/client/v3/keys/query", req, std::move(callback));
}

//! Claims one-time keys for use in pre-key messages.
void
Client::claim_keys(const sdn::requests::ClaimKeys &req, Callback<sdn::responses::ClaimKeys> cb)
{
    post<sdn::requests::ClaimKeys, sdn::responses::ClaimKeys>(
      "/client/v3/keys/claim", req, std::move(cb));
}

void
Client::key_changes(const std::string &from,
                    const std::string &to,
                    Callback<sdn::responses::KeyChanges> callback)
{
    std::map<std::string, std::string> params;

    if (!from.empty())
        params.emplace("from", from);

    if (!to.empty())
        params.emplace("to", to);

    get<sdn::responses::KeyChanges>(
      "/client/v3/keys/changes?" + sdn::client::utils::query_params(params),
      [callback = std::move(callback)](const sdn::responses::KeyChanges &res,
                                       HeaderFields,
                                       RequestErr err) { callback(res, err); });
}

//
// Key backup endpoints
//
void
Client::backup_version(Callback<sdn::responses::backup::BackupVersion> cb)
{
    get<sdn::responses::backup::BackupVersion>(
      "/client/v3/room_keys/version",
      [cb = std::move(cb)](const sdn::responses::backup::BackupVersion &res,
                           HeaderFields,
                           RequestErr err) { cb(res, err); });
}
void
Client::backup_version(const std::string &version,
                       Callback<sdn::responses::backup::BackupVersion> cb)
{
    get<sdn::responses::backup::BackupVersion>(
      "/client/v3/room_keys/version/" + sdn::client::utils::url_encode(version),
      [cb = std::move(cb)](const sdn::responses::backup::BackupVersion &res,
                           HeaderFields,
                           RequestErr err) { cb(res, err); });
}

void
Client::update_backup_version(const std::string &version,
                              const sdn::responses::backup::BackupVersion &data,
                              ErrCallback cb)
{
    put<sdn::responses::backup::BackupVersion>("/client/v3/room_keys/version/" +
                                                 sdn::client::utils::url_encode(version),
                                               data,
                                               std::move(cb));
}

void
Client::post_backup_version(const std::string &algorithm,
                            const std::string &auth_data,
                            Callback<sdn::responses::Version> cb)
{
    nlohmann::json req = {{"algorithm", algorithm},
                          {"auth_data", nlohmann::json::parse(auth_data)}};
    post<nlohmann::json, sdn::responses::Version>(
      "/client/v3/room_keys/version", req, std::move(cb));
}
void
Client::room_keys(const std::string &version, Callback<sdn::responses::backup::KeysBackup> cb)
{
    get<sdn::responses::backup::KeysBackup>(
      "/client/v3/room_keys/keys?" + sdn::client::utils::query_params({{"version", version}}),
      [cb = std::move(cb)](const sdn::responses::backup::KeysBackup &res,
                           HeaderFields,
                           RequestErr err) { cb(res, err); });
}
void
Client::room_keys(const std::string &version,
                  const std::string &room_id,
                  Callback<sdn::responses::backup::RoomKeysBackup> cb)
{
    get<sdn::responses::backup::RoomKeysBackup>(
      "/client/v3/room_keys/keys/" + sdn::client::utils::url_encode(room_id) + "?" +
        sdn::client::utils::query_params({{"version", version}}),
      [cb = std::move(cb)](const sdn::responses::backup::RoomKeysBackup &res,
                           HeaderFields,
                           RequestErr err) { cb(res, err); });
}
void
Client::room_keys(const std::string &version,
                  const std::string &room_id,
                  const std::string &session_id,
                  Callback<sdn::responses::backup::SessionBackup> cb)
{
    get<sdn::responses::backup::SessionBackup>(
      "/client/v3/room_keys/keys/" + sdn::client::utils::url_encode(room_id) + "/" +
        sdn::client::utils::url_encode(session_id) + "?" +
        sdn::client::utils::query_params({{"version", version}}),
      [cb = std::move(cb)](const sdn::responses::backup::SessionBackup &res,
                           HeaderFields,
                           RequestErr err) { cb(res, err); });
}

void
Client::put_room_keys(const std::string &version,
                      const sdn::responses::backup::KeysBackup &keys,
                      ErrCallback cb)
{
    put("/client/v3/room_keys/keys?" + sdn::client::utils::query_params({{"version", version}}),
        keys,
        std::move(cb));
}
void
Client::put_room_keys(const std::string &version,
                      const std::string &room_id,
                      const sdn::responses::backup::RoomKeysBackup &keys,
                      ErrCallback cb)
{
    put("/client/v3/room_keys/keys/" + sdn::client::utils::url_encode(room_id) + "?" +
          sdn::client::utils::query_params({{"version", version}}),
        keys,
        std::move(cb));
}
void
Client::put_room_keys(const std::string &version,
                      const std::string &room_id,
                      const std::string &session_id,
                      const sdn::responses::backup::SessionBackup &keys,
                      ErrCallback cb)
{
    put("/client/v3/room_keys/keys/" + sdn::client::utils::url_encode(room_id) + "/" +
          sdn::client::utils::url_encode(session_id) + "?" +
          sdn::client::utils::query_params({{"version", version}}),
        keys,
        std::move(cb));
}

//! Retrieve a specific secret
void
Client::secret_storage_secret(const std::string &secret_id,
                              Callback<sdn::secret_storage::Secret> cb)
{
    get<sdn::secret_storage::Secret>(
      "/client/v3/user/" + sdn::client::utils::url_encode(user_id_.to_string()) + "/account_data/" +
        sdn::client::utils::url_encode(secret_id),
      [cb = std::move(cb)](const sdn::secret_storage::Secret &res, HeaderFields, RequestErr err) {
          cb(res, err);
      });
}
//! Retrieve information about a key
void
Client::secret_storage_key(const std::string &key_id,
                           Callback<sdn::secret_storage::AesHmacSha2KeyDescription> cb)
{
    get<sdn::secret_storage::AesHmacSha2KeyDescription>(
      "/client/v3/user/" + sdn::client::utils::url_encode(user_id_.to_string()) +
        "/account_data/m.secret_storage.key." + sdn::client::utils::url_encode(key_id),
      [cb = std::move(cb)](const sdn::secret_storage::AesHmacSha2KeyDescription &res,
                           HeaderFields,
                           RequestErr err) { cb(res, err); });
}

//! Upload a specific secret
void
Client::upload_secret_storage_secret(const std::string &secret_id,
                                     const sdn::secret_storage::Secret &secret,
                                     ErrCallback cb)
{
    put("/client/v3/user/" + sdn::client::utils::url_encode(user_id_.to_string()) +
          "/account_data/" + sdn::client::utils::url_encode(secret_id),
        secret,
        std::move(cb));
}

//! Upload information about a key
void
Client::upload_secret_storage_key(const std::string &key_id,
                                  const sdn::secret_storage::AesHmacSha2KeyDescription &desc,
                                  ErrCallback cb)
{
    put("/client/v3/user/" + sdn::client::utils::url_encode(user_id_.to_string()) +
          "/account_data/m.secret_storage.key." + sdn::client::utils::url_encode(key_id),
        desc,
        std::move(cb));
}

void
Client::set_secret_storage_default_key(const std::string &key_id, ErrCallback cb)
{
    nlohmann::json key = {{"key", key_id}};
    put("/client/v3/user/" + sdn::client::utils::url_encode(user_id_.to_string()) +
          "/account_data/m.secret_storage.default_key",
        key,
        std::move(cb));
}

void
Client::enable_encryption(const std::string &room, Callback<sdn::responses::EventId> callback)
{
    using namespace sdn::events;
    state::Encryption event;

    send_state_event<state::Encryption>(room, "", event, std::move(callback));
}

void
Client::get_turn_server(Callback<sdn::responses::TurnServer> cb)
{
    get<sdn::responses::TurnServer>("/client/v3/voip/turnServer",
                                    [cb = std::move(cb)](const sdn::responses::TurnServer &res,
                                                         HeaderFields,
                                                         RequestErr err) { cb(res, err); });
}

void
Client::set_pusher(const sdn::requests::SetPusher &req, Callback<sdn::responses::Empty> cb)
{
    post<sdn::requests::SetPusher, sdn::responses::Empty>(
      "/client/v3/pushers/set", req, std::move(cb));
}

void
Client::search_user_directory(const std::string &search_term,
                              Callback<sdn::responses::Users> callback,
                              int limit)
{
    nlohmann::json req = {{"search_term", search_term}};
    if (limit >= 0)
        req["limit"] = limit;
    post<nlohmann::json, sdn::responses::Users>(
      "/client/v3/user_directory/search", req, std::move(callback));
}

// Template instantiations for the various send functions

#define MTXCLIENT_SEND_STATE_EVENT(Content)                                                        \
    template void sdn::http::Client::send_state_event<sdn::events::Content>(                       \
      const std::string &,                                                                         \
      const std::string &state_key,                                                                \
      const sdn::events::Content &,                                                                \
      Callback<sdn::responses::EventId> cb);                                                       \
    template void sdn::http::Client::send_state_event<sdn::events::Content>(                       \
      const std::string &, const sdn::events::Content &, Callback<sdn::responses::EventId> cb);    \
    template void sdn::http::Client::get_state_event<sdn::events::Content>(                        \
      const std::string &room_id,                                                                  \
      const std::string &type,                                                                     \
      const std::string &state_key,                                                                \
      Callback<sdn::events::Content> cb);                                                          \
    template void sdn::http::Client::get_state_event<sdn::events::Content>(                        \
      const std::string &room_id,                                                                  \
      const std::string &state_key,                                                                \
      Callback<sdn::events::Content> cb);

MTXCLIENT_SEND_STATE_EVENT(state::Aliases)
MTXCLIENT_SEND_STATE_EVENT(state::Avatar)
MTXCLIENT_SEND_STATE_EVENT(state::CanonicalAlias)
MTXCLIENT_SEND_STATE_EVENT(state::Create)
MTXCLIENT_SEND_STATE_EVENT(state::Encryption)
MTXCLIENT_SEND_STATE_EVENT(state::GuestAccess)
MTXCLIENT_SEND_STATE_EVENT(state::HistoryVisibility)
MTXCLIENT_SEND_STATE_EVENT(state::JoinRules)
MTXCLIENT_SEND_STATE_EVENT(state::Member)
MTXCLIENT_SEND_STATE_EVENT(state::Name)
MTXCLIENT_SEND_STATE_EVENT(state::PinnedEvents)
MTXCLIENT_SEND_STATE_EVENT(state::PowerLevels)
MTXCLIENT_SEND_STATE_EVENT(state::Tombstone)
MTXCLIENT_SEND_STATE_EVENT(state::Topic)
MTXCLIENT_SEND_STATE_EVENT(state::Widget)
MTXCLIENT_SEND_STATE_EVENT(state::policy_rule::UserRule)
MTXCLIENT_SEND_STATE_EVENT(state::policy_rule::RoomRule)
MTXCLIENT_SEND_STATE_EVENT(state::policy_rule::ServerRule)
MTXCLIENT_SEND_STATE_EVENT(state::space::Child)
MTXCLIENT_SEND_STATE_EVENT(state::space::Parent)
MTXCLIENT_SEND_STATE_EVENT(msc2545::ImagePack)

#define MTXCLIENT_SEND_ROOM_MESSAGE(Content)                                                       \
    template void sdn::http::Client::send_room_message<Content>(                                   \
      const std::string &,                                                                         \
      const std::string &,                                                                         \
      const Content &,                                                                             \
      Callback<sdn::responses::EventId> cb);                                                       \
    template void sdn::http::Client::send_room_message<Content>(                                   \
      const std::string &, const Content &, Callback<sdn::responses::EventId> cb);

MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::Encrypted)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::StickerImage)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::Reaction)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::Audio)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::Emote)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::File)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::Image)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::Notice)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::Text)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::Unknown)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::Video)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::ElementEffect)
// MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationRequest)
// MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationStart)
// MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationReady)
// MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationDone)
// MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationAccept)
// MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationCancel)
// MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationKey)
// MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationMac)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::voip::CallInvite)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::voip::CallCandidates)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::voip::CallAnswer)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::voip::CallHangUp)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::voip::CallSelectAnswer)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::voip::CallReject)
MTXCLIENT_SEND_ROOM_MESSAGE(sdn::events::voip::CallNegotiate)

#define MTXCLIENT_SEND_TO_DEVICE(Content)                                                          \
    template void sdn::http::Client::send_to_device<Content>(                                      \
      const std::string &txid,                                                                     \
      const std::map<sdn::identifiers::User, std::map<std::string, Content>> &messages,            \
      ErrCallback callback);

MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::RoomKey)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::ForwardedRoomKey)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::KeyRequest)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::OlmEncrypted)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::Encrypted)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::Dummy)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::KeyVerificationRequest)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::KeyVerificationStart)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::KeyVerificationReady)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::KeyVerificationDone)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::KeyVerificationAccept)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::KeyVerificationCancel)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::KeyVerificationKey)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::KeyVerificationMac)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::SecretSend)
MTXCLIENT_SEND_TO_DEVICE(sdn::events::msg::SecretRequest)

#define MTXCLIENT_ACCOUNT_DATA(Payload)                                                            \
    template void sdn::http::Client::put_room_account_data<Payload>(const std::string &room_id,    \
                                                                    const std::string &type,       \
                                                                    const Payload &payload,        \
                                                                    ErrCallback cb);               \
    template void sdn::http::Client::put_room_account_data<Payload>(                               \
      const std::string &room_id, const Payload &payload, ErrCallback cb);                         \
    template void sdn::http::Client::put_account_data<Payload>(                                    \
      const std::string &type, const Payload &payload, ErrCallback cb);                            \
    template void sdn::http::Client::put_account_data<Payload>(const Payload &payload,             \
                                                               ErrCallback cb);                    \
    template void sdn::http::Client::get_room_account_data<Payload>(                               \
      const std::string &room_id, const std::string &type, Callback<Payload> payload);             \
    template void sdn::http::Client::get_room_account_data<Payload>(const std::string &room_id,    \
                                                                    Callback<Payload> cb);         \
    template void sdn::http::Client::get_account_data<Payload>(const std::string &type,            \
                                                               Callback<Payload> payload);         \
    template void sdn::http::Client::get_account_data<Payload>(Callback<Payload> cb);

MTXCLIENT_ACCOUNT_DATA(sdn::events::msc2545::ImagePack)
MTXCLIENT_ACCOUNT_DATA(sdn::events::msc2545::ImagePackRooms)
MTXCLIENT_ACCOUNT_DATA(sdn::events::account_data::nheko_extensions::HiddenEvents)
MTXCLIENT_ACCOUNT_DATA(sdn::events::account_data::nheko_extensions::EventExpiry)
MTXCLIENT_ACCOUNT_DATA(sdn::events::account_data::Tags)
MTXCLIENT_ACCOUNT_DATA(sdn::events::account_data::Direct)
MTXCLIENT_ACCOUNT_DATA(sdn::events::account_data::IgnoredUsers)