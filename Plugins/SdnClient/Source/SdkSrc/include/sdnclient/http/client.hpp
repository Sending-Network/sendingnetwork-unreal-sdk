#pragma once

/// @file
/// @brief Primary header to access the http API.

#if __has_include(<nlohmann/json_fwd.hpp>)
#include <nlohmann/json_fwd.hpp>
#else
#include <nlohmann/json.hpp>
#endif

#include "sdn/errors.hpp"             // for Error
#include "sdn/events.hpp"             // for EventType, to_string, json
#include "sdn/events/collections.hpp" // for TimelineEvents
#include "sdn/identifiers.hpp"        // for User
#include "sdn/identifiers.hpp"        // for Class user
#include "sdn/pushrules.hpp"
#include "sdn/requests.hpp"
#include "sdn/responses/empty.hpp" // for Empty, Logout, RoomInvite
#include "sdn/secret_storage.hpp"
#include "sdnclient/http/errors.hpp" // for ClientError
#include "sdnclient/utils.hpp"       // for random_token, url_encode, des...
// #include "sdn/common.hpp"

#include <cstdint>    // for uint16_t, uint64_t
#include <functional> // for function
#include <memory>     // for allocator, shared_ptr, enable...
#include <optional>   // for optional
#include <string>     // for string, operator+, char_traits
#include <utility>    // for move
#include <vector>     // for vector

#include <coeurl/headers.hpp>

// forward declarations
namespace sdn {
namespace http {
struct ClientPrivate;
struct Session;
}
namespace requests {
struct CreateRoom;
struct KeySignaturesUpload;
struct PreLogin;
struct Login;
struct QueryKeys;
struct ClaimKeys;
struct UploadKeys;
struct PublicRoomVisibility;
struct PublicRooms;
struct PushersData;
struct SetPushers;
}
namespace responses {
struct Aliases;
struct Available;
struct AvatarUrl;
struct ClaimKeys;
struct ContentURI;
struct CreateRoom;
struct Device;
struct EventId;
struct FilterId;
struct KeyChanges;
struct KeySignaturesUpload;
struct PreLogin;
struct Login;
struct LoginFlows;
struct Members;
struct Messages;
struct Notifications;
struct Profile;
struct PublicRoomVisibility;
struct PublicRoomsChunk;
struct PublicRooms;
struct HierarchyRooms;
struct QueryDevices;
struct QueryKeys;
struct Register;
struct RegistrationTokenValidity;
struct RequestToken;
struct RoomId;
struct Success;
struct Sync;
struct StateEvents;
struct TurnServer;
struct UploadKeys;
struct Users;
struct Version;
struct Versions;
struct WellKnown;
namespace backup {
struct SessionBackup;
struct RoomKeysBackup;
struct KeysBackup;
struct BackupVersion;
}
namespace capabilities {
struct Capabilities;
}
}
}

namespace sdn {
//! Types related to invoking the actual HTTP requests
namespace http {

enum class PaginationDirection
{
    Backwards,
    Forwards,
};

inline std::string
to_string(PaginationDirection dir)
{
    if (dir == PaginationDirection::Backwards)
        return "b";

    return "f";
}

using RequestErr   = const std::optional<sdn::http::ClientError> &;
using HeaderFields = const std::optional<coeurl::Headers> &;
using ErrCallback  = std::function<void(RequestErr)>;

template<class Response>
using Callback = std::function<void(const Response &, RequestErr)>;

template<class Response>
using HeadersCallback    = std::function<void(const Response &, HeaderFields, RequestErr)>;
using TypeErasedCallback = std::function<void(HeaderFields, const std::string_view &, int, int)>;

//! A helper to handle user interactive authentication. This will cache the request and call the
//! prompt every time there is a new stage. Advance the flow by calling next().
class UIAHandler
{
public:
    //! The callback for when a new UIA stage needs to be completed
    using UIAPrompt =
      std::function<void(const UIAHandler &, const user_interactive::Unauthorized &)>;

    //! Create a new UIA handler. Pass a callback for when a new stage needs to be completed.
    UIAHandler(UIAPrompt prompt_)
      : prompt(std::move(prompt_))
    {
    }

    void next(const user_interactive::Auth &auth) const;

private:
    UIAPrompt prompt;

    std::function<void(const UIAHandler &, const nlohmann::json &)> next_;

    friend class Client;
};

//! Sync configuration options.
struct SyncOpts
{
    //! Filter to apply.
    std::string filter;
    //! Sync pagination token.
    std::string since;
    //! The amount of msecs to wait for long polling.
    uint16_t timeout = 30'000;
    //! Wheter to include the full state of each room.
    bool full_state = false;
    //! Explicitly set the presence of the user
    std::optional<sdn::presence::PresenceState> set_presence;
};

//! Configuration for the /messages endpoint.
struct MessagesOpts
{
    std::string room_id;
    std::string from;
    std::string to;
    std::string filter;

    PaginationDirection dir = PaginationDirection::Backwards;

    uint16_t limit = 30;
};

//! Configuration for thumbnail retrieving.
struct ThumbOpts
{
    //! The desired width of the thumbnail.
    uint16_t width = 128;
    //! The desired height of the thumbnail.
    uint16_t height = 128;
    //! The desired resizing method. One of: ["crop", "scale"]
    std::string method = "crop";
    //! A mxc URI which points to the content.
    std::string mxc_url;
};

struct ClientPrivate;
struct Session;

//! The main object that the user will interact.
class Client : public std::enable_shared_from_this<Client>
{
public:
    Client(const std::string &server = "", uint16_t port = 443);
    ~Client();

    //! Set a path to cache alternate service lookups like the http/3 ports of a server.
    void alt_svc_cache_path(const std::string &path);

    //! Wait for the client to close.
    void close(bool force = false);
    //! Enable or disable certificate verification. On by default
    void verify_certificates(bool enabled = true);
    //! Set the homeserver domain name.
    void set_user(const sdn::identifiers::User &user) { user_id_ = user; }
    //! Set the device ID.
    void set_device_id(const std::string &device_id) { device_id_ = device_id; }
    //! Set the homeserver domain name.
    void set_server(const std::string &server);
    //! Retrieve the homeserver domain name.
    std::string server() { return server_; };
    //! Retrieve the full server url including protocol and ports
    std::string server_url()
    {
        return protocol_ + "://" + server() + ":" + std::to_string(port());
    };
    //! Set the homeserver port.
    void set_port(uint16_t port) { port_ = port; };
    //! Retrieve the homeserver port.
    uint16_t port() { return port_; };
    //! Add an access token.
    void set_access_token(const std::string &token) { access_token_ = token; }
    //! Retrieve the access token.
    std::string access_token() const { return access_token_; }
    //! Update the next batch token.
    void set_next_batch_token(const std::string &token) { next_batch_token_ = token; }
    //! Retrieve the current next batch token.
    std::string next_batch_token() const { return next_batch_token_; }
    //! Retrieve the user_id.
    sdn::identifiers::User user_id() const { return user_id_; }
    //! Retrieve the device_id.
    std::string device_id() const { return device_id_; }
    //! Generate a new transaction id.
    std::string generate_txn_id() { return client::utils::random_token(32, false); }
    //! Abort all active pending requests.
    void shutdown();
    //! Remove all saved configuration.
    void clear()
    {
        device_id_.clear();
        access_token_.clear();
        next_batch_token_.clear();
        server_.clear();
        port_ = 443;
    }

    //! Perfom login.
    void login(const std::string &username,
               const std::string &password,
               Callback<sdn::responses::Login> cb);
    void login(const std::string &username,
               const std::string &password,
               const std::string &device_name,
               Callback<sdn::responses::Login> cb);
    void login(const sdn::requests::Login &req, Callback<sdn::responses::Login> cb);
    void pre_login(const std::string address, Callback<sdn::responses::PreLogin> cb);

    //! Get the supported login flows
    void get_login(Callback<sdn::responses::LoginFlows> cb);
    //! Get url to navigate to for sso login flow, optionally preselecting an identity provider
    //! Open this in a browser
    std::string login_sso_redirect(std::string redirectUrl, const std::string &idp = "");
    //! Lookup real server to connect to.
    //! Call set_server with the returned homeserver url after this
    void well_known(Callback<sdn::responses::WellKnown> cb);

    //! Check for username availability
    void register_username_available(const std::string &username,
                                     Callback<sdn::responses::Available> cb);

    //! Register with an UIA handler so you don't need to repeat the request manually.
    void registration(const std::string &user,
                      const std::string &pass,
                      UIAHandler uia_handler,
                      Callback<sdn::responses::Register> cb,
                      const std::string &initial_device_display_name = "");

    //! Send a dummy registration request to query the auth flows
    void registration(Callback<sdn::responses::Register> cb);

    //! Check the validity of a registration token
    void registration_token_validity(const std::string token,
                                     Callback<sdn::responses::RegistrationTokenValidity> cb);

    //! Validate an unused email address.
    void register_email_request_token(const requests::RequestEmailToken &r,
                                      Callback<sdn::responses::RequestToken> cb);
    //! Validate a used email address.
    void verify_email_request_token(const requests::RequestEmailToken &r,
                                    Callback<sdn::responses::RequestToken> cb);

    //! Validate an unused phone number.
    void register_phone_request_token(const requests::RequestMSISDNToken &r,
                                      Callback<sdn::responses::RequestToken> cb);
    //! Validate a used phone number.
    void verify_phone_request_token(const requests::RequestMSISDNToken &r,
                                    Callback<sdn::responses::RequestToken> cb);

    //! Validate ownership of an email address/phone number.
    void validate_submit_token(const std::string &url,
                               const requests::IdentitySubmitToken &r,
                               Callback<sdn::responses::Success>);

    //! Paginate through the list of events that the user has been,
    //! or would have been notified about.
    void notifications(uint64_t limit,
                       const std::string &from,
                       const std::string &only,
                       Callback<sdn::responses::Notifications> cb);

    //! Retrieve all push rulesets for this user.
    void get_pushrules(Callback<pushrules::GlobalRuleset> cb);

    //! Retrieve a single specified push rule.
    void get_pushrules(const std::string &scope,
                       const std::string &kind,
                       const std::string &ruleId,
                       Callback<pushrules::PushRule> cb);

    //! This endpoint removes the push rule defined in the path.
    void delete_pushrules(const std::string &scope,
                          const std::string &kind,
                          const std::string &ruleId,
                          ErrCallback cb);

    //! This endpoint allows the creation, modification and deletion of pushers for this user
    //! ID.
    void put_pushrules(const std::string &scope,
                       const std::string &kind,
                       const std::string &ruleId,
                       const pushrules::PushRule &rule,
                       ErrCallback cb,
                       const std::string &before = "",
                       const std::string &after  = "");

    //! Retrieve a single specified push rule.
    void get_pushrules_enabled(const std::string &scope,
                               const std::string &kind,
                               const std::string &ruleId,
                               Callback<pushrules::Enabled> cb);

    //! This endpoint allows clients to enable or disable the specified push rule.
    void put_pushrules_enabled(const std::string &scope,
                               const std::string &kind,
                               const std::string &ruleId,
                               bool enabled,
                               ErrCallback cb);

    //! This endpoint get the actions for the specified push rule.
    void get_pushrules_actions(const std::string &scope,
                               const std::string &kind,
                               const std::string &ruleId,
                               Callback<pushrules::actions::Actions> cb);

    //! This endpoint allows clients to change the actions of a push rule. This can be used to
    //! change the actions of builtin rules.
    void put_pushrules_actions(const std::string &scope,
                               const std::string &kind,
                               const std::string &ruleId,
                               const pushrules::actions::Actions &actions,
                               ErrCallback cb);

    //! Perform logout.
    void logout(Callback<sdn::responses::Logout> cb);
    //! Change avatar.
    void set_avatar_url(const std::string &avatar_url, ErrCallback cb);
    //! Change displayname.
    void set_displayname(const std::string &displayname, ErrCallback cb);
    //! Get user profile.
    void get_profile(const std::string &user_id, Callback<sdn::responses::Profile> cb);
    //! Get user avatar URL.
    void get_avatar_url(const std::string &user_id, Callback<sdn::responses::AvatarUrl> cb);

    //! List the tags set by a user on a room.
    void get_tags(const std::string &room_id, Callback<sdn::events::account_data::Tags> cb);
    //! Add a tag to the room.
    void put_tag(const std::string &room_id,
                 const std::string &tag_name,
                 const sdn::events::account_data::Tag &tag,
                 ErrCallback cb);
    //! Remove a tag from the room.
    void delete_tag(const std::string &room_id, const std::string &tag_name, ErrCallback cb);

    //! Create a room with the given options.
    void create_room(const sdn::requests::CreateRoom &room_options,
                     Callback<sdn::responses::CreateRoom> cb);
    //! Join a room by an alias or a room_id.
    void join_room(const std::string &room, Callback<sdn::responses::RoomId> cb);
    //! Join a room by an alias or a room_id. `via` are other servers, that may know about this
    //! room.
    void join_room(const std::string &room,
                   const std::vector<std::string> &via,
                   Callback<sdn::responses::RoomId> cb,
                   const std::string &reason = "");
    //! Leave a room by its room_id.
    void leave_room(const std::string &room_id,
                    Callback<sdn::responses::Empty> cb,
                    const std::string &reason = "");
    //! Knock on a room.
    void knock_room(const std::string &room_id,
                    const std::vector<std::string> &via,
                    Callback<sdn::responses::RoomId> cb,
                    const std::string &reason = "");

    //! Invite a user to a room.
    void invite_user(const std::string &room_id,
                     const std::string &user_id,
                     Callback<sdn::responses::RoomInvite> cb,
                     const std::string &reason = "");
    //! Kick a user from a room.
    void kick_user(const std::string &room_id,
                   const std::string &user_id,
                   Callback<sdn::responses::Empty> cb,
                   const std::string &reason = "");
    //! Ban a user from a room.
    void ban_user(const std::string &room_id,
                  const std::string &user_id,
                  Callback<sdn::responses::Empty> cb,
                  const std::string &reason = "");
    //! Unban a user from a room.
    void unban_user(const std::string &room_id,
                    const std::string &user_id,
                    Callback<sdn::responses::Empty> cb,
                    const std::string &reason = "");

    //! Perform sync.
    void sync(const SyncOpts &opts, Callback<sdn::responses::Sync> cb);

    //! List members in a room.
    void members(const std::string &room_id,
                 Callback<sdn::responses::Members> cb,
                 const std::string &at                                        = "",
                 std::optional<sdn::events::state::Membership> membership     = {},
                 std::optional<sdn::events::state::Membership> not_membership = {});

    //! Paginate through room messages.
    void messages(const MessagesOpts &opts, Callback<sdn::responses::Messages> cb);

    //! Get the supported versions from the server.
    void versions(Callback<sdn::responses::Versions> cb);

    //! Get the supported capabilities from the server.
    void capabilities(Callback<sdn::responses::capabilities::Capabilities> cb);

    //! Mark an event as read.
    void read_event(const std::string &room_id,
                    const std::string &event_id,
                    ErrCallback cb,
                    bool hidden = false);

    //! Redact an event from a room.
    void redact_event(const std::string &room_id,
                      const std::string &event_id,
                      Callback<sdn::responses::EventId> cb,
                      const std::string &reason = "");

    //! Upload a filter
    void upload_filter(const nlohmann::json &j, Callback<sdn::responses::FilterId> cb);

    //! Upload data to the content repository.
    void upload(const std::string &data,
                const std::string &content_type,
                const std::string &filename,
                Callback<sdn::responses::ContentURI> cb);
    //! Retrieve data from the content repository.
    void download(const std::string &mxc_url,
                  std::function<void(const std::string &data,
                                     const std::string &content_type,
                                     const std::string &original_filename,
                                     RequestErr err)> cb);
    void download(const std::string &server,
                  const std::string &media_id,
                  std::function<void(const std::string &data,
                                     const std::string &content_type,
                                     const std::string &original_filename,
                                     RequestErr err)> cb);
    std::string mxc_to_download_url(const std::string &mxc_url);

    //! Retrieve a thumbnail from the given mxc url.
    //! If the thumbnail isn't found and `try_download` is `true` it will try
    //! to use the `/download` endpoint to retrieve the media.
    void get_thumbnail(const ThumbOpts &opts, Callback<std::string> cb, bool try_download = true);

    //! Send typing notifications to the room.
    void start_typing(const std::string &room_id, uint64_t timeout, ErrCallback cb);
    //! Remove typing notifications from the room.
    void stop_typing(const std::string &room_id, ErrCallback cb);

    //! Get presence of a user
    void presence_status(const std::string &user_id, Callback<sdn::events::presence::Presence> cb);
    //! Set presence of the user
    void put_presence_status(sdn::presence::PresenceState state,
                             std::optional<std::string> status_msg,
                             ErrCallback cb);

    //! Get a single event.
    void get_event(const std::string &room_id,
                   const std::string &event_id,
                   Callback<sdn::events::collections::TimelineEvents> cb);

    //! Retrieve the whole state of a room
    void get_state(const std::string &room_id, Callback<sdn::responses::StateEvents> payload);

    //! Retrieve a single state event.
    template<class Payload>
    void get_state_event(const std::string &room_id,
                         const std::string &type,
                         const std::string &state_key,
                         Callback<Payload> payload);
    //! Retrieve a single state event.
    template<class Payload>
    void get_state_event(const std::string &room_id,
                         const std::string &state_key,
                         Callback<Payload> cb);

    //! Store a room account_data event.
    template<class Payload>
    void put_room_account_data(const std::string &room_id,
                               const std::string &type,
                               const Payload &payload,
                               ErrCallback cb);
    //! Store a room account_data event.
    template<class Payload>
    void put_room_account_data(const std::string &room_id, const Payload &payload, ErrCallback cb);

    //! Store an account_data event.
    template<class Payload>
    void put_account_data(const std::string &type, const Payload &payload, ErrCallback cb);
    //! Store an account_data event.
    template<class Payload>
    void put_account_data(const Payload &payload, ErrCallback cb);

    //! Retrieve a room account_data event.
    template<class Payload>
    void get_room_account_data(const std::string &room_id,
                               const std::string &type,
                               Callback<Payload> payload);
    //! Retrieve a room account_data event.
    template<class Payload>
    void get_room_account_data(const std::string &room_id, Callback<Payload> cb);

    //! Retrieve an account_data event.
    template<class Payload>
    void get_account_data(const std::string &type, Callback<Payload> payload);
    //! Retrieve an account_data event.
    template<class Payload>
    void get_account_data(Callback<Payload> cb);

    //! Send a room message with auto-generated transaction id.
    template<class Payload>
    void send_room_message(const std::string &room_id,
                           const Payload &payload,
                           Callback<sdn::responses::EventId> cb);
    //! Send a room message by providing transaction id.
    template<class Payload>
    void send_room_message(const std::string &room_id,
                           const std::string &txn_id,
                           const Payload &payload,
                           Callback<sdn::responses::EventId> cb);
    //! Send a state event by providing the state key.
    void send_state_event(const std::string &room_id,
                          const std::string &event_type,
                          const std::string &state_key,
                          const nlohmann::json &payload,
                          Callback<sdn::responses::EventId> callback);
    template<class Payload>
    void send_state_event(const std::string &room_id,
                          const std::string &state_key,
                          const Payload &payload,
                          Callback<sdn::responses::EventId> cb);
    //! Send a state event with an empty state key.
    template<class Payload>
    void send_state_event(const std::string &room_id,
                          const Payload &payload,
                          Callback<sdn::responses::EventId> cb);

    //! Send send-to-device events to a set of client devices with a specified transaction id.
    void send_to_device(const std::string &event_type,
                        const std::string &txid,
                        const nlohmann::json &body,
                        ErrCallback cb);

    //! Send send-to-device events to a set of client devices with a generated transaction id.
    void send_to_device(const std::string &event_type, const nlohmann::json &body, ErrCallback cb)
    {
        send_to_device(event_type, generate_txn_id(), body, cb);
    }
    //! Send send-to-device events to a set of client devices with a specified transaction id.
    template<typename EventContent>
    void send_to_device(
      const std::string &txid,
      const std::map<sdn::identifiers::User, std::map<std::string, EventContent>> &messages,
      ErrCallback callback);

    //! Resolve the specified roomalias to a roomid.
    void resolve_room_alias(const std::string &alias, Callback<sdn::responses::RoomId> cb);
    //! Add an alias to a room.
    void add_room_alias(const std::string &alias, const std::string &roomid, ErrCallback cb);
    //! Delete an alias from a room.
    void delete_room_alias(const std::string &alias, ErrCallback cb);
    //! List the local aliases on the users server.
    void list_room_aliases(const std::string &room_id, Callback<sdn::responses::Aliases> cb);

    //! Gets the visibility of a given room on the server's public room directory.
    void get_room_visibility(const std::string &room_id,
                             Callback<sdn::responses::PublicRoomVisibility> cb);

    //! Sets the visibility of a given room in the server's public room directory.
    void put_room_visibility(const std::string &room_id,
                             const sdn::requests::PublicRoomVisibility &req,
                             ErrCallback cb);

    //! Lists the public rooms on the server. This API returns paginated responses.
    //! The rooms are ordered by the number of joined members, with the largest rooms first.
    void get_public_rooms(Callback<sdn::responses::PublicRooms> cb,
                          const std::string &server = "",
                          size_t limit              = 0,
                          const std::string &since  = "");

    //! Lists the public rooms on the server, with optional filter. POST Request.
    void post_public_rooms(const sdn::requests::PublicRooms &req,
                           Callback<sdn::responses::PublicRooms> cb,
                           const std::string &server = "");

    //! Paginates over the space tree in a depth-first manner to locate child rooms of a given
    //! space.
    void get_hierarchy(const std::string &room_id,
                       Callback<sdn::responses::HierarchyRooms> cb,
                       const std::string &from = "",
                       size_t limit            = 0,
                       size_t max_depth        = 0,
                       bool suggested_only     = false);

    //! summarize a room
    void get_summary(const std::string &room_id,
                     Callback<sdn::responses::PublicRoomsChunk> cb,
                     std::vector<std::string> vias = {});

    //
    // Device related endpoints.
    //

    //! List devices
    void query_devices(Callback<sdn::responses::QueryDevices> cb);

    //! Gets information on a single device, by device id.
    void get_device(const std::string &device_id, Callback<sdn::responses::Device> cb);

    //! Updates the display name of the given device id.
    void set_device_name(const std::string &device_id,
                         const std::string &display_name,
                         ErrCallback callback);

    //! Delete device
    void delete_device(const std::string &device_id, UIAHandler uia_handler, ErrCallback cb);

    //! Delete devices
    void delete_devices(const std::vector<std::string> &device_ids,
                        UIAHandler uia_handler,
                        ErrCallback cb);

    //
    // Encryption related endpoints.
    //

    //! Enable encryption in a room by sending a `m.room.encryption` state event.
    void enable_encryption(const std::string &room, Callback<sdn::responses::EventId> cb);

    //! Upload identity keys & one time keys.
    void upload_keys(const sdn::requests::UploadKeys &req, Callback<sdn::responses::UploadKeys> cb);

    //! Upload signatures for cross-signing keys
    void keys_signatures_upload(const sdn::requests::KeySignaturesUpload &req,
                                Callback<sdn::responses::KeySignaturesUpload> cb);

    //! Upload cross signing keys
    void device_signing_upload(const sdn::requests::DeviceSigningUpload &,
                               UIAHandler uia_handler,
                               ErrCallback cb);

    //! Returns the current devices and identity keys for the given users.
    void query_keys(const sdn::requests::QueryKeys &req, Callback<sdn::responses::QueryKeys> cb);

    /// @brief Claims one-time keys for use in pre-key messages.
    ///
    /// Pass in a map from userid to device_keys
    void claim_keys(const sdn::requests::ClaimKeys &req, Callback<sdn::responses::ClaimKeys> cb);

    /// @brief Gets a list of users who have updated their device identity keys since a previous
    /// sync token.
    void key_changes(const std::string &from,
                     const std::string &to,
                     Callback<sdn::responses::KeyChanges> cb);

    //
    // Key backup endpoints
    //
    void backup_version(Callback<sdn::responses::backup::BackupVersion> cb);
    void backup_version(const std::string &version,
                        Callback<sdn::responses::backup::BackupVersion> cb);
    void update_backup_version(const std::string &version,
                               const sdn::responses::backup::BackupVersion &data,
                               ErrCallback cb);
    void post_backup_version(const std::string &algorithm,
                             const std::string &auth_data,
                             Callback<sdn::responses::Version> cb);

    void room_keys(const std::string &version, Callback<sdn::responses::backup::KeysBackup> cb);
    void room_keys(const std::string &version,
                   const std::string &room_id,
                   Callback<sdn::responses::backup::RoomKeysBackup> cb);
    void room_keys(const std::string &version,
                   const std::string &room_id,
                   const std::string &session_id,
                   Callback<sdn::responses::backup::SessionBackup> cb);
    void put_room_keys(const std::string &version,
                       const sdn::responses::backup::KeysBackup &keys,
                       ErrCallback cb);
    void put_room_keys(const std::string &version,
                       const std::string &room_id,
                       const sdn::responses::backup::RoomKeysBackup &keys,
                       ErrCallback cb);
    void put_room_keys(const std::string &version,
                       const std::string &room_id,
                       const std::string &session_id,
                       const sdn::responses::backup::SessionBackup &keys,
                       ErrCallback cb);

    //
    // Secret storage endpoints
    //

    //! Retrieve a specific secret
    void secret_storage_secret(const std::string &secret_id,
                               Callback<sdn::secret_storage::Secret> cb);
    //! Retrieve information about a key
    void secret_storage_key(const std::string &key_id,
                            Callback<sdn::secret_storage::AesHmacSha2KeyDescription> cb);

    //! Upload a specific secret
    void upload_secret_storage_secret(const std::string &secret_id,
                                      const sdn::secret_storage::Secret &secret,
                                      ErrCallback cb);
    //! Upload information about a key
    void upload_secret_storage_key(const std::string &key_id,
                                   const sdn::secret_storage::AesHmacSha2KeyDescription &desc,
                                   ErrCallback cb);

    //! Set the default key for the secret storage
    void set_secret_storage_default_key(const std::string &key_id, ErrCallback cb);

    //! Gets any TURN server URIs and authentication credentials
    void get_turn_server(Callback<sdn::responses::TurnServer> cb);

    //! Sets, updates, or deletes a pusher
    void set_pusher(const sdn::requests::SetPusher &req, Callback<sdn::responses::Empty> cb);

    //! Searches the user directory
    void search_user_directory(const std::string &search_term,
                               Callback<sdn::responses::Users> callback,
                               int limit = -1);

private:
    template<class Request, class Response>
    void post(const std::string &endpoint,
              const Request &req,
              Callback<Response> cb,
              bool requires_auth              = true,
              const std::string &content_type = "application/json");

    // put function for the PUT HTTP requests that send responses
    template<class Request, class Response>
    void put(const std::string &endpoint,
             const Request &req,
             Callback<Response> cb,
             bool requires_auth = true);

    template<class Request>
    void put(const std::string &endpoint,
             const Request &req,
             ErrCallback cb,
             bool requires_auth = true);

    template<class Response>
    void get(const std::string &endpoint,
             HeadersCallback<Response> cb,
             bool requires_auth                    = true,
             const std::string &endpoint_namespace = "/_api",
             int num_redirects                     = 0);

    // type erased versions of http verbs
    void post(const std::string &endpoint,
              const std::string &req,
              TypeErasedCallback cb,
              bool requires_auth,
              const std::string &content_type);

    void put(const std::string &endpoint,
             const std::string &req,
             TypeErasedCallback cb,
             bool requires_auth);

    void get(const std::string &endpoint,
             TypeErasedCallback cb,
             bool requires_auth,
             const std::string &endpoint_namespace,
             int num_redirects = 0);

    void delete_(const std::string &endpoint, ErrCallback cb, bool requires_auth = true);

    coeurl::Headers prepare_headers(bool requires_auth);
    std::string endpoint_to_url(const std::string &endpoint,
                                const char *endpoint_namespace = "/_api");

    template<class Response>
    TypeErasedCallback prepare_callback(HeadersCallback<Response> callback);

    //! The protocol used, i.e. https or http
    std::string protocol_;
    //! The homeserver to connect to.
    std::string server_;
    //! The access token that would be used for authentication.
    std::string access_token_;
    //! The user ID associated with the client.
    sdn::identifiers::User user_id_;
    //! The device that this session is associated with.
    std::string device_id_;
    //! The token that will be used as the 'since' parameter on the next sync request.
    std::string next_batch_token_;
    //! The homeserver port to connect.
    uint16_t port_ = 443;

    std::unique_ptr<ClientPrivate> p;
};
}
}

// Template instantiations for the various send functions

#define SDNCLIENT_SEND_STATE_EVENT_FWD(Content)                                                    \
    extern template void sdn::http::Client::send_state_event<sdn::events::Content>(                \
      const std::string &,                                                                         \
      const std::string &state_key,                                                                \
      const sdn::events::Content &,                                                                \
      Callback<sdn::responses::EventId> cb);                                                       \
    extern template void sdn::http::Client::send_state_event<sdn::events::Content>(                \
      const std::string &, const sdn::events::Content &, Callback<sdn::responses::EventId> cb);

SDNCLIENT_SEND_STATE_EVENT_FWD(state::Aliases)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::Avatar)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::CanonicalAlias)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::Create)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::Encryption)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::GuestAccess)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::HistoryVisibility)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::JoinRules)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::Member)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::Name)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::PinnedEvents)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::PowerLevels)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::Tombstone)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::ServerAcl)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::Topic)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::Widget)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::policy_rule::UserRule)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::policy_rule::RoomRule)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::policy_rule::ServerRule)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::space::Child)
SDNCLIENT_SEND_STATE_EVENT_FWD(state::space::Parent)
SDNCLIENT_SEND_STATE_EVENT_FWD(msc2545::ImagePack)

#define SDNCLIENT_SEND_ROOM_MESSAGE_FWD(Content)                                                   \
    extern template void sdn::http::Client::send_room_message<Content>(                            \
      const std::string &,                                                                         \
      const std::string &,                                                                         \
      const Content &,                                                                             \
      Callback<sdn::responses::EventId> cb);                                                       \
    extern template void sdn::http::Client::send_room_message<Content>(                            \
      const std::string &, const Content &, Callback<sdn::responses::EventId> cb);

SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::Encrypted)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::StickerImage)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::Reaction)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::Audio)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::Emote)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::File)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::Image)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::Notice)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::Text)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::Video)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::msg::ElementEffect)
// SDNCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationRequest)
// SDNCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationStart)
// SDNCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationReady)
// SDNCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationDone)
// SDNCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationAccept)
// SDNCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationCancel)
// SDNCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationKey)
// SDNCLIENT_SEND_ROOM_MESSAGE(sdn::events::msg::KeyVerificationMac)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::voip::CallInvite)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::voip::CallCandidates)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::voip::CallAnswer)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::voip::CallHangUp)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::voip::CallSelectAnswer)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::voip::CallReject)
SDNCLIENT_SEND_ROOM_MESSAGE_FWD(sdn::events::voip::CallNegotiate)

#define SDNCLIENT_SEND_TO_DEVICE_FWD(Content)                                                      \
    extern template void sdn::http::Client::send_to_device<Content>(                               \
      const std::string &txid,                                                                     \
      const std::map<sdn::identifiers::User, std::map<std::string, Content>> &messages,            \
      ErrCallback callback);

SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::RoomKey)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::ForwardedRoomKey)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::KeyRequest)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::OlmEncrypted)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::Encrypted)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::Dummy)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::KeyVerificationRequest)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::KeyVerificationStart)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::KeyVerificationReady)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::KeyVerificationDone)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::KeyVerificationAccept)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::KeyVerificationCancel)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::KeyVerificationKey)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::KeyVerificationMac)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::SecretSend)
SDNCLIENT_SEND_TO_DEVICE_FWD(sdn::events::msg::SecretRequest)

#define SDNCLIENT_ACCOUNT_DATA_FWD(Payload)                                                        \
    extern template void sdn::http::Client::put_room_account_data<Payload>(                        \
      const std::string &room_id,                                                                  \
      const std::string &type,                                                                     \
      const Payload &payload,                                                                      \
      ErrCallback cb);                                                                             \
    extern template void sdn::http::Client::put_room_account_data<Payload>(                        \
      const std::string &room_id, const Payload &payload, ErrCallback cb);                         \
    extern template void sdn::http::Client::put_account_data<Payload>(                             \
      const std::string &type, const Payload &payload, ErrCallback cb);                            \
    extern template void sdn::http::Client::put_account_data<Payload>(const Payload &payload,      \
                                                                      ErrCallback cb);             \
    extern template void sdn::http::Client::get_room_account_data<Payload>(                        \
      const std::string &room_id, const std::string &type, Callback<Payload> payload);             \
    extern template void sdn::http::Client::get_room_account_data<Payload>(                        \
      const std::string &room_id, Callback<Payload> cb);                                           \
    extern template void sdn::http::Client::get_account_data<Payload>(const std::string &type,     \
                                                                      Callback<Payload> payload);  \
    extern template void sdn::http::Client::get_account_data<Payload>(Callback<Payload> cb);

SDNCLIENT_ACCOUNT_DATA_FWD(sdn::events::msc2545::ImagePack)
SDNCLIENT_ACCOUNT_DATA_FWD(sdn::events::msc2545::ImagePackRooms)
SDNCLIENT_ACCOUNT_DATA_FWD(sdn::events::account_data::nheko_extensions::HiddenEvents)
SDNCLIENT_ACCOUNT_DATA_FWD(sdn::events::account_data::nheko_extensions::EventExpiry)
SDNCLIENT_ACCOUNT_DATA_FWD(sdn::events::account_data::Tags)
SDNCLIENT_ACCOUNT_DATA_FWD(sdn::events::account_data::Direct)
