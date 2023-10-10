//
// Simple example bot that will accept any invite.
//

#include <unistd.h>
#include <iostream>
#include <variant>

#include "sdn.hpp"
#include "sdn/identifiers.hpp"
#include "sdnclient/crypto/ecdsa.hpp"
#include "sdnclient/http/client.hpp"
#include "sdnclient/http/errors.hpp"

using namespace std;
using namespace sdn::client;
using namespace sdn::http;
using namespace sdn::events;
using namespace sdn::identifiers;

using TimelineEvent = sdn::events::collections::TimelineEvents;

namespace {
std::shared_ptr<Client> client = nullptr;
const std::string wallet_address = "0x7347756Cbc4D39B90eDD5B92Dc1734C06e300350";
const std::string wallet_key = "a62519d208e90a1b9bce6c90a505132383a27de797fd210f64324bb003dc5236";
}

void
print_errors(RequestErr err)
{
    if (err->status_code)
        cout << err->status_code << "\n";
    if (!err->sdn_error.error.empty())
        cout << err->sdn_error.error << "\n";
    if (err->error_code)
        cout << err->error_code << "\n";
}

// Check if the given event has a textual representation.
bool
is_room_message(const TimelineEvent &e)
{
    return (std::holds_alternative<sdn::events::RoomEvent<msg::Audio>>(e)) ||
           (std::holds_alternative<sdn::events::RoomEvent<msg::Emote>>(e)) ||
           (std::holds_alternative<sdn::events::RoomEvent<msg::File>>(e)) ||
           (std::holds_alternative<sdn::events::RoomEvent<msg::Image>>(e)) ||
           (std::holds_alternative<sdn::events::RoomEvent<msg::Notice>>(e)) ||
           (std::holds_alternative<sdn::events::RoomEvent<msg::Text>>(e)) ||
           (std::holds_alternative<sdn::events::RoomEvent<msg::Video>>(e));
}

// Retrieves the fallback body value from the event.
std::string
get_body(const TimelineEvent &e)
{
    if (auto ev = std::get_if<RoomEvent<msg::Audio>>(&e); ev != nullptr)
        return ev->content.body;
    else if (auto ev = std::get_if<RoomEvent<msg::Emote>>(&e); ev != nullptr)
        return ev->content.body;
    else if (auto ev = std::get_if<RoomEvent<msg::File>>(&e); ev != nullptr)
        return ev->content.body;
    else if (auto ev = std::get_if<RoomEvent<msg::Image>>(&e); ev != nullptr)
        return ev->content.body;
    else if (auto ev = std::get_if<RoomEvent<msg::Notice>>(&e); ev != nullptr)
        return ev->content.body;
    else if (auto ev = std::get_if<RoomEvent<msg::Text>>(&e); ev != nullptr)
        return ev->content.body;
    else if (auto ev = std::get_if<RoomEvent<msg::Video>>(&e); ev != nullptr)
        return ev->content.body;

    return "";
}

// Retrieves the sender of the event.
std::string
get_sender(const TimelineEvent &event)
{
    return std::visit([](const auto &e) { return e.sender; }, event);
}

void
parse_messages(const sdn::responses::Sync &res, bool parse_repeat_cmd = false)
{
    for (const auto &room : res.rooms.invite) {
        auto room_id = room.first;

        printf("joining room %s\n", room_id.c_str());
        client->join_room(room_id, [room_id](const sdn::responses::RoomId &obj, RequestErr e) {
            if (e) {
                print_errors(e);
                printf("failed to join room %s\n", room_id.c_str());
                return;
            }

            printf("joined room \n%s\n", obj.room_id.c_str());

            sdn::events::msg::Text text;
            text.body = "Thanks for the invitation!";

            client->send_room_message<sdn::events::msg::Text>(
              room_id, text, [room_id](const sdn::responses::EventId &, RequestErr e) {
                  if (e) {
                      print_errors(e);
                      return;
                  }

                  printf("sent message to %s\n", room_id.c_str());
              });
        });
    }

    if (!parse_repeat_cmd)
        return;

    for (const auto &room : res.rooms.join) {
        const std::string repeat_cmd = "!repeat";
        const std::string room_id    = room.first;

        for (const auto &e : room.second.timeline.events) {
            if (!is_room_message(e))
                continue;

            auto body = get_body(e);
            if (body.find(repeat_cmd) != 0)
                continue;

            auto word = std::string(body.begin() + repeat_cmd.size(), body.end());
            auto user = get_sender(e);

            sdn::events::msg::Text text;
            text.body = user + ": " + word;

            client->send_room_message<sdn::events::msg::Text>(
              room_id, text, [room_id](const sdn::responses::EventId &, RequestErr e) {
                  if (e) {
                      print_errors(e);
                      return;
                  }

                  printf("sent message to %s\n", room_id.c_str());
              });
        }
    }
}

// Callback to executed after a /sync request completes.
void
sync_handler(const sdn::responses::Sync &res, RequestErr err)
{
    SyncOpts opts;

    if (err) {
        cout << "sync error:\n";
        print_errors(err);
        opts.since = client->next_batch_token();
        client->sync(opts, &sync_handler);
        return;
    }

    parse_messages(res, true);

    opts.since = res.next_batch;
    client->set_next_batch_token(res.next_batch);
    client->sync(opts, &sync_handler);
}

// Callback to executed after the first (initial) /sync request completes.
void
initial_sync_handler(const sdn::responses::Sync &res, RequestErr err)
{
    SyncOpts opts;

    if (err) {
        cout << "error during initial sync:\n";
        print_errors(err);

        if (err->status_code != 200) {
            cout << "retrying initial sync ...\n";
            opts.timeout = 0;
            client->sync(opts, &initial_sync_handler);
        }

        return;
    }

    parse_messages(res);

    opts.since = res.next_batch;
    client->set_next_batch_token(res.next_batch);
    client->sync(opts, &sync_handler);
}

void
login_handler(const sdn::responses::Login &, RequestErr err)
{
    if (err) {
        printf("login error\n");
        print_errors(err);
        return;
    }

    printf("user_id: %s\n", client->user_id().to_string().c_str());
    printf("device_id: %s\n", client->device_id().c_str());

    SyncOpts opts;
    opts.timeout = 0;
    client->sync(opts, &initial_sync_handler);
}

void
pre_login_handler(const sdn::responses::PreLogin &resp, RequestErr err)
{
    if (err) {
        printf("pre login error\n");
        print_errors(err);
        return;
    }

    std::string msg_sig;
    auto ret_val = sdn::crypto::hash_and_sign(wallet_key, resp.message, msg_sig);
    if (!ret_val) {
        printf("sign message error\n");
        return;
    }

    sdn::requests::login_identifier::DID did_identifier;
    did_identifier.address = wallet_address;
    did_identifier.did = resp.did;
    did_identifier.message = resp.message;
    did_identifier.token = msg_sig;

    sdn::requests::Login login_req;
    login_req.random_server = resp.random_server;
    login_req.updated = resp.updated;
    login_req.device_id = "sdn-cpp-sdk";
    login_req.identifier = did_identifier;


    client->login(login_req, login_handler);

    printf("did: %s\n", resp.did.c_str());
    printf("message: %s\n", resp.message.c_str());
    printf("random_server: %s\n", resp.random_server.c_str());
    printf("updated: %s\n", resp.updated.c_str());
    printf("signature: %s\n", msg_sig.c_str());
}

int
main()
{
    std::string server;

    cout << "server: ";
    std::getline(std::cin, server);

    client = std::make_shared<Client>(server);
    client->pre_login(wallet_address, pre_login_handler);
    client->close();

    return 0;
}
