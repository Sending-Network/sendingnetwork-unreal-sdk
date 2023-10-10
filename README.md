# SdnClient

Unreal plugin SDK for the SendingNetwork Protocol.

### Dependencies
- OpenSSL
- Coeurl (A C++ wrapper around curl.)
- nlohmann_json
- spdlog
- C++ 20 compiler
- CMake 3.15 or greater

## Setup
1. Copy directory `Plugins/SdnClient` into your UE5 project under `Plugins`
2. In your project file `.uproject`, add `SdnClient` as a plugin as follows
    ```
        "Plugins": [
            {
                "Name": "SdnClient",
                "Enabled": true
            }
        ]
    ```
3. In module build script `.Build.cs`, call the static function `SdnClient.AddDefault`
    ```
    SdnClient.AddDefault(Target, this);
    ```
Then you should be able to include header files and call functions from the sdk

## Basic Usage

### Login the Client
1. Create a `Client` object with a node server url. Call `pre_login` with a wallet address and a callback function.
    ```c++
    client = std::make_shared<Client>(server_url);
    client->pre_login(wallet_address, pre_login_handler);
    ```
2. The callback function receives a text message, and you need to sign it using wallet account key and developer key respectively. And then passing both two signatures to function `login`
    ```c++
    // fill parameters in a Login struct
    sdn::requests::Login login_req;
    client->login(login_req, login_handler);
    ```
    > Notice: You should manage the developer key in a backed server and provide an api to sign a message for clients.
3. If Login success, the callback function receives an access token, which is a required parameter to call other APIs.

### Create chat room and invite user
```c++
sdn::requests::CreateRoom create_room_req;
create_room_req.name="room name"
create_room_req.invite.emplace_back("user id");
client->create_room(create_room_req, callback_handler);
```

### Send messages
```c++
sdn::events::msg::Text text;
text.body = "hello";
const std::string roomId = "room id";

client->send_room_message<msg::Text>(
  roomId, text, [roomId](const sdn::responses::EventId &, RequestErr e) {
      // process send message result
  });
```

### Receive messages
```c++
void start_sync()
{
    SyncOpts opts;
    opts.timeout = 0;
    client->sync(opts, sync_handler);
}

void sync_handler(const sdn::responses::Sync &res, RequestErr err)
{
    // process received messages
    parse_messages(res);

    // start another sync
    opts.since = res.next_batch;
    client->set_next_batch_token(res.next_batch);
    client->sync(opts, &sync_handler);
}
```

## Example

In project `SdnUnreal`, we show you how to create a chat widget based on `SdnClient` Plugin. It's a basic example for developers who want to integrate in-game chat functions;