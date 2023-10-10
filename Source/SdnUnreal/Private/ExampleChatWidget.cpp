// Fill out your copyright notice in the Description page of Project Settings.


#include "ExampleChatWidget.h"
#include "HttpModule.h"
#include "Interfaces/IHttpRequest.h"
#include "Interfaces/IHttpResponse.h"

#define UI UI_ST
THIRD_PARTY_INCLUDES_START
#include "sdn.hpp"
#include "sdnclient/utils.hpp"
#include "sdnclient/crypto/ecdsa.hpp"
THIRD_PARTY_INCLUDES_END
#undef UI

using TimelineEvent = sdn::events::collections::TimelineEvents;
using namespace sdn::client;
using namespace sdn::http;
using namespace sdn::identifiers;
using namespace sdn::events;

void PrintLog(const std::string &Message) {
    const FString MessageString(Message.c_str());
    UE_LOG(LogTemp, Display, TEXT("%s"), *MessageString);
}

void PrintErr(RequestErr Err) {
    if (Err->status_code)
        UE_LOG(LogTemp, Display, TEXT("status_code: %d"), Err->status_code);
    if (!Err->sdn_error.error.empty())
    {
        PrintLog(Err->sdn_error.error);
    }
    if (Err->error_code)
        UE_LOG(LogTemp, Display, TEXT("error_code: %d"), Err->error_code);
}

// Check if the given event has a textual representation.
bool IsRoomMessage(const TimelineEvent &e) {
    return (std::holds_alternative<RoomEvent<msg::Audio>>(e)) ||
           (std::holds_alternative<RoomEvent<msg::Emote>>(e)) ||
           (std::holds_alternative<RoomEvent<msg::File>>(e)) ||
           (std::holds_alternative<RoomEvent<msg::Image>>(e)) ||
           (std::holds_alternative<RoomEvent<msg::Notice>>(e)) ||
           (std::holds_alternative<RoomEvent<msg::Text>>(e)) ||
           (std::holds_alternative<RoomEvent<msg::Video>>(e));
}

// Retrieves the fallback body value from the event.
std::string GetBody(const TimelineEvent &e) {
    if (const auto ev = std::get_if<RoomEvent<msg::Audio>>(&e); ev != nullptr)
        return ev->content.body;
    if (const auto ev = std::get_if<RoomEvent<msg::Emote>>(&e); ev != nullptr)
        return ev->content.body;
    if (const auto ev = std::get_if<RoomEvent<msg::File>>(&e); ev != nullptr)
        return ev->content.body;
    if (const auto ev = std::get_if<RoomEvent<msg::Image>>(&e); ev != nullptr)
        return ev->content.body;
    if (const auto ev = std::get_if<RoomEvent<msg::Notice>>(&e); ev != nullptr)
        return ev->content.body;
    if (const auto ev = std::get_if<RoomEvent<msg::Text>>(&e); ev != nullptr)
        return ev->content.body;
    if (const auto ev = std::get_if<RoomEvent<msg::Video>>(&e); ev != nullptr)
        return ev->content.body;

    return "";
}

// Retrieves the sender of the event.
std::string GetSender(const TimelineEvent &event) {
    return std::visit([](const auto &e) { return e.sender; }, event);
}

bool UExampleChatWidget::Login(FString Server, FString Address, FString Key)
{
    this->client = std::make_shared<Client>(TCHAR_TO_UTF8(*Server));
    this->WalletAddress = TCHAR_TO_UTF8(*Address);
    this->WalletKey = TCHAR_TO_UTF8(*Key);
    this->client->pre_login(this->WalletAddress, std::bind(&UExampleChatWidget::PreLoginHandler, this, std::placeholders::_1, std::placeholders::_2));
    return true;
}

void UExampleChatWidget::LoadSession(const FChatSession &Session)
{
    this->client = std::make_shared<Client>(TCHAR_TO_UTF8(*Session.Server));
    this->client->set_user(parse<User>(TCHAR_TO_UTF8(*Session.UserId)));
    this->client->set_device_id(TCHAR_TO_UTF8(*Session.DeviceId));
    this->client->set_access_token(TCHAR_TO_UTF8(*Session.AccessToken));
    this->client->set_next_batch_token(TCHAR_TO_UTF8(*Session.NextBatchToken));
}

void
UExampleChatWidget::StartSync()
{
    SyncOpts opts;
    opts.timeout = 0;
    client->sync(opts, std::bind(&UExampleChatWidget::SyncHandler, this, std::placeholders::_1, std::placeholders::_2));
}

void UExampleChatWidget::Shutdown()
{
    if(client) {
        client->shutdown();
    }
}

bool UExampleChatWidget::SendMessage(FString RoomId, FString Message)
{
    msg::Text text;
    text.body = TCHAR_TO_UTF8(*Message);
    const std::string roomId = TCHAR_TO_UTF8(*RoomId);

    client->send_room_message<msg::Text>(
      roomId, text, [roomId](const sdn::responses::EventId &, RequestErr e) {
          if (e) {
              PrintErr(e);
              return;
          }
          PrintLog("sent message to " + roomId);
      });
    return true;
}

void UExampleChatWidget::PreLoginHandler(const sdn::responses::PreLogin &Resp, RequestErr Err)
{
    if (Err) {
        PrintErr(Err);
        return;
    }
    const std::string Address = this->WalletAddress;
    const std::string Key = this->WalletKey;
    std::string MsgSig;
    if (!sdn::crypto::hash_and_sign(Key, Resp.message, MsgSig)) {
        PrintLog("sign message error");
        return;
    }

    const TSharedPtr<FJsonObject> RequestObject = MakeShareable(new FJsonObject);
    RequestObject->SetStringField("message", FString(Resp.message.c_str()));
    FString RequestString;
    const TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&RequestString);
    FJsonSerializer::Serialize(RequestObject.ToSharedRef(), Writer);
    FHttpModule& HttpModule = FHttpModule::Get();
    const TSharedRef<IHttpRequest, ESPMode::ThreadSafe> Request = HttpModule.CreateRequest();
    Request->SetVerb("POST");
    Request->SetContentAsString(RequestString);
    Request->SetURL("https://rewards.sending.network/_api/appservice/sign");
    Request->OnProcessRequestComplete().BindLambda([this, Resp, MsgSig](
            FHttpRequestPtr pRequest,
            FHttpResponsePtr pResponse,
            bool connectedSuccessfully) mutable {
        if (connectedSuccessfully) {
            const auto ResponseString = pResponse->GetContentAsString();
            if (pResponse->GetResponseCode() != 200) {
                UE_LOG(LogTemp, Display, TEXT("request signature fail: %d, %s"), pResponse->GetResponseCode(), *ResponseString);
                return;
            }
            const TSharedRef<TJsonReader<TCHAR>> JsonReader = TJsonReaderFactory<TCHAR>::Create(ResponseString);
            TSharedPtr<FJsonObject> Out;
            FJsonSerializer::Deserialize(JsonReader, Out);
            const auto DeveloperKeySignature = Out->GetStringField("signature");
            UE_LOG(LogTemp, Display, TEXT("developer key signature: %s"), *DeveloperKeySignature);
            UE_LOG(LogTemp, Display, TEXT("IsInGameThread: %s"), IsInGameThread() ? *FString("true") : *FString("false"));

            sdn::requests::login_identifier::DID did_identifier;
            did_identifier.address = this->WalletAddress;
            did_identifier.did = Resp.did;
            did_identifier.message = Resp.message;
            did_identifier.token = MsgSig;
            did_identifier.app_token = TCHAR_TO_UTF8(*DeveloperKeySignature);

            sdn::requests::Login login_req;
            login_req.random_server = Resp.random_server;
            login_req.updated = Resp.updated;
            login_req.device_id = "sdn-cpp-sdk";
            login_req.identifier = did_identifier;

            client->login(login_req, std::bind(&UExampleChatWidget::LoginHandler, this, std::placeholders::_1, std::placeholders::_2));
        }
    });
    Request->ProcessRequest();
}

void UExampleChatWidget::LoginHandler(const sdn::responses::Login &Resp, RequestErr Err)
{
    if (Err) {
        PrintErr(Err);
        return;
    }
    const FChatSession Session(
        FString(client->server().c_str()),
        FString(client->user_id().to_string().c_str()),
        FString(client->device_id().c_str()),
        FString(client->access_token().c_str()),
        "");
    AsyncTask(ENamedThreads::GameThread, [this, Session] () {
        this->OnLoginSuccess(Session);
    });
    PrintLog("user_id: " + client->user_id().to_string());
    PrintLog("device_id: " + client->device_id());
    PrintLog("access_token: " + client->access_token());
    SyncOpts opts;
    opts.timeout = 0;
    client->sync(opts, std::bind(&UExampleChatWidget::SyncHandler, this, std::placeholders::_1, std::placeholders::_2));
}

void UExampleChatWidget::SyncHandler(const sdn::responses::Sync &Res, RequestErr Err)
{
    PrintLog("Sync returned.");
    if (Err) {
        PrintErr(Err);
        return;
    }

    ParseMessages(Res);
    AsyncTask(ENamedThreads::GameThread, [this] () {
        this->OnSyncUpdated();
    });

    SyncOpts opts;
    opts.since = Res.next_batch;
    client->set_next_batch_token(Res.next_batch);
    client->sync(opts, std::bind(&UExampleChatWidget::SyncHandler, this, std::placeholders::_1, std::placeholders::_2));
}

void UExampleChatWidget::ParseMessages(const sdn::responses::Sync &Res)
{
    for (const auto &room : Res.rooms.invite) {
        auto room_id = room.first;
        PrintLog("joining room %s" + room_id);
        client->join_room(room_id, [room_id](const sdn::responses::RoomId &obj, RequestErr e) {
            if (e) {
                PrintErr(e);
                PrintLog("failed to join room %s" + room_id);
                return;
            }
            PrintLog("joined room " + obj.room_id);
        });
    }

    const auto UserId = client->user_id().to_string();
    for (const auto &room : Res.rooms.join) {
        auto room_id = room.first;
        PrintLog("room id: " + room_id);
        for (const auto &e : room.second.state.events) {
            if (const auto ev = std::get_if<StateEvent<state::Member>>(&e); ev != nullptr) {
                auto member_name = ev->content.display_name;
                if (member_name.empty()) {
                    member_name = ev->state_key;
                }
                if (ev->content.membership == state::Membership::Join) {
                    auto Profile = NewObject<UUserProfile>();
                    Profile->UserId = ev->state_key.c_str();
                    Profile->DisplayName = member_name.c_str();
                    Profile->AvatarUrl = ev->content.avatar_url.c_str();
                    // auto Profile = UUserProfile(ev->state_key.c_str(), member_name.c_str(), ev->content.avatar_url.c_str());
                    this->RoomMembers.Add(ev->state_key.c_str(), Profile);
                }
            }
        }
        for (const auto &e : room.second.timeline.events) {
            if (const auto ev = std::get_if<StateEvent<state::Member>>(&e); ev != nullptr) {
                auto member_name = ev->content.display_name;
                if (member_name.empty()) {
                    member_name = ev->state_key;
                }
                if (ev->content.membership == state::Membership::Join) {
                    auto Profile = NewObject<UUserProfile>();
                    Profile->UserId = ev->state_key.c_str();
                    Profile->DisplayName = member_name.c_str();
                    Profile->AvatarUrl = ev->content.avatar_url.c_str();
                    // auto Profile = UUserProfile(ev->state_key.c_str(), member_name.c_str(), ev->content.avatar_url.c_str());
                    this->RoomMembers.Add(ev->state_key.c_str(), Profile);
                }
                continue;
            }
            if (!IsRoomMessage(e))
                continue;
            auto Sender = GetSender(e);
            auto Body = GetBody(e);
            PrintLog("received message: " + Body);
            auto Event = NewObject<URoomEvent>();
            Event->SenderId = Sender.c_str();
            Event->Content = Body.c_str();
            RoomEvents.Add(Event);
        }
    }
}

void UExampleChatWidget::UpdateEventSenderName()
{
    for (const auto Event : RoomEvents) {
        UUserProfile* Member = RoomMembers.FindRef(Event->SenderId);
        Event->SenderName = Member->DisplayName;
    }
}

void UExampleChatWidget::OnLoginSuccess_Implementation(const FChatSession &Session)
{
}

void UExampleChatWidget::OnSyncUpdated_Implementation()
{
}
