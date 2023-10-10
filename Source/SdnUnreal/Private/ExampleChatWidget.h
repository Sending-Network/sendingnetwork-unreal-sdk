// Fill out your copyright notice in the Description page of Project Settings.

#pragma once

#include <SdkSrc/include/sdnclient/http/client.hpp>

#include "CoreMinimal.h"
#include "Blueprint/UserWidget.h"
#include "Models/ChatSession.h"
#include "Models/RoomEvent.h"
#include "Models/UserProfile.h"
#include "ExampleChatWidget.generated.h"

/**
 * 
 */
UCLASS()
class SDNCLIENT_API UExampleChatWidget : public UUserWidget
{
    GENERATED_BODY()
private:
    std::shared_ptr<sdn::http::Client> client = nullptr;
    std::string WalletAddress;
    std::string WalletKey;

public:
    UPROPERTY(VisibleAnywhere, BlueprintReadOnly)
    TMap<FString, UUserProfile*> RoomMembers;

    UPROPERTY(VisibleAnywhere, BlueprintReadOnly)
    TArray<URoomEvent*> RoomEvents;

public:
    UFUNCTION(BlueprintCallable)
    bool Login(FString Server, FString Address, FString Key);

    UFUNCTION(BlueprintCallable)
    void LoadSession(const FChatSession &Session);

    UFUNCTION(BlueprintCallable)
    void StartSync();

    UFUNCTION(BlueprintCallable)
    void Shutdown();

    UFUNCTION(BlueprintCallable)
    bool SendMessage(FString RoomId, FString Message);

    UFUNCTION(BlueprintCallable, BlueprintNativeEvent)
    void OnLoginSuccess(const FChatSession &Session);

    UFUNCTION(BlueprintCallable, BlueprintNativeEvent)
    void OnSyncUpdated();

    UFUNCTION(BlueprintCallable)
    void UpdateEventSenderName();

public:
    void PreLoginHandler(const sdn::responses::PreLogin &Resp, sdn::http::RequestErr Err);
    void LoginHandler(const sdn::responses::Login &Resp, sdn::http::RequestErr Err);
    void SyncHandler(const sdn::responses::Sync &Res, sdn::http::RequestErr Err);
    void ParseMessages(const sdn::responses::Sync &Res);
};
