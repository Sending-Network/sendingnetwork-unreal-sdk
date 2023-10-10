#pragma once

#include "CoreMinimal.h"
#include "ChatSession.generated.h"

USTRUCT(BlueprintType)
struct FChatSession
{
    GENERATED_BODY()

    FChatSession() : Server(""), UserId(""), DeviceId(""), AccessToken(""), NextBatchToken("")
    {
    }

    FChatSession(const FString& InServer, const FString& InUserId, const FString& InDeviceId, const FString& InAccessToken, const FString& InNextBatchToken) :
    Server(InServer), UserId(InUserId), DeviceId(InDeviceId), AccessToken(InAccessToken), NextBatchToken(InNextBatchToken)
    {
    }

    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString Server;

    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString UserId;

    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString DeviceId;

    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString AccessToken;

    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString NextBatchToken;
};
