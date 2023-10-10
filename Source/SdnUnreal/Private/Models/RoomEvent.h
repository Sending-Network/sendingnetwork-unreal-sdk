// Fill out your copyright notice in the Description page of Project Settings.

#pragma once

#include "CoreMinimal.h"
#include "UserProfile.h"
#include "UObject/NoExportTypes.h"
#include "RoomEvent.generated.h"

/**
 * 
 */
UCLASS(BlueprintType)
class URoomEvent : public UObject
{
    GENERATED_BODY()

public:
    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString SenderId;

    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString SenderName;

    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString Content;

};
