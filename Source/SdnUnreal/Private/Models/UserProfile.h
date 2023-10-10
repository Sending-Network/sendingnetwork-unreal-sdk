// Fill out your copyright notice in the Description page of Project Settings.

#pragma once

#include "CoreMinimal.h"
#include "UObject/NoExportTypes.h"
#include "UserProfile.generated.h"

/**
 * 
 */
UCLASS(BlueprintType)
class UUserProfile : public UObject
{
    GENERATED_BODY()

public:
    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString UserId;

    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString DisplayName;

    UPROPERTY(BlueprintReadWrite, EditAnywhere)
    FString AvatarUrl;
};
