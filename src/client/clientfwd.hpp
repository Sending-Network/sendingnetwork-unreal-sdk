/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <tuple>
#include <variant>

#include <lager/context.hpp>
#include <context.hpp>

#include "room/room-model.hpp"

namespace Kazv
{
    using namespace Api;
    class JobInterface;
    class EventInterface;

    struct LoginAction;
    struct TokenLoginAction;
    struct LogoutAction;
    struct GetWellknownAction;
    struct GetVersionsAction;
    struct SyncAction;
    struct SetShouldSyncAction;
    struct PostInitialFiltersAction;
    struct PaginateTimelineAction;
    struct SendMessageAction;
    struct SendStateEventAction;
    struct CreateRoomAction;
    struct GetRoomStatesAction;
    struct GetStateEventAction;
    struct InviteToRoomAction;
    struct JoinRoomByIdAction;
    struct EmitKazvEventsAction;
    struct JoinRoomAction;
    struct LeaveRoomAction;
    struct ForgetRoomAction;
    struct KickAction;
    struct BanAction;
    struct UnbanAction;

    struct ProcessResponseAction;
    struct SetTypingAction;
    struct PostReceiptAction;
    struct SetReadMarkerAction;

    struct UploadContentAction;
    struct DownloadContentAction;
    struct DownloadThumbnailAction;

    struct SendToDeviceMessageAction;

    struct UploadIdentityKeysAction;
    struct GenerateAndUploadOneTimeKeysAction;
    struct QueryKeysAction;
    struct ClaimKeysAction;
    struct EncryptMegOlmEventAction;
    struct EncryptOlmEventAction;

    struct GetUserProfileAction;
    struct SetAvatarUrlAction;
    struct SetDisplayNameAction;

    struct ResubmitJobAction;

    struct ClientModel;

    using ClientAction = std::variant<
        RoomListAction,

        LoginAction,
        TokenLoginAction,
        LogoutAction,
        GetWellknownAction,
        GetVersionsAction,

        SyncAction,
        SetShouldSyncAction,
        PostInitialFiltersAction,

        PaginateTimelineAction,
        SendMessageAction,
        SendStateEventAction,
        CreateRoomAction,
        GetRoomStatesAction,
        GetStateEventAction,
        InviteToRoomAction,
        JoinRoomByIdAction,

        JoinRoomAction,
        LeaveRoomAction,
        ForgetRoomAction,
        KickAction,
        BanAction,
        UnbanAction,

        ProcessResponseAction,

        SetTypingAction,
        PostReceiptAction,
        SetReadMarkerAction,

        UploadContentAction,
        DownloadContentAction,
        DownloadThumbnailAction,

        SendToDeviceMessageAction,

        UploadIdentityKeysAction,
        GenerateAndUploadOneTimeKeysAction,
        QueryKeysAction,
        ClaimKeysAction,
        EncryptMegOlmEventAction,
        EncryptOlmEventAction,

        GetUserProfileAction,
        SetAvatarUrlAction,
        SetDisplayNameAction,

        ResubmitJobAction
        >;

    using ClientEffect = Effect<ClientAction, lager::deps<>>;

    using ClientResult = std::pair<ClientModel, ClientEffect>;
}
