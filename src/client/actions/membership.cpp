/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <csapi/create_room.hpp>
#include <csapi/inviting.hpp>
#include <csapi/joining.hpp>
#include <debug.hpp>

#include "client-model.hpp"
#include "clientutil.hpp"
#include "cursorutil.hpp"
#include "status-utils.hpp"

#include "membership.hpp"

namespace Kazv
{
    static std::string visibilityToStr(CreateRoomAction::Visibility v)
    {
        using V = CreateRoomAction::Visibility;
        switch (v) {
        case V::Private:
            return "private";
        case V::Public:
            return "public";
        default:
            // should not happen
            return "";
        }
    }

    static std::string presetToStr(CreateRoomAction::Preset p)
    {
        using P = CreateRoomAction::Preset;
        switch (p) {
        case P::PrivateChat:
            return "private_chat";
        case P::PublicChat:
            return "public_chat";
        case P::TrustedPrivateChat:
            return "trusted_private_chat";
        default:
            // should not happen
            return "";
        }
    }

    ClientResult updateClient(ClientModel m, CreateRoomAction a)
    {
        auto visibility = visibilityToStr(a.visibility);
        std::optional<std::string> preset = a.preset
            ? std::optional<std::string>(presetToStr(a.preset.value()))
            : std::nullopt;

        using StateEvT = Kazv::CreateRoomJob::StateEvent;
        auto initialState = intoImmer(
            immer::array<StateEvT>{},
            zug::map(
                [](Event e) {
                    return StateEvT{e.type(), e.stateKey(), e.content()};
                }),
            a.initialState);

        auto job = m.job<CreateRoomJob>().make(
            visibility,
            a.roomAliasName,
            a.name,
            a.topic,
            a.invite,
            DEFVAL, // invite3pid, not supported yet
            a.roomVersion,
            a.creationContent,
            initialState,
            preset,
            a.isDirect,
            a.powerLevelContentOverride);

        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, CreateRoomResponse r)
    {
        if (! r.success()) {
            kzo.client.dbg() << "Create room failed" << std::endl;
            m.addTrigger(CreateRoomFailed{r.errorCode(), r.errorMessage()});
            return { std::move(m), failWithResponse(r) };
        }

        m.addTrigger(CreateRoomSuccessful{r.roomId()});
        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, InviteToRoomAction a)
    {
        auto job = m.job<InviteUserJob>()
            .make(a.roomId, a.userId)
            .withData(json{
                    {"roomId", a.roomId},
                    {"userId", a.userId},
                });
        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, InviteUserResponse r)
    {
        auto roomId = r.dataStr("roomId");
        auto userId = r.dataStr("userId");

        if (! r.success()) {
            // Error
            kzo.client.warn() << "Error inviting user " << r.errorCode() << r.errorMessage() << std::endl;

            m.addTrigger(InviteUserFailed{roomId, userId, r.errorCode(), r.errorMessage()});
            return { std::move(m), failWithResponse(r) };
        }

        kzo.client.info() << "Inviting user successful" << std::endl;
        m.addTrigger(InviteUserSuccessful{roomId, userId});
        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, JoinRoomAction a)
    {
        auto job = m.job<JoinRoomJob>()
            .make(a.roomIdOrAlias, a.serverName)
            .withData(json{{"roomIdOrAlias", a.roomIdOrAlias}});

        m.addJob(std::move(job));
        return { m, lager::noop };
    }

    ClientResult processResponse(ClientModel m, JoinRoomResponse r)
    {
        auto roomIdOrAlias = r.dataStr("roomIdOrAlias");
        if (! r.success()) {
            m.addTrigger(JoinRoomFailed{
                    roomIdOrAlias,
                    r.errorCode(),
                    r.errorMessage()
                });
            kzo.client.warn() << "Error joining room" << r.errorCode() << r.errorMessage() << std::endl;
            return { std::move(m), failWithResponse(r) };
        }

        kzo.client.info() << "Successfully joined room" << std::endl;
        m.addTrigger(JoinRoomSuccessful{roomIdOrAlias});
        return { std::move(m), lager::noop};
    }

    ClientResult updateClient(ClientModel m, JoinRoomByIdAction a)
    {
        auto job = m.job<JoinRoomByIdJob>()
            .make(a.roomId)
            .withData(json{{"roomIdOrAlias", a.roomId}});

        m.addJob(std::move(job));
        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, JoinRoomByIdResponse r)
    {
        auto roomIdOrAlias = r.dataStr("roomIdOrAlias");
        if (! r.success()) {
            m.addTrigger(JoinRoomFailed{
                    roomIdOrAlias,
                    r.errorCode(),
                    r.errorMessage()
                });

            kzo.client.warn() << "Error joining room" << r.errorCode() << r.errorMessage() << std::endl;
            return { std::move(m), failWithResponse(r) };
        }

        kzo.client.info() << "Successfully joined room" << std::endl;
        m.addTrigger(JoinRoomSuccessful{roomIdOrAlias});
        return { std::move(m), lager::noop};
    }

    ClientResult updateClient(ClientModel m, LeaveRoomAction a)
    {
        auto job = m.job<LeaveRoomJob>()
            .make(a.roomId)
            .withData(json{{"roomId", a.roomId}});

        m.addJob(std::move(job));
        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, LeaveRoomResponse r)
    {
        auto roomId = r.dataStr("roomId");
        if (! r.success()) {
            m.addTrigger(LeaveRoomFailed{
                    roomId,
                    r.errorCode(),
                    r.errorMessage()
                });
            kzo.client.warn() << "Error leaving room" << r.errorCode() << r.errorMessage() << std::endl;
            return { std::move(m), failWithResponse(r) };
        }

        kzo.client.info() << "Successfully left room" << std::endl;
        m.addTrigger(LeaveRoomSuccessful{roomId});
        return { std::move(m), lager::noop};
    }

    ClientResult updateClient(ClientModel m, ForgetRoomAction a)
    {
        auto job = m.job<ForgetRoomJob>()
            .make(a.roomId)
            .withData(json{{"roomId", a.roomId}});

        m.addJob(std::move(job));
        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, ForgetRoomResponse r)
    {
        auto roomId = r.dataStr("roomId");
        if (! r.success()) {
            m.addTrigger(ForgetRoomFailed{
                    roomId,
                    r.errorCode(),
                    r.errorMessage()
                });
            kzo.client.warn() << "Error forgetting room" << r.errorCode() << r.errorMessage() << std::endl;
            return { std::move(m), failWithResponse(r) };
        }

        kzo.client.info() << "Successfully forgot room" << std::endl;
        m.addTrigger(ForgetRoomSuccessful{roomId});
        return { std::move(m), lager::noop};
    }

    ClientResult updateClient(ClientModel m, KickAction a)
    {
        m.addJob(m.job<KickJob>().make(a.roomId, a.userId, a.reason));
        return { std::move(m), lager::noop };
    }
    ClientResult processResponse(ClientModel m, KickResponse r)
    {
        if (!r.success()) {
            kzo.client.warn() << "Error kicking" << r.errorCode() << r.errorMessage() << std::endl;
            return { std::move(m), failWithResponse(r) };
        }
        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, BanAction a)
    {
        m.addJob(m.job<BanJob>().make(a.roomId, a.userId, a.reason));
        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, BanResponse r)
    {
        if (!r.success()) {
            kzo.client.warn() << "Error banning" << r.errorCode() << r.errorMessage() << std::endl;
            return { std::move(m), failWithResponse(r) };
        }
        return { std::move(m), lager::noop };
    }

    ClientResult updateClient(ClientModel m, UnbanAction a)
    {
        m.addJob(m.job<UnbanJob>().make(a.roomId, a.userId));
        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, UnbanResponse r)
    {
        if (!r.success()) {
            kzo.client.warn() << "Error unbanning" << r.errorCode() << r.errorMessage() << std::endl;
            return { std::move(m), failWithResponse(r) };
        }
        return { std::move(m), lager::noop };
    }
};
