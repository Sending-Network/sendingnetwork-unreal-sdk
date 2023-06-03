/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <filesystem>

#include <lager/constant.hpp>

#include "client.hpp"

namespace Kazv
{
    Client::Client(lager::reader<SdkModel> sdk,
                   ContextT ctx, std::nullopt_t)
        : m_sdk(sdk)
        , m_client(sdk.map(&SdkModel::c))
        , m_ctx(std::move(ctx))
    {
    }

    Client::Client(lager::reader<SdkModel> sdk,
                   ContextWithDepsT ctx)
        : m_sdk(sdk)
        , m_client(sdk.map(&SdkModel::c))
        , m_ctx(ctx)
        , m_deps(std::move(ctx))
    {
    }

    Client::Client(InEventLoopTag,
                   ContextWithDepsT ctx)
        : m_sdk(std::nullopt)
        , m_client(std::nullopt)
        , m_ctx(ctx)
        , m_deps(std::move(ctx))
#ifdef KAZV_USE_THREAD_SAFETY_HELPER
        , KAZV_ON_EVENT_LOOP_VAR(true)
#endif
    {
    }

    Client::Client(InEventLoopTag,
                   ContextT ctx, DepsT deps)
        : m_sdk(std::nullopt)
        , m_client(std::nullopt)
        , m_ctx(std::move(ctx))
        , m_deps(std::move(deps))
#ifdef KAZV_USE_THREAD_SAFETY_HELPER
        , KAZV_ON_EVENT_LOOP_VAR(true)
#endif
    {
    }


    Client Client::toEventLoop() const
    {
        return Client(InEventLoopTag{}, m_ctx, m_deps.value());
    }


    Room Client::room(std::string id) const
    {
        if (m_deps.has_value()) {
            return Room(sdkCursor(), lager::make_constant(id), m_ctx, m_deps.value());
        } else {
            return Room(sdkCursor(), lager::make_constant(id), m_ctx);
        }
    }

    Room Client::roomByCursor(lager::reader<std::string> id) const
    {
        if (m_deps.has_value()) {
            return Room(sdkCursor(), id, m_ctx, m_deps.value());
        } else {
            return Room(sdkCursor(), id, m_ctx);
        }
    }

    auto Client::passwordLogin(std::string node, std::string username,
                               std::string password, std::string deviceName) const
        -> PromiseT
    {
        auto p1 = m_ctx.dispatch(LoginAction{
                node, username, password, deviceName});
        p1
            .then([that=toEventLoop()](auto stat) {
                      if (! stat.success()) {
                          return;
                      }
                      // It is meaningless to wait for it in a Promise
                      // that is never exposed to the user.
                      that.startSyncing();
                  });

        return p1;
    }

    auto Client::tokenLogin(std::string node, std::string username,
                            std::string token, std::string deviceId) const
        -> PromiseT
    {
        auto p1 = m_ctx.dispatch(TokenLoginAction{
                node, username, token, deviceId});
        p1
            .then([that=toEventLoop()](auto stat) {
                      if (! stat.success()) {
                          return;
                      }
                      that.startSyncing();
                  });

        return p1;
    }

    auto Client::autoDiscover(std::string userId) const
        -> PromiseT
    {
        return m_ctx.dispatch(GetWellknownAction{userId})
            .then([that=toEventLoop()](auto stat) {
                      if (!stat.success()) {
                          return that.m_ctx.createResolvedPromise(stat);
                      }
                      return that.m_ctx.dispatch(GetVersionsAction{stat.dataStr("nodeUrl")})
                          .then([that, stat](auto stat2) {
                              if (!stat2.success()) {
                                  return stat2;
                              } else {
                                  return stat;
                              }
                          });
                  });
    }

    auto Client::createRoom(RoomVisibility v,
                            std::optional<std::string> name,
                            std::optional<std::string> alias,
                            immer::array<std::string> invite,
                            std::optional<bool> isDirect,
                            bool allowFederate,
                            std::optional<std::string> topic,
                            JsonWrap powerLevelContentOverride) const
        -> PromiseT
    {
        CreateRoomAction a;
        a.visibility = v;
        a.name = name;
        a.roomAliasName = alias;
        a.invite = invite;
        a.isDirect = isDirect;
        a.topic = topic;
        a.powerLevelContentOverride = powerLevelContentOverride;
        // Synapse won't buy it if we do not provide
        // a creationContent object.
        a.creationContent = json{
            {"m.federate", allowFederate}
        };
        return m_ctx.dispatch(std::move(a));
    }

    auto Client::joinRoomById(std::string roomId) const -> PromiseT
    {
        return m_ctx.dispatch(JoinRoomByIdAction{roomId});
    }

    auto Client::joinRoom(std::string roomId, immer::array<std::string> serverName) const
        -> PromiseT
    {
        return m_ctx.dispatch(JoinRoomAction{roomId, serverName});
    }

    auto Client::uploadContent(immer::box<Bytes> content,
                              std::string uploadId,
                              std::optional<std::string> filename,
                              std::optional<std::string> contentType) const
        -> PromiseT
    {
        return m_ctx.dispatch(UploadContentAction{
                FileDesc(FileContent{content.get().begin(), content.get().end()}),
                filename, contentType, uploadId});
    }

    auto Client::uploadContent(FileDesc file) const
        -> PromiseT
    {
        auto basename = file.name()
            ? std::optional(std::filesystem::path(file.name().value()).filename().native())
            : std::nullopt;
        return m_ctx.dispatch(UploadContentAction{
                file,
                // use only basename to prevent path info being leaked
                basename,
                file.contentType(),
                // uploadId unused
                std::string{}});
    }

    auto Client::downloadContent(std::string mxcUri, std::optional<FileDesc> downloadTo) const
        -> PromiseT
    {
        return m_ctx.dispatch(DownloadContentAction{mxcUri, downloadTo});
    }

    auto Client::downloadThumbnail(
        std::string mxcUri,
        int width,
        int height,
        std::optional<ThumbnailResizingMethod> method,
        std::optional<FileDesc> downloadTo) const
        -> PromiseT
    {
        return m_ctx.dispatch(DownloadThumbnailAction{mxcUri, width, height, method, std::nullopt, downloadTo});
    }

    auto Client::startSyncing() const -> PromiseT
    {
        KAZV_VERIFY_THREAD_ID();
        using namespace Kazv::CursorOp;

        if (+syncing()) {
            return m_ctx.createResolvedPromise(true);
        }

        auto p1 = m_ctx.createResolvedPromise(true)
            .then([that=toEventLoop()](auto) {
                      // post filters, if filters are incomplete
                      if ((+that.clientCursor()[&ClientModel::initialSyncFilterId]).empty()
                          || (+that.clientCursor()[&ClientModel::incrementalSyncFilterId]).empty()) {
                          return that.m_ctx.dispatch(PostInitialFiltersAction{});
                      }
                      return that.m_ctx.createResolvedPromise(true);
                  })
            .then([that=toEventLoop()](auto stat) {
                      if (! stat.success()) {
                          return that.m_ctx.createResolvedPromise(stat);
                      }
                      // Upload identity keys if we need to
                      if (+that.clientCursor()[&ClientModel::crypto]
                          && ! +that.clientCursor()[&ClientModel::identityKeysUploaded]) {
                          return that.m_ctx.dispatch(UploadIdentityKeysAction{});
                      } else {
                          return that.m_ctx.createResolvedPromise(true);
                      }
                  });

        p1
            .then([m_ctx=m_ctx](auto stat) {
                      m_ctx.dispatch(SetShouldSyncAction{true});
                      return stat;
                  })
            .then([that=toEventLoop()](auto stat) {
                      if (stat.success()) {
                          that.syncForever();
                      }
                  });

        return p1;
    }

    auto Client::syncForever(std::optional<int> retryTime) const -> void
    {
        KAZV_VERIFY_THREAD_ID();

        // assert (m_deps);
        using namespace CursorOp;

        bool isInitialSync = ! (+clientCursor()[&ClientModel::syncToken]).has_value();

        bool shouldSync = +clientCursor()[&ClientModel::shouldSync];

        if (! shouldSync) {
            return;
        }
        //

        auto syncRes = m_ctx.dispatch(SyncAction{});

        auto uploadOneTimeKeysRes = syncRes
            .then([that=toEventLoop()](auto stat) {
                      if (! stat.success()) {
                          return that.m_ctx.createResolvedPromise(stat);
                      }
                      auto &rg = lager::get<RandomInterface &>(that.m_deps.value());
                      bool hasCrypto{+that.clientCursor()[&ClientModel::crypto]};
                      if (! hasCrypto) {
                          return that.m_ctx.createResolvedPromise(true);
                      }
                      auto numKeysToGenerate = (+that.clientCursor()).numOneTimeKeysNeeded();
                      return that.m_ctx.dispatch(GenerateAndUploadOneTimeKeysAction{
                              numKeysToGenerate,
                              rg.generateRange<RandomData>(GenerateAndUploadOneTimeKeysAction::randomSize(numKeysToGenerate))
                          });
                  });

        auto queryKeysRes = syncRes
            .then([that=toEventLoop(), isInitialSync](auto stat) {
                      if (! stat.success()) {
                          return that.m_ctx.createResolvedPromise(stat);
                      }
                      bool hasCrypto{+that.clientCursor()[&ClientModel::crypto]};
                      return hasCrypto
                          ? that.m_ctx.dispatch(QueryKeysAction{isInitialSync})
                          : that.m_ctx.createResolvedPromise(true);
                  });

        m_ctx.promiseInterface()
            .all(std::vector<PromiseT>{uploadOneTimeKeysRes, queryKeysRes})
            .then([that=toEventLoop(), retryTime](auto stat) {
                      if (stat.success()) {
                          that.syncForever(); // reset retry time
                      } else {
                          auto firstRetryTime = +that.clientCursor()[&ClientModel::firstRetryMs];
                          auto retryTimeFactor = +that.clientCursor()[&ClientModel::retryTimeFactor];
                          auto maxRetryTime = +that.clientCursor()[&ClientModel::maxRetryMs];
                          auto curRetryTime = retryTime ? retryTime.value() : firstRetryTime;
                          if (curRetryTime > maxRetryTime) { curRetryTime = maxRetryTime; }
                          auto nextRetryTime = curRetryTime * retryTimeFactor;

                          kzo.client.warn() << "Sync failed, retrying in " << curRetryTime << "ms" << std::endl;
                          auto &jh = getJobHandler(that.m_deps.value());
                          jh.setTimeout([that=that.toEventLoop(), nextRetryTime]() { that.syncForever(nextRetryTime); },
                                        curRetryTime);
                      }
                  });
    }

    void Client::stopSyncing() const
    {
        m_ctx.dispatch(SetShouldSyncAction{false});
    }

    lager::reader<ClientModel> Client::clientCursor() const
    {
        KAZV_VERIFY_THREAD_ID();

        if (m_client.has_value()) {
            return m_client.value();
        } else {
            assert(m_deps.has_value());
            return lager::get<SdkModelCursorKey>(m_deps.value())->map(&SdkModel::c);
        }
    }

    const lager::reader<SdkModel> &Client::sdkCursor() const
    {
        KAZV_VERIFY_THREAD_ID();

        if (m_sdk.has_value()) {
            return m_sdk.value();
        } else {
            assert(m_deps.has_value());
            return *(lager::get<SdkModelCursorKey>(m_deps.value()));
        }
    }

    auto Client::getProfile(std::string userId) const -> PromiseT
    {
        return m_ctx.dispatch(GetUserProfileAction{userId});
    }

    auto Client::setAvatarUrl(std::optional<std::string> avatarUrl) const -> PromiseT
    {
        return m_ctx.dispatch(SetAvatarUrlAction{avatarUrl});
    }

    auto Client::setDisplayName(std::optional<std::string> displayName) const -> PromiseT
    {
        return m_ctx.dispatch(SetDisplayNameAction{displayName});
    }
}
