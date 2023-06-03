/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <boost/algorithm/string.hpp>

#include "status-utils.hpp"

#include "content.hpp"

namespace Kazv
{
    std::pair<std::string, std::string> mxcUriToMediaDesc(std::string mxcUri)
    {
        using namespace boost::algorithm;

        if (mxcUri.find("mxc://") != 0) {
            return {"", ""};
        }

        mxcUri.erase(0, 6); // remove "mxc://"

        std::vector<std::string> a;
        split(a, mxcUri, is_any_of("/"));
        if (a.size() != 2) {
            return {"", ""};
        }
        return { a[0], a[1] };
    }

    ClientResult updateClient(ClientModel m, UploadContentAction a)
    {
        auto job = m.job<UploadContentJob>()
            .make(a.content, a.filename, a.contentType)
            .withData(json{ {"uploadId", a.uploadId} });
        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, UploadContentResponse r)
    {
        auto uploadId = r.dataStr("uploadId");
        if (! r.success()) {
            m.addTrigger(UploadContentFailed{uploadId, r.errorCode(), r.errorMessage()});
            return { std::move(m), failWithResponse(r) };
        }
        auto mxcUri = r.contentUri();
        m.addTrigger(UploadContentSuccessful{mxcUri, uploadId});
        return {
            std::move(m),
            [=](auto &&) {
                return EffectStatus{/* succ = */ true, json{{"mxcUri", mxcUri}}};
            }
        };
    }

    ClientResult updateClient(ClientModel m, DownloadContentAction a)
    {
        auto [serverName, mediaId] = mxcUriToMediaDesc(a.mxcUri);
        auto data = json{
            {"mxcUri", a.mxcUri},
            {"streaming", false},
        };
        if (a.downloadTo.has_value() && a.downloadTo.value().name().has_value()) {
            data["streaming"] = true;
        }
        auto job = m.job<GetContentJob>()
            .make(serverName, mediaId, /* allowRemote = */ true, a.downloadTo)
            .withData(std::move(data));
        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, GetContentResponse r)
    {
        auto mxcUri = r.dataStr("mxcUri");
        if (! r.success()) {
            return { std::move(m), failWithResponse(r) };
        }
        auto isStreaming = r.dataJson("streaming").template get<bool>();

        return {
            std::move(m),
            [=](auto &&) {
                auto data = json::object();
                if (! isStreaming) {
                    data["content"] = std::get<Bytes>(std::move(r).data());
                }
                return EffectStatus{/* succ = */ true, data};
            }
        };
    }

    ClientResult updateClient(ClientModel m, DownloadThumbnailAction a)
    {
        auto [serverName, mediaId] = mxcUriToMediaDesc(a.mxcUri);
        std::optional<std::string> method;
        if (a.method) {
            method = a.method.value() == Crop ? "crop" : "scale";
        }
        auto job = m.job<GetContentThumbnailJob>()
            .make(serverName, mediaId, a.width, a.height, method, /* allowRemote = */ true, a.downloadTo)
            .withData(json{ {"mxcUri", a.mxcUri},
                            {"streaming", a.downloadTo.has_value() && a.downloadTo.value().name().has_value()} });
        m.addJob(std::move(job));

        return { std::move(m), lager::noop };
    }

    ClientResult processResponse(ClientModel m, GetContentThumbnailResponse r)
    {
        auto mxcUri = r.dataStr("mxcUri");
        if (! r.success()) {
            return { std::move(m), failWithResponse(r) };
        }
        auto isStreaming = r.dataJson("streaming").template get<bool>();

        return {
            std::move(m),
            [=](auto &&) {
                auto data = json::object();
                if (! isStreaming) {
                    data["content"] = std::get<Bytes>(std::move(r).data());
                }
                return EffectStatus{/* succ = */ true, data};
            }
        };
    }

}
