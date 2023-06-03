/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <libkazv-config.hpp>

#include <algorithm>
#include <deque>

#include <zug/into_vector.hpp>
#include <zug/transducer/map.hpp>

#include <cpr.h>
#include <callback.h>

#include <asio-std-file-handler.hpp>

#include "cprjobhandler.hpp"
#include "debug.hpp"

namespace {
    using namespace Kazv;
    struct SyncFileStream
    {
        using DataT = FileContent;

        inline SyncFileStream(std::string filename, FileOpenMode mode)
            : m_stream(filename,
                       (mode == FileOpenMode::Read
                        ? std::ios_base::in
                        : std::ios_base::out)
                       | std::ios_base::binary)
            {}

        template<class Callback>
        void read(int maxSize, Callback readCallback) {
            auto buf = std::vector<char>(maxSize, '\0');
            auto data = FileContent{};
            auto actualSize = int{};

            try {
                m_stream.read(buf.data(), maxSize);

                actualSize = m_stream.gcount();

                data = FileContent(buf.begin(), buf.begin() + actualSize);
            } catch (const std::exception &) {
                readCallback(FileOpRetCode::Error, FileContent{});
                return;
            }

            if (actualSize > 0) {
                readCallback(FileOpRetCode::Success, data);
            } else if (m_stream.eof()) {
                readCallback(FileOpRetCode::Eof, FileContent{});
            } else {
                readCallback(FileOpRetCode::Error, FileContent{});
            }
        }

        template<class Callback>
        void write(DataT data, Callback writeCallback) {
            for (auto c : data) {
                m_stream.put(c);
                if (m_stream.bad()) {
                    writeCallback(FileOpRetCode::Error, 0);
                    return;
                }
            }

            writeCallback(FileOpRetCode::Success, data.size());
        }

        std::fstream m_stream;
    };

    struct SyncFileProvider
    {
        using FileStreamT = SyncFileStream;

        std::string filename;

        FileStreamT getStream(FileOpenMode mode) const {
            return FileStreamT(filename, mode);
        }
    };

    struct SyncFileHandler
    {
        using FileProviderT = SyncFileProvider;
        FileProviderT getProviderFor(FileDesc desc) const {
            // assert(desc.name())
            return FileProviderT{desc.name().value()};
        }
    };
}

namespace Kazv
{
    struct CprJobHandler::Private
    {
        CprJobHandler *q;
        boost::asio::io_context::executor_type executor;
        using TimerSP = std::shared_ptr<boost::asio::steady_timer>;
        using TimerSPList = std::vector<TimerSP>;
        using TimerMap = std::unordered_map<std::optional<std::string>, TimerSPList>;
        TimerMap timerMap;

        enum Status
        {
            Waiting,
            Running,
        };
        using Callback = std::function<void(Response)>;
        struct JobDesc
        {
            BaseJob job;
            Callback callback;
            Status status;
        };
        using JobQueue = std::deque<JobDesc>;
        using JobMap = std::unordered_map<std::string, JobQueue>;
        JobMap jobQueues;

        void submitImpl(BaseJob job, std::function<void(Response)> userCallback);

        void addToQueue(BaseJob job, Callback callback) {
            boost::asio::post(
                executor,
                [=] {
                    // precondition: job has a queueId
                    auto queueId = job.queueId().value();

                    jobQueues[queueId].push_back(JobDesc{job, callback, Waiting});
                });
        }

        void clearQueue(std::string queueId) {
            boost::asio::post(
                executor,
                [=] { clearQueueImpl(queueId); });
        }

        void clearQueueImpl(std::string queueId) {
            Response fakeResponse;
            fakeResponse.statusCode = headFailureCancelledStatusCode;
            fakeResponse.body = JsonBody(
                json{ {"errcode", headFailureCancelledErrorCode},
                      {"error", headFailureCancelledErrorMsg} }
                );
            kzo.job.dbg() << "clearQueueImpl called with " << queueId << std::endl;

            for (auto [job, callback, status] : jobQueues[queueId]) {
                kzo.job.dbg() << "this job is " << (status == Waiting ? "Waiting" : "Running") << std::endl;
                if (status == Waiting) {
                    // Run callback in a different thread, just as in submitImpl().
                    q->async([=] { callback(job.genResponse(fakeResponse)); } );
                }
                // if status is Running, the callback is already called
            }
            jobQueues[queueId].clear();
        }

        void popJob(std::string queueId) {
            boost::asio::post(
                executor,
                [=] { popJobImpl(queueId); });
        }

        void popJobImpl(std::string queueId) {
            if (! jobQueues[queueId].empty()) {
                jobQueues[queueId].pop_front();
            }
        }

        void monitorQueues() {
            boost::asio::post(
                executor,
                [=] {
                    // precondition: job has a queueId
                    for (auto &[queueId, queue] : jobQueues) { // need to change queue
                        if (! queue.empty()) {
                            auto [job, callback, status] = queue.front();
                            if (status == Waiting) {
                                queue.front().status = Running;
                                submitImpl(
                                    job,
                                    [=](Response r) { // in new thread
                                        callback(r);

                                        if (! r.success() // should be enough for now
                                            && job.queuePolicy() == CancelFutureIfFailed) {
                                            clearQueue(queueId); // in executor thread
                                        } else {
                                            popJob(queueId); // in executor thread
                                        }
                                    });
                            }
                        }
                    }
                });
        }

        void addTimerToMap(TimerSP timer, std::optional<std::string> timerId) {
            boost::asio::post(
                executor,
                [=] {
                    timerMap[timerId].push_back(timer);
                });
        }

        void clearTimer(TimerSP timer, std::optional<std::string> timerId) {
            boost::asio::post(
                executor,
                [=] {
                    std::remove(timerMap[timerId].begin(), timerMap[timerId].end(), timer);
                });
        }

        void cancelAllTimers(std::optional<std::string> timerId) {
            boost::asio::post(
                executor,
                [=] {
                    cancelAllTimersImpl(timerId);
                });
        }

        void cancelAllTimersImpl(std::optional<std::string> timerId) {
            auto timers = timerMap[timerId];
            timerMap.erase(timerId);
            for (auto timer : timers) {
                timer->cancel();
            }
        }

        void intervalTimerCallback(TimerSP timer,
                                   std::function<void()> func,
                                   int ms,
                                   const boost::system::error_code &error) {
            if (! error) {
                func();
                auto dur = boost::asio::chrono::milliseconds(ms);
                timer->expires_at(timer->expiry() + dur);
                timer->async_wait(
                    [=](const boost::system::error_code &error) {
                        intervalTimerCallback(timer, func, ms, error);
                    });
            }
        }
    };

    CprJobHandler::CprJobHandler(boost::asio::io_context::executor_type executor)
        : m_d(new Private{this, std::move(executor), Private::TimerMap{}, Private::JobMap{}})
    {
        setInterval(
            [=] {
                m_d->monitorQueues();
            },
            50, // ms
            "-queue-monitor");
    }

    CprJobHandler::~CprJobHandler() = default;

    void CprJobHandler::async(std::function<void()> func)
    {
        std::thread([func=std::move(func), guard=boost::asio::make_work_guard(m_d->executor)]() {
                        func();
                    }).detach();
    }

    void CprJobHandler::setTimeout(std::function<void()> func, int ms, std::optional<std::string> timerId)
    {
        auto timer=std::make_shared<boost::asio::steady_timer>(
            m_d->executor, boost::asio::chrono::milliseconds(ms));

        m_d->addTimerToMap(timer, timerId);

        timer->async_wait(
            [=, timer=timer](const boost::system::error_code &error){
                if (! error) {
                    func();
                    this->m_d->clearTimer(timer, timerId);
                }
            });
    }

    void CprJobHandler::setInterval(std::function<void()> func, int ms, std::optional<std::string> timerId)
    {
        auto dur = boost::asio::chrono::milliseconds(ms);
        auto timer = std::make_shared<boost::asio::steady_timer>(m_d->executor, dur);

        m_d->addTimerToMap(timer, timerId);

        timer->async_wait(
            [=](const boost::system::error_code &error) {
                m_d->intervalTimerCallback(timer, func, ms, error);
            });
    }

    void CprJobHandler::cancel(std::string timerId)
    {
        m_d->cancelAllTimers(timerId);
    }

    void CprJobHandler::submit(BaseJob job, std::function<void(Response)> userCallback)
    {
        if (job.queueId()) {
            m_d->addToQueue(job, userCallback);
        } else {
            m_d->submitImpl(job, userCallback);
        }
    }

    void CprJobHandler::Private::submitImpl(BaseJob job, std::function<void(Response)> userCallback)
    {
        cpr::Url url{job.url()};

        cpr::Body body;
        BaseJob::Header origHeader = job.requestHeader();
        cpr::Header header(origHeader.get().begin(), origHeader.get().end());

        auto readCallback = std::function<bool(char *, size_t &)>{};
        auto writeCallback = std::function<bool(std::string)>{};

        if (! std::holds_alternative<FileDesc>(job.requestBody())) {
            body = std::get<BytesBody>(job.requestBody());
        } else {
            auto fileDesc = std::get<FileDesc>(job.requestBody());
            auto typeOpt = fileDesc.contentType();
            if (typeOpt) {
                header.insert_or_assign("Content-Type", typeOpt.value());
                kzo.job.dbg() << "Content-Type is " << header["Content-Type"] << std::endl;
            }
            auto fh = SyncFileHandler{};
            auto provider = fileDesc.provider(fh);
            auto stream = std::make_shared<FileStream>(provider.getStream());

            readCallback =
                [stream](char *buffer, size_t &length) -> bool {
                    bool retval = true;
                    kzo.job.dbg() << "A buffer of length " << length << " requested." << std::endl;
                    stream->read(length,
                                 [&](FileOpRetCode code, FileContent data) {
                                     if (code == FileOpRetCode::Success) {
                                         std::copy_n(data.begin(), data.size(), buffer);
                                         kzo.job.dbg() << "Read file successful, read " << data.size() << " bytes." << std::endl;
                                         length = data.size();
                                     } else if (code == FileOpRetCode::Eof) {
                                         kzo.job.dbg() << "Got eof." << std::endl;
                                         length = 0;
                                     } else {
                                         kzo.job.dbg() << "Got error reading file." << std::endl;
                                         length = 0;
                                         retval = false;
                                     }
                                 });
                    return retval;
                };
        }

        if (job.responseFile()) {
            auto fileDesc = job.responseFile().value();

            auto fh = SyncFileHandler{};
            auto provider = fileDesc.provider(fh);
            auto stream = std::make_shared<FileStream>(provider.getStream(FileOpenMode::Write));

            writeCallback =
                [stream](std::string buffer) -> bool {
                    bool retval = true;
                    kzo.job.dbg() << "A buffer of length " << buffer.size() << " responded." << std::endl;
                    FileContent data(buffer.begin(), buffer.end());
                    stream->write(data,
                                 [&](FileOpRetCode code, int num) {
                                     if (code == FileOpRetCode::Success) {
                                         kzo.job.dbg() << "Write file successful, wrote " << num << " bytes." << std::endl;
                                     } else {
                                         kzo.job.dbg() << "Got error writing file." << std::endl;
                                         retval = false;
                                     }
                                 });
                    return retval;
                };
        }

        cpr::Parameters params;
        BaseJob::Query query = job.requestQuery();
        BaseJob::ReturnType returnType = job.returnType();
        BaseJob::Method method = job.requestMethod();

        if (! query.empty()) {
            // from cpr/parameters.cpp
            cpr::CurlHolder holder;
            for (const auto &kv : query) {
                std::string key = kv.first;
                std::string value = kv.second;
                params.Add(cpr::Parameter(std::move(key), std::move(value)));
            }
        }

        auto callback = [returnType, responseFile=job.responseFile()](cpr::Response r) -> Response {
                            Body body;

                            if (responseFile) {
                                body = responseFile.value();
                            } else if (returnType == BaseJob::ReturnType::Json) {
                                try {
                                    body = BaseJob::JsonBody(std::move(json::parse(r.text)));
                                } catch (const json::exception &e) {
                                    // the response is not valid json
                                    body = r.text;
                                    kzo.job.dbg() << "body is not correct json: " << e.what() << std::endl;
                                }
                            } else {
                                body = r.text;
                            }

                            return { static_cast<Response::StatusCode>(r.status_code),
                                     body,
                                     BaseJob::Header(r.header.begin(), r.header.end()),
                                     {} // extraData, will be added in genResponse
                            };
                        };


        std::shared_future<Response> res = std::visit(lager::visitor{
                [=](BaseJob::Get) {
                    if (readCallback) {
                        return cpr::GetCallback(callback, url, cpr::ReadCallback(readCallback), header, params);
                    } else if (writeCallback) {
                        return cpr::GetCallback(callback, url, cpr::WriteCallback(writeCallback), header, body, params);
                    } else {
                        return cpr::GetCallback(callback, url, header, body, params);
                    }
                },
                [=](BaseJob::Post) {
                    if (readCallback) {
                        return cpr::PostCallback(callback, url, cpr::ReadCallback(readCallback), header, params);
                    } else if (writeCallback) {
                        return cpr::PostCallback(callback, url, cpr::WriteCallback(writeCallback), header, body, params);
                    } else {
                        return cpr::PostCallback(callback, url, header, body, params);
                    }
                },
                [=](BaseJob::Put) {
                    if (readCallback) {
                        return cpr::PutCallback(callback, url, cpr::ReadCallback(readCallback), header, params);
                    } else if (writeCallback) {
                        return cpr::PutCallback(callback, url, cpr::WriteCallback(writeCallback), header, body, params);
                    } else {
                        return cpr::PutCallback(callback, url, header, body, params);
                    }
                },
                [=](BaseJob::Delete) {
                    if (readCallback) {
                        return cpr::DeleteCallback(callback, url, cpr::ReadCallback(readCallback), header, params);
                    } else if (writeCallback) {
                        return cpr::DeleteCallback(callback, url, cpr::WriteCallback(writeCallback), header, body, params);
                    } else {
                        return cpr::DeleteCallback(callback, url, header, body, params);
                    }
                }
            }, method).share();

        q->async([=]() {
                     userCallback(job.genResponse(res.get()));
                 });
    }

    void CprJobHandler::stop()
    {
        boost::asio::post(
            m_d->executor,
            [=] {
                auto ids = zug::into_vector(
                    zug::map([](auto i) { return i.first; }),
                    m_d->timerMap);
                for (auto id : ids) {
                    m_d->cancelAllTimersImpl(id);
                }
                m_d->jobQueues.clear();
            });
    }
}
