/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020-2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include "libkazv-config.hpp"

#include <optional>
#include <variant>
#include <tuple>
#include <functional>
#include <string>
#include <map>
#include <future>
#include <immer/map.hpp>
#include <immer/array.hpp>
#include <immer/box.hpp>

#include "types.hpp"
#include "descendent.hpp"

#include "file-desc.hpp"

namespace Kazv
{
    using Header = immer::box<std::map<std::string, std::string>>;

    using BytesBody = Bytes;
    using JsonBody = JsonWrap;
    using FileBody = FileDesc;
    struct EmptyBody {};
    using Body = std::variant<EmptyBody, JsonBody, BytesBody, FileBody>;
    inline bool operator==(EmptyBody, EmptyBody)
    {
        return true;
    }

    inline bool isBodyJson(Body body) {
        return std::holds_alternative<JsonBody>(body);
    };

    enum JobQueuePolicy
    {
        AlwaysContinue,
        CancelFutureIfFailed
    };

    struct Response {
        using StatusCode = int;
        StatusCode statusCode;
        Body body;
        Header header;
        JsonWrap extraData;
        std::string errorCode() const;
        std::string errorMessage() const;
        JsonWrap jsonBody() const;
        constexpr bool success() const {
            return statusCode < 400;
        }
        json dataJson(const std::string &key) const;
        std::string dataStr(const std::string &key) const;
        std::string jobId() const;
    };

    inline bool operator==(Response a, Response b)
    {
        return a.statusCode == b.statusCode
            && a.body == b.body
            && a.header == b.header
            && a.extraData == b.extraData;
    }


    class BaseJob
    {
    public:
        struct Get {};
        struct Post {};
        struct Put {};
        struct Delete {};
        using Method = std::variant<Get, Post, Put, Delete>;

        static Get GET;
        static Post POST;
        static Put PUT;
        static Delete DELETE;

        class Query : public std::vector<std::pair<std::string, std::string>>
        {
            using BaseT = std::vector<std::pair<std::string, std::string>>;
        public:
            using BaseT::BaseT;
            void add(std::string k, std::string v) {
                push_back({k, v});
            }
        };

        using Body = ::Kazv::Body;
        using BytesBody = ::Kazv::BytesBody;
        using JsonBody = ::Kazv::JsonBody;
        using EmptyBody = ::Kazv::EmptyBody;
        using Header = ::Kazv::Header;
        using Response = ::Kazv::Response;

        enum ReturnType {
            Json,
            File,
        };

        BaseJob(std::string serverUrl,
                std::string requestUrl,
                Method method,
                std::string jobId,
                std::string token = {},
                ReturnType returnType = ReturnType::Json,
                Body body = EmptyBody{},
                Query query = {},
                Header header = {},
                std::optional<FileDesc> responseFile = std::nullopt);

        bool shouldReturnJson() const;

        std::string url() const;

        Body requestBody() const;

        Header requestHeader() const;

        ReturnType returnType() const;

        /// returns the non-encoded query as an array of pairs
        Query requestQuery() const;

        Method requestMethod() const;

        static bool contentTypeMatches(immer::array<std::string> expected, std::string actual);

        Response genResponse(Response r) const;

        BaseJob withData(JsonWrap j) &&;
        BaseJob withData(JsonWrap j) const &;

        BaseJob withQueue(std::string id, JobQueuePolicy policy = AlwaysContinue) &&;
        BaseJob withQueue(std::string id, JobQueuePolicy policy = AlwaysContinue) const &;

        json dataJson(const std::string &key) const;
        std::string dataStr(const std::string &key) const;
        std::string jobId() const;
        std::optional<std::string> queueId() const;
        JobQueuePolicy queuePolicy() const;

        std::optional<FileDesc> responseFile() const;

    protected:
        void attachData(JsonWrap data);

    private:
        friend bool operator==(BaseJob a, BaseJob b);
        struct Private;
        Descendent<Private> m_d;
    };

    bool operator==(BaseJob a, BaseJob b);
    bool operator!=(BaseJob a, BaseJob b);
    inline bool operator==(BaseJob::Get, BaseJob::Get) { return true; }
    inline bool operator==(BaseJob::Post, BaseJob::Post) { return true; }
    inline bool operator==(BaseJob::Put, BaseJob::Put) { return true; }
    inline bool operator==(BaseJob::Delete, BaseJob::Delete) { return true; }


    namespace detail
    {
        template<class T>
        struct AddToQueryT
        {
            template<class U>
            static void call(BaseJob::Query &q, std::string name, U &&arg) {
                q.add(name, std::to_string(std::forward<U>(arg)));
            }
        };

        template<>
        struct AddToQueryT<std::string>
        {
            template<class U>
            static void call(BaseJob::Query &q, std::string name, U &&arg) {
                q.add(name, std::forward<U>(arg));
            }
        };

        template<>
        struct AddToQueryT<bool>
        {
            template<class U>
            static void call(BaseJob::Query &q, std::string name, U &&arg) {
                q.add(name, std::forward<U>(arg) ? "true"s : "false"s);
            }
        };

        template<class T>
        struct AddToQueryT<immer::array<T>>
        {
            template<class U>
            static void call(BaseJob::Query &q, std::string name, U &&arg) {
                for (auto v : std::forward<U>(arg)) {
                    q.add(name, v);
                }
            }
        };

        template<>
        struct AddToQueryT<json>
        {
            // https://github.com/nlohmann/json/issues/2040
            static void call(BaseJob::Query &q, std::string /* name */, const json &arg) {
                // assume v is string type
                for (auto [k, v] : arg.items()) {
                    q.add(k, v);
                }
            }
        };
    }

    template<class T>
    inline void addToQuery(BaseJob::Query &q, std::string name, T &&arg)
    {
        detail::AddToQueryT<std::decay_t<T>>::call(q, name, std::forward<T>(arg));
    }

    namespace detail
    {
        template<class T>
        struct AddToQueryIfNeededT
        {
            template<class U>
            static void call(BaseJob::Query &q, std::string name, U &&arg) {
                using ArgT = std::decay_t<U>;
                if constexpr (detail::hasEmptyMethod(boost::hana::type_c<ArgT>)) {
                    if (! arg.empty()) {
                        addToQuery(q, name, std::forward<U>(arg));
                    }
                } else {
                    addToQuery(q, name, std::forward<U>(arg));
                }
            }
        };

        template<class T>
        struct AddToQueryIfNeededT<std::optional<T>>
        {
            template<class U>
            static void call(BaseJob::Query &q, std::string name, U &&arg) {
                if (arg.has_value()) {
                    addToQuery(q, name, std::forward<U>(arg).value());
                }
            }
        };
    }

    template<class T>
    inline void addToQueryIfNeeded(BaseJob::Query &q, std::string name, T &&arg)
    {
        detail::AddToQueryIfNeededT<std::decay_t<T>>::call(q, name, std::forward<T>(arg));
    }

}
