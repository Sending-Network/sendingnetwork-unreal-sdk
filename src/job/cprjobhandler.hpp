/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include <libkazv-config.hpp>

#include <memory>

#include <boost/asio.hpp>

#include "jobinterface.hpp"
#include "descendent.hpp"

namespace Kazv
{
    struct CprJobHandler : public JobInterface
    {
        CprJobHandler(boost::asio::io_context::executor_type executor);
        ~CprJobHandler() override;
        void async(std::function<void()> func) override;
        void setTimeout(std::function<void()> func, int ms,
                        std::optional<std::string> timerId = std::nullopt) override;
        void setInterval(std::function<void()> func, int ms,
                         std::optional<std::string> timerId = std::nullopt) override;
        void cancel(std::string timerId) override;

        void submit(BaseJob job,
                    std::function<void(Response)> callback) override;

        void stop();
    private:
        struct Private;
        std::unique_ptr<Private> m_d;
    };
}
