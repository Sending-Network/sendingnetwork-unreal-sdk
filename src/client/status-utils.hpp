/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <context.hpp>

namespace Kazv
{
    namespace detail
    {
        struct SimpleFailT
        {
            template<class Context>
            EffectStatus operator()(Context &&) const {
                return EffectStatus(/* succ = */ false);
            };
        };
    }

    /**
     * A effect that returns a failed EffectStatus upon invocation.
     */
    constexpr auto simpleFail = detail::SimpleFailT{};

    /**
     * A effect that returns a failed EffectStatus upon invocation.
     */
    template<class Resp>
    constexpr auto failWithResponse(Resp &&r)
    {
        auto code = r.errorCode();
        auto msg = std::forward<Resp>(r).errorMessage();
        auto d = json{
            {"error", msg},
            {"errorCode", code},
        };
        return [data=JsonWrap(d)](auto &&) {
            return EffectStatus(/* succ = */ false, data);
        };
    }
}
