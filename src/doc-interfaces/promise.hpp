/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

static_assert(false, "This is an *interface*, not an actual class in the library.");

/**
 * A Promise represents an asynchronous result that can be fetched later.
 *
 * @warning This is an *interface*, not an actual class in the library.
 *
 * A Promise is called *resolved* when the result becomes available.
 *
 * In libkazv docs, the result type is usually EffectStatus.
 */
template<class T>
class Promise
{
public:
    /**
     * The type of the value this Promise will hold.
     */
    using DataT = T;

    /**
     * Specify something to do after this Promise resolves.
     *
     * @param f the function to run. It should take a DataT as the only argument.
     *
     * @return A Promise.
     * Assume `result` is the result this Promise resolves to.
     * If `f(result)` returns void, it resolves to `DataT()` after `f` returns.
     * If `f(result)` returns a Promise, it resolves to what the Promise will resolve to,
     * after that Promise resolves.
     * Otherwise it resolves to what `f(result)` returns, implicitly converted to `DataT`,
     * after that function returns.
     */
    template<class Func>
    Promise then(Func &&f);
};
