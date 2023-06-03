/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

static_assert(false, "This is an *interface*, not an actual class in the library.");

#include <cstddef>

/**
 * A RangeT is an ordered collection that can be iterated through.
 *
 * @warning This is an *interface*, not an actual class in the library.
 *
 */
template<class T>
class RangeT
{
public:
    /// The type of items in this range.
    using DataT = T;

    /**
     * The beginning iterator of this range.
     */
    auto begin() const;

    /**
     * The past-end iterator of this range.
     */
    auto end() const;

    /**
     * Get the item at index with bound-checking.
     *
     * If there is no such index, it will throw.
     */
    const DataT &at(std::size_t index) const;

    /**
     * Get the item at index without bound-checking.
     *
     * If there is no such index, it might return a default-constructed
     * instance, or it might be undefined behaviour.
     */
    const DataT &operator[](std::size_t index) const;
};
