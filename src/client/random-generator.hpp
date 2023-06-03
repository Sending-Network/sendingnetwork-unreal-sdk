/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once
#include <libkazv-config.hpp>

#include <memory>

namespace Kazv
{
    class RandomInterface
    {
    public:
        using DataT = unsigned int;

        /**
         * Construct a RandomInterface using an implementation.
         *
         * @param obj The random generator implementation.
         *
         * The implementation obj must be of a movable type and
         * must be such that the following
         * call is valid, and after that v should contain a random number:
         *
         * `unsigned int v = obj();`
         */
        template<class DeriveT>
        RandomInterface(DeriveT obj)
            : m_d(std::make_unique<Model<DeriveT>>(std::move(obj)))
            {}

        /**
         * Generate a random number of type DataT.
         *
         * @return A randomly generated DataT.
         */
        DataT operator()() {
            return (*m_d)();
        }

        /**
         * Generate a range containing `size` random elements.
         *
         * RangeT must have a constructor such that
         * `RangeT(size, ValueT())` constructs a range of `size`
         * elements valued `ValueT()`, where `ValueT` is the value type
         * of `RangeT`.
         *
         * @param size The size of the range to create.
         *
         * @return A RangeT containing `size` random elements.
         */
        template<class RangeT>
        RangeT generateRange(std::size_t size) {
            using ValueT = std::decay_t<decltype(* (std::declval<RangeT>().begin()))>;
            RangeT range(size, ValueT());
            return fillRange(std::move(range));
        }

        /**
         * Fill the given range.
         *
         * @param range The range to fill.
         *
         * @return A range filled with random elements. Its size will be
         * the same as `range`.
         */
        template<class RangeT>
        RangeT fillRange(RangeT range) {
            std::generate(range.begin(), range.end(), [this] { return (*this)(); });
            return range;
        }

    private:
        struct Concept
        {
            virtual ~Concept() = default;
            virtual DataT operator()() = 0;
        };

        template<class DeriveT>
        struct Model : public Concept
        {
            Model(DeriveT obj) : instance(std::move(obj)) {}
            ~Model() override = default;
            DataT operator()() override {
                return instance();
            }
            DeriveT instance;
        };

        std::unique_ptr<Concept> m_d;
    };

    /**
     * A movable wrapper around std::random_device.
     */
    class RandomDeviceGenerator
    {
    public:
        RandomDeviceGenerator() : m_d(std::make_unique<std::random_device>()) {}

        auto operator()() { return (*m_d)(); }

    private:
        std::unique_ptr<std::random_device> m_d;
    };
}
