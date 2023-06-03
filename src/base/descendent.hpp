/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once
#include "libkazv-config.hpp"

#include <memory>

namespace Kazv
{
    template<typename T>
    class Descendent
    {
        struct concept
        {
            virtual ~concept() = default;
            virtual const T *ptr() const = 0;
            virtual T *ptr() = 0;
            virtual const T &ref() const = 0;
            virtual T &ref() = 0;
            virtual T &&rref() && = 0;
            virtual std::unique_ptr<concept> clone() const = 0;
        };
        template<typename U>
        struct model : public concept
        {
            model(U x) : instance(std::move(x)) {}
            const T *ptr() const { return &instance; }
            T *ptr() { return &instance; }
            const T &ref() const { return instance; }
            T &ref() { return instance; }
            T &&rref() && { return std::move(instance); }
            // or std::unique_ptr<model<U> >(new model<U>(U(instance))) if you do not have C++14
            std::unique_ptr<concept> clone() const { return std::make_unique<model<U> >(U(instance)); }
            U instance;
        };

        std::unique_ptr<concept> m_d;
    public:
        Descendent() : m_d(std::make_unique<model<T>>(T())) {}

        template<typename U>
        Descendent(U x) : m_d(std::make_unique<model<U> >(std::move(x))) {}

        Descendent(const Descendent & that) : m_d(std::move(that.m_d->clone())) {}
        Descendent(Descendent && that) : m_d(std::move(that.m_d)) {}

        Descendent & operator=(const Descendent &that) { Descendent t(that); *this = std::move(t); return *this; }
        Descendent & operator=(Descendent && that) { m_d = std::move(that.m_d); return *this; }

        const T &ref() const { return m_d->ref(); }
        const T &constRef() const { return m_d->ref(); }
        const T &ref() { return m_d->ref(); }
        T &&rref() && { return m_d->rref(); }

        const T *data() const { return m_d->ptr(); }
        const T *constData() const { return m_d->ptr(); }
        T *data() { return m_d->ptr(); }
        const T *operator->() const { return m_d->ptr(); }
        T *operator->() { return m_d->ptr(); }

        template<class Derived> bool isa() const {
            return dynamic_cast<Derived *>(constData());
        }

        template<class Derived> Derived &cast() {
            return dynamic_cast<Derived &>(ref());
        }
        template<class Derived> const Derived &cast() const {
            return dynamic_cast<const Derived &>(ref());
        }
        template<class Derived> const Derived &constCast() const {
            return dynamic_cast<const Derived &>(ref());
        }
        template<class Derived> const Derived &rCast() && {
            return dynamic_cast<Derived &&>(rref());
        }
    };
}
