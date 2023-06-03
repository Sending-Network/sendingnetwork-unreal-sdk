/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2020 Tusooa Zhu
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#include <vector>
#include <memory>
#include <algorithm>


#include <lager/store.hpp>
#include <lager/reader.hpp>
#include <lager/event_loop/manual.hpp>

#include "types.hpp"

#include "eventinterface.hpp"

namespace Kazv
{
    class LagerStoreEventEmitter : public EventInterface
    {
        struct Model { KazvEvent curEvent; };
        struct Action { KazvEvent nextEvent; };

        struct ListenerHolder;

        using Result = std::pair<Model,
                                 lager::effect<Action, lager::deps<ListenerHolder &>>>;

        using SlotT = std::function<void(KazvEvent)>;

        struct Listener
        {
            void emit(KazvEvent e) {
                for (const auto &slot: m_slots) {
                    slot(e);
                }
            }

            void connect(SlotT slot) {
                m_slots.push_back(std::move(slot));
            }

            std::vector<SlotT> m_slots;
        };

        using ListenerSP = std::shared_ptr<Listener>;
        using ListenerWSP = std::weak_ptr<Listener>;

        struct ListenerHolder
        {
            void sendToListeners(KazvEvent e) {
                bool needsCleanup = false;
                for (auto listener : m_listeners) {
                    auto strongListener = listener.lock();
                    if (strongListener) {
                        strongListener->emit(e);
                    } else {
                        needsCleanup = true;
                    }
                }

                if (needsCleanup) {
                    std::remove_if(m_listeners.begin(),
                                   m_listeners.end(),
                                   [](auto ptr) {
                                       return ptr.expired();
                                   });
                }

            }

            std::vector<ListenerWSP> m_listeners;
        };

        inline static Result update(Model, Action a) {
            return {
                Model{a.nextEvent},
                [=](auto &&ctx) {
                    auto &holder = lager::get<ListenerHolder &>(ctx);
                    holder.sendToListeners(a.nextEvent);
                }
            };
        }

    public:
        template<class EventLoop>
        LagerStoreEventEmitter(EventLoop loop)
            : m_holder{}
            , m_store(
                lager::make_store<Action>(
                    Model{},
                    loop,
                    lager::with_reducer(&update),
                    lager::with_deps(std::ref(m_holder))))
            , m_postingFunc(
                [loop=loop](auto &&func) mutable {
                    loop.post(std::forward<decltype(func)>(func));
                }) {}
        ~LagerStoreEventEmitter() override = default;

        void emit(KazvEvent e) override {
            m_store.dispatch(Action{e});
        }

        class Watchable
        {
        public:
            Watchable(LagerStoreEventEmitter &ee)
                : m_listener(std::make_shared<Listener>()) {
                ee.addListener(m_listener);
            }
            template<class EventType, class Func>
            void after(Func &&func) {
                m_listener->connect(
                    [f=std::forward<Func>(func)](KazvEvent e) {
                        if (std::holds_alternative<EventType>(e)) {
                            f(std::get<EventType>(e));
                        }
                    });
            }

            template<class Func>
            void afterAll(Func &&func) {
                m_listener->connect(
                    [f=std::forward<Func>(func)](KazvEvent e) {
                        f(e);
                    });
            }

        private:
            ListenerSP m_listener;
        };

        /**
         * An object you can watch for events.
         * ```
         * auto watchable = eventEmitter.watchable();
         * watchable.after<ReceivingRoomTimelineEvent>(
         *     [](auto &&e) { ... });
         * ```
         */
        Watchable watchable() {
            return Watchable(*this);
        }


    private:
        void addListener(ListenerSP listener) {
            m_postingFunc([=]() {
                              m_holder.m_listeners.push_back(listener);
                          });
        }

        using StoreT =
            decltype(lager::make_store<Action>(
                         Model{},
                         lager::with_manual_event_loop{},
                         lager::with_reducer(&update),
                         lager::with_deps(std::ref(detail::declref<ListenerHolder>()))));

        using PostingFunc = std::function<void(std::function<void()>)>;

        ListenerHolder m_holder;
        StoreT m_store;
        PostingFunc m_postingFunc;
    };

}
