/*
 * This file is part of libkazv.
 * SPDX-FileCopyrightText: 2021 Tusooa Zhu <tusooa@kazv.moe>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#pragma once

#include <limits> // workaround for immer under gcc11 21/07/11
#include "libkazv-defs.hpp"

// https://github.com/arximboldi/zug/issues/24
#ifndef ZUG_VARIANT_BOOST
#define ZUG_VARIANT_BOOST 1
#endif
