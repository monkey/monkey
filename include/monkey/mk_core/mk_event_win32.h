/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2026 Eduardo Silva <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MK_EVENT_WIN32_H
#define MK_EVENT_WIN32_H

#include <winsock2.h>
#include <ws2tcpip.h>

struct mk_event_ctx {
    int queue_size;
    struct mk_event **events;
    struct mk_event **poll_events;
    struct mk_event *fired;
    WSAPOLLFD *pfds;
};

#define mk_event_foreach(event, evl)                                         \
    int __i;                                                                 \
    struct mk_event_ctx *__ctx = evl->data;                                  \
                                                                             \
    if (evl->n_events > 0) {                                                 \
        event = __ctx->fired[0].data;                                        \
    }                                                                        \
                                                                             \
    for (__i = 0;                                                            \
         __i < evl->n_events;                                                \
         __i++,                                                              \
             event = ((__i < evl->n_events) ? __ctx->fired[__i].data : NULL) \
         )

#endif
