/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
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

#include <sys/epoll.h>

#ifndef MK_EVENT_EPOLL_H
#define MK_EVENT_EPOLL_H

typedef struct {
    int efd;
    int queue_size;
    struct epoll_event *events;
} mk_event_ctx_t;

#define mk_event_foreach(evl, fd, mask)                                 \
    int i = 0;                                                          \
    mk_event_ctx_t *ctx = evl->data;                                    \
    struct mk_event_fd_state *st;                                       \
                                                                        \
    fd   = ctx->events[i].data.fd;                                      \
    mask = ctx->events[i].events;                                       \
    st = &mk_events_fdt->states[fd];                                    \
                                                                        \
    evl->events[i].fd   = fd;                                           \
    evl->events[i].mask = mask;                                         \
    evl->events[i].data = st->data;                                     \
                                                                        \
    for (i = 0;                                                         \
         i < evl->n_events;                                             \
         i++,                                                           \
             fd = ctx->events[i].data.fd,                               \
             mask = ctx->events[i].events,                              \
             evl->events[i].fd   = fd,                                  \
             evl->events[i].mask = mask,                                \
             evl->events[i].data = st->data)
#endif
