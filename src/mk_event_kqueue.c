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

#include <monkey/mk_event.h>
#include <monkey/mk_memory.h>
#include <monkey/mk_utils.h>

typedef struct {
    int kfd;
    int queue_size;
    void *events;
} mk_event_ctx_t;

static inline void *_mk_event_loop_create(int size)
{
    (void) size;

    return NULL;
}

static inline int _mk_event_add(mk_event_ctx_t *ctx, int fd, int events)
{
    (void) ctx;
    (void) fd;
    (void) events;

    return -1;
}

static inline int _mk_event_del(mk_event_ctx_t *ctx, int fd)
{
    (void) ctx;
    (void) fd;

    return -1;
}

static inline int _mk_event_timeout_create(mk_event_ctx_t *ctx, int expire)
{
    (void) ctx;
    (void) expire;

    return -1;
}

static inline int _mk_event_channel_create(mk_event_ctx_t *ctx)
{
    (void) ctx;
    return -1;
}

static inline int _mk_event_wait(mk_event_loop_t *loop)
{
    (void) loop;

    return 0;
}
