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

#ifndef __linux__
   #include <sys/types.h>
   #include <sys/event.h>
   #include <sys/time.h>
#endif

#ifdef LINUX_KQUEUE
   #include <kqueue/sys/event.h>
#endif

#include <monkey/mk_event.h>
#include <monkey/mk_memory.h>
#include <monkey/mk_utils.h>

typedef struct {
    int kfd;
    int queue_size;
    struct kevent *events;
} mk_event_ctx_t;

static inline void *_mk_event_loop_create(int size)
{
    mk_event_ctx_t *ctx;

    /* Main event context */
    ctx = mk_mem_malloc_z(sizeof(mk_event_ctx_t));
    if (!ctx) {
        return NULL;
    }

    /* Create the epoll instance */
    ctx->kfd = kqueue();
    if (ctx->kfd == -1) {
        mk_libc_error("kqueue");
        mk_mem_free(ctx);
        return NULL;
    }

    /* Allocate space for events queue */
    ctx->events = mk_mem_malloc_z(sizeof(struct kevent) * size);
    if (!ctx->events) {
        close(ctx->kfd);
        mk_mem_free(ctx);
        return NULL;
    }
    ctx->queue_size = size;
    return ctx;
}

static inline int _mk_event_add(mk_event_ctx_t *ctx, int fd, int events)
{
    int ret;
    struct kevent ke;

    if (events & MK_EVENT_READ) {
        EV_SET(&ke, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);

        ret = kevent(ctx->kfd, &ke, 1, NULL, 0, NULL);
        if (ret < 0) {
            mk_libc_error("kevent");
            return -1;
        }
    }

    if (events & MK_EVENT_WRITE) {
        EV_SET(&ke, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);

        ret = kevent(ctx->kfd, &ke, 1, NULL, 0, NULL);
        if (ret < 0) {
            mk_libc_error("kevent");
            return -1;
        }
    }

    return 0;
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

    return 1;
}

static inline int _mk_event_channel_create(mk_event_ctx_t *ctx)
{
    (void) ctx;
    return 1;
}

static inline int _mk_event_wait(mk_event_loop_t *loop)
{
    (void) loop;

    return 0;
}
