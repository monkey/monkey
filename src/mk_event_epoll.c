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

#include <monkey/mk_event.h>
#include <monkey/mk_memory.h>
#include <monkey/mk_utils.h>

typedef struct {
  int efd;
  struct epoll_event *events;
} mk_event_ctx_t;

static mk_event_ctx_t *mk_event_create(int size)
{
    mk_event_ctx_t *ctx;

    /* Main event context */
    ctx = mk_mem_malloc_z(sizeof(mk_event_ctx_t));
    if (!ctx) {
        return NULL;
    }

    /* Create the epoll instance */
    ctx->efd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->efd == -1) {
        mk_libc_error("epoll_create");
        mk_mem_free(ctx);
        return NULL;
    }

    /* Allocate space for events */
    ctx->events = mk_mem_malloc_z(sizeof(struct epoll_event) * size);
    if (!ctx->events) {
        close(ctx->efd);
        mk_mem_free(ctx);
        return NULL;
    }

    return ctx;
}


/*
 * It register certain events for the file descriptor in question, if
 * the file descriptor have not been registered, create a new entry.
 */
static int mk_event_add(mk_event_ctx_t *ctx, int fd, int events)
{
    int op;
    int ret;
    struct epoll_event event = {0, {0}};

    /*
     * FIXME: detect if an entry exists in the global state and check
     * the desired operation here.
     */
    op = EPOLL_CTL_ADD;

    event.data.fd = fd;
    event.events = EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    if (events & MK_EVENT_READ) {
        event.events |= EPOLLIN;
    }
    if (events & MK_EVENT_WRITE) {
        event.events |= EPOLLOUT;
    }

    ret = epoll_ctl(ctx->efd, op, fd, &event);
#ifdef TRACE
    if (ret < 0) {
        mk_libc_error("epoll_ctl");
    }
#endif

    return ret;
}

/* Delete an event */
static int mk_event_del(mk_event_ctx_t *ctx, int fd)
{
    int ret;

    /* FIXME: remove entry from global state */

    ret = epoll_ctl(ctx->efd, EPOLL_CTL_DEL, fd, NULL);
    MK_TRACE("[FD %i] Epoll, remove from QUEUE_FD=%i, ret=%i",
             fd, ctx->efd, ret);
#ifdef TRACE
    if (ret < 0) {
        mk_libc_error("epoll_ctl");
    }
#endif

    return ret;
}
