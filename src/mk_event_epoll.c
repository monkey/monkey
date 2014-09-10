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
#include <sys/eventfd.h>
#include <sys/timerfd.h>

#include <monkey/mk_event.h>
#include <monkey/mk_memory.h>
#include <monkey/mk_utils.h>

typedef struct {
    int efd;
    int queue_size;
    struct epoll_event *events;
} mk_event_ctx_t;

static inline mk_event_loop_t *_mk_event_loop_create(int size)
{
    mk_event_ctx_t *ctx;
    mk_event_loop_t *loop;

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

    /* Allocate space for events queue */
    ctx->events = mk_mem_malloc_z(sizeof(struct epoll_event) * size);
    if (!ctx->events) {
        close(ctx->efd);
        mk_mem_free(ctx);
        return NULL;
    }

    ctx->queue_size = size;

    loop = mk_mem_malloc_z(sizeof(mk_event_loop_t));
    loop->size = size;
    loop->data = ctx;

    return loop;
}


/*
 * It register certain events for the file descriptor in question, if
 * the file descriptor have not been registered, create a new entry.
 */
static inline int _mk_event_add(mk_event_ctx_t *ctx, int fd, int events)
{
    int op;
    int ret;
    struct mk_event_fd_state *fds;
    struct epoll_event event = {0, {0}};

    /* Verify the FD status and desired operation */
    fds = mk_event_get_state(fd);
    if (fds->mask == MK_EVENT_EMPTY) {
        op = EPOLL_CTL_ADD;
    }
    else {
        op = EPOLL_CTL_MOD;
    }

    event.data.fd = fd;
    event.events = EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    if (events & MK_EVENT_READ) {
        event.events |= EPOLLIN;
    }
    if (events & MK_EVENT_WRITE) {
        event.events |= EPOLLOUT;
    }

    ret = epoll_ctl(ctx->efd, op, fd, &event);
    if (ret < 0) {
        mk_libc_error("epoll_ctl");
        return -1;
    }

    return ret;
}

/* Delete an event */
static inline int _mk_event_del(mk_event_ctx_t *ctx, int fd)
{
    int ret;

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

/* Register a timeout file descriptor */
static inline int _mk_event_timeout_create(mk_event_ctx_t *ctx, int expire)
{
    int ret;
    int timer_fd;
    struct itimerspec its;
    struct epoll_event event = {0, {0}};

    /* expiration interval */
    its.it_interval.tv_sec  = expire;
    its.it_interval.tv_nsec = 0;

    /* initial expiration */
    its.it_value.tv_sec  = time(NULL) + expire;
    its.it_value.tv_nsec = 0;

    timer_fd = timerfd_create(CLOCK_REALTIME, 0);
    if (timer_fd == -1) {
        mk_libc_error("timerfd");
        return -1;
    }

    ret = timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &its, NULL);
    if (ret < 0) {
        mk_libc_error("timerfd_settime");
        return -1;
    }

    /* register the timer into the epoll queue */
    event.data.fd = timer_fd;
    event.events  = EPOLLIN;
    ret = epoll_ctl(ctx->efd, EPOLL_CTL_ADD, timer_fd, &event);
    if (ret < 0) {
        printf("efd=%i fd=%i\n", ctx->efd, timer_fd);
        mk_libc_error("epoll_ctl");
        return -1;
    }

    return timer_fd;
}

static inline int _mk_event_channel_create(mk_event_ctx_t *ctx)
{
    int fd;
    int ret;

    fd = eventfd(0, EFD_CLOEXEC);
    if (fd == -1) {
        mk_libc_error("eventfd");
        return -1;
    }

    ret = _mk_event_add(ctx, fd, MK_EVENT_READ);
    if (ret != 0) {
        printf("sad: %i\n", ret);
        close(fd);
        return ret;
    }

    return fd;
}

static inline int _mk_event_wait(mk_event_loop_t *loop)
{
    mk_event_ctx_t *ctx = loop->data;

    loop->n_events = epoll_wait(ctx->efd, ctx->events, ctx->queue_size, -1);
    loop->events = (mk_event_t *) ctx->events;

    return loop->n_events;
}
