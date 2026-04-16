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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <mk_core/mk_event.h>

struct win32_timer {
    SOCKET read_fd;
    SOCKET write_fd;
    HANDLE timer;
    HANDLE stop_event;
    HANDLE thread;
};

static LONG win32_wsa_initialized = 0;

static int win32_socketpair(SOCKET pair[2])
{
    int ret;
    int one = 1;
    int addrlen;
    SOCKET listener = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;
    SOCKET server = INVALID_SOCKET;
    struct sockaddr_in addr;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        return -1;
    }

    ret = setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one));
    if (ret == SOCKET_ERROR) {
        closesocket(listener);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    ret = bind(listener, (struct sockaddr *) &addr, sizeof(addr));
    if (ret == SOCKET_ERROR) {
        closesocket(listener);
        return -1;
    }

    ret = listen(listener, 1);
    if (ret == SOCKET_ERROR) {
        closesocket(listener);
        return -1;
    }

    addrlen = sizeof(addr);
    ret = getsockname(listener, (struct sockaddr *) &addr, &addrlen);
    if (ret == SOCKET_ERROR) {
        closesocket(listener);
        return -1;
    }

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        closesocket(listener);
        return -1;
    }

    ret = connect(client, (struct sockaddr *) &addr, sizeof(addr));
    if (ret == SOCKET_ERROR) {
        closesocket(client);
        closesocket(listener);
        return -1;
    }

    server = accept(listener, NULL, NULL);
    closesocket(listener);
    if (server == INVALID_SOCKET) {
        closesocket(client);
        return -1;
    }

    pair[0] = server;
    pair[1] = client;
    return 0;
}

static inline int _mk_event_init()
{
    int ret;
    WSADATA wsa_data;

    if (InterlockedCompareExchange(&win32_wsa_initialized, 1, 0) != 0) {
        return 0;
    }

    ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (ret != 0) {
        InterlockedExchange(&win32_wsa_initialized, 0);
        return -1;
    }

    return 0;
}

static inline void *_mk_event_loop_create(int size)
{
    struct mk_event_ctx *ctx;

    if (_mk_event_init() != 0) {
        return NULL;
    }

    ctx = mk_mem_alloc_z(sizeof(struct mk_event_ctx));
    if (!ctx) {
        return NULL;
    }

    ctx->events = mk_mem_alloc_z(sizeof(struct mk_event *) * size);
    if (!ctx->events) {
        mk_mem_free(ctx);
        return NULL;
    }

    ctx->poll_events = mk_mem_alloc_z(sizeof(struct mk_event *) * size);
    if (!ctx->poll_events) {
        mk_mem_free(ctx->events);
        mk_mem_free(ctx);
        return NULL;
    }

    ctx->fired = mk_mem_alloc_z(sizeof(struct mk_event) * size);
    if (!ctx->fired) {
        mk_mem_free(ctx->poll_events);
        mk_mem_free(ctx->events);
        mk_mem_free(ctx);
        return NULL;
    }

    ctx->pfds = mk_mem_alloc_z(sizeof(WSAPOLLFD) * size);
    if (!ctx->pfds) {
        mk_mem_free(ctx->fired);
        mk_mem_free(ctx->poll_events);
        mk_mem_free(ctx->events);
        mk_mem_free(ctx);
        return NULL;
    }

    ctx->queue_size = size;
    return ctx;
}

static inline void _mk_event_loop_destroy(struct mk_event_ctx *ctx)
{
    mk_mem_free(ctx->pfds);
    mk_mem_free(ctx->fired);
    mk_mem_free(ctx->poll_events);
    mk_mem_free(ctx->events);
    mk_mem_free(ctx);
}

static inline int _mk_event_add(struct mk_event_ctx *ctx, int fd,
                                int type, uint32_t events, void *data)
{
    int i;
    int found = -1;
    int empty = -1;
    struct mk_event *event;

    mk_bug(ctx == NULL);
    mk_bug(data == NULL);

    for (i = 0; i < ctx->queue_size; i++) {
        if (ctx->events[i] == NULL) {
            if (empty == -1) {
                empty = i;
            }
            continue;
        }

        if (ctx->events[i]->fd == fd) {
            found = i;
            break;
        }
    }

    if (found == -1) {
        if (empty == -1) {
            return -1;
        }
        found = empty;
    }

    event = (struct mk_event *) data;
    ctx->events[found] = event;

    if (event->mask == MK_EVENT_EMPTY) {
        event->fd = fd;
        event->status = MK_EVENT_REGISTERED;
    }

    event->mask = events;
    if (type != MK_EVENT_UNMODIFIED) {
        event->type = type;
    }

    event->priority = MK_EVENT_PRIORITY_DEFAULT;

    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    return 0;
}

static inline int _mk_event_del(struct mk_event_ctx *ctx, struct mk_event *event)
{
    int i;

    mk_bug(ctx == NULL);
    mk_bug(event == NULL);

    if (!MK_EVENT_IS_REGISTERED(event)) {
        return 0;
    }

    for (i = 0; i < ctx->queue_size; i++) {
        if (ctx->events[i] == event) {
            ctx->events[i] = NULL;
            break;
        }
    }

    if (i == ctx->queue_size) {
        return -1;
    }

    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    MK_EVENT_NEW(event);
    return 0;
}

static DWORD WINAPI win32_timer_worker(LPVOID arg)
{
    DWORD ret;
    uint64_t value = 1;
    HANDLE handles[2];
    struct win32_timer *timer = arg;

    handles[0] = timer->stop_event;
    handles[1] = timer->timer;

    while (1) {
        ret = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        if (ret == WAIT_OBJECT_0) {
            break;
        }

        if (ret != WAIT_OBJECT_0 + 1) {
            break;
        }

        ret = send(timer->write_fd, (const char *) &value, sizeof(value), 0);
        if (ret == SOCKET_ERROR) {
            break;
        }
    }

    return 0;
}

static inline int _mk_event_timeout_create(struct mk_event_ctx *ctx,
                                           time_t sec, long nsec, void *data)
{
    int ret;
    DWORD period_ms;
    LARGE_INTEGER due_time;
    SOCKET pair[2];
    struct mk_event *event;
    struct win32_timer *timer;

    mk_bug(data == NULL);

    if (win32_socketpair(pair) != 0) {
        return -1;
    }

    timer = mk_mem_alloc_z(sizeof(struct win32_timer));
    if (!timer) {
        closesocket(pair[0]);
        closesocket(pair[1]);
        return -1;
    }

    period_ms = (DWORD) (sec * 1000);
    if (nsec > 0) {
        period_ms += (DWORD) ((nsec + 999999) / 1000000);
    }
    if (period_ms == 0) {
        period_ms = 1;
    }

    timer->read_fd = pair[0];
    timer->write_fd = pair[1];
    timer->stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    timer->timer = CreateWaitableTimer(NULL, FALSE, NULL);

    if (timer->stop_event == NULL || timer->timer == NULL) {
        if (timer->stop_event != NULL) {
            CloseHandle(timer->stop_event);
        }
        if (timer->timer != NULL) {
            CloseHandle(timer->timer);
        }
        closesocket(pair[0]);
        closesocket(pair[1]);
        mk_mem_free(timer);
        return -1;
    }

    due_time.QuadPart = -((LONGLONG) period_ms * 10000);
    ret = SetWaitableTimer(timer->timer, &due_time, period_ms, NULL, NULL, FALSE);
    if (ret == 0) {
        CloseHandle(timer->timer);
        CloseHandle(timer->stop_event);
        closesocket(pair[0]);
        closesocket(pair[1]);
        mk_mem_free(timer);
        return -1;
    }

    timer->thread = CreateThread(NULL, 0, win32_timer_worker, timer, 0, NULL);
    if (timer->thread == NULL) {
        CancelWaitableTimer(timer->timer);
        CloseHandle(timer->timer);
        CloseHandle(timer->stop_event);
        closesocket(pair[0]);
        closesocket(pair[1]);
        mk_mem_free(timer);
        return -1;
    }

    event = (struct mk_event *) data;
    event->fd = (int) pair[0];
    event->type = MK_EVENT_NOTIFICATION;
    event->mask = MK_EVENT_EMPTY;
    event->data = timer;

    ret = _mk_event_add(ctx, event->fd, MK_EVENT_NOTIFICATION, MK_EVENT_READ, data);
    if (ret != 0) {
        SetEvent(timer->stop_event);
        WaitForSingleObject(timer->thread, INFINITE);
        CloseHandle(timer->thread);
        CancelWaitableTimer(timer->timer);
        CloseHandle(timer->timer);
        CloseHandle(timer->stop_event);
        closesocket(pair[0]);
        closesocket(pair[1]);
        mk_mem_free(timer);
        return ret;
    }

    return event->fd;
}

static inline int _mk_event_timeout_destroy(struct mk_event_ctx *ctx, void *data)
{
    struct mk_event *event;
    struct win32_timer *timer;

    if (data == NULL) {
        return 0;
    }

    event = (struct mk_event *) data;
    timer = event->data;

    _mk_event_del(ctx, event);

    if (timer != NULL) {
        SetEvent(timer->stop_event);
        WaitForSingleObject(timer->thread, INFINITE);
        CloseHandle(timer->thread);
        CancelWaitableTimer(timer->timer);
        CloseHandle(timer->timer);
        CloseHandle(timer->stop_event);
        closesocket(timer->read_fd);
        closesocket(timer->write_fd);
        mk_mem_free(timer);
        event->data = NULL;
    }

    return 0;
}

static inline int _mk_event_channel_create(struct mk_event_ctx *ctx,
                                           int *r_fd, int *w_fd, void *data)
{
    int ret;
    SOCKET pair[2];
    struct mk_event *event;

    mk_bug(data == NULL);

    if (win32_socketpair(pair) != 0) {
        return -1;
    }

    event = (struct mk_event *) data;
    event->fd = (int) pair[0];
    event->type = MK_EVENT_NOTIFICATION;
    event->mask = MK_EVENT_EMPTY;

    ret = _mk_event_add(ctx, event->fd, MK_EVENT_NOTIFICATION, MK_EVENT_READ, event);
    if (ret != 0) {
        closesocket(pair[0]);
        closesocket(pair[1]);
        return ret;
    }

    *r_fd = (int) pair[0];
    *w_fd = (int) pair[1];
    return 0;
}

static inline int _mk_event_channel_destroy(struct mk_event_ctx *ctx,
                                            int r_fd, int w_fd, void *data)
{
    struct mk_event *event;
    int ret;

    event = (struct mk_event *) data;
    if (event->fd != r_fd) {
        return -1;
    }

    ret = _mk_event_del(ctx, event);
    closesocket((SOCKET) r_fd);
    closesocket((SOCKET) w_fd);
    return ret;
}

static inline int _mk_event_inject(struct mk_event_loop *loop,
                                   struct mk_event *event,
                                   int mask,
                                   int prevent_duplication)
{
    int i;
    struct mk_event_ctx *ctx;

    ctx = loop->data;

    if (prevent_duplication) {
        for (i = 0; i < loop->n_events; i++) {
            if (ctx->fired[i].data == event) {
                return 0;
            }
        }
    }

    event->mask = mask;
    ctx->fired[loop->n_events].data = event;
    loop->n_events++;
    return 0;
}

static inline int _mk_event_wait_2(struct mk_event_loop *loop, int timeout)
{
    int i;
    int count = 0;
    int fired = 0;
    short events;
    short revents;
    uint32_t mask;
    struct mk_event *event;
    struct mk_event_ctx *ctx = loop->data;

    loop->n_events = 0;

    for (i = 0; i < ctx->queue_size; i++) {
        event = ctx->events[i];
        if (event == NULL) {
            continue;
        }

        events = 0;
        if (event->mask & MK_EVENT_READ) {
            events |= POLLIN;
        }
        if (event->mask & MK_EVENT_WRITE) {
            events |= POLLOUT;
        }

        ctx->pfds[count].fd = (SOCKET) event->fd;
        ctx->pfds[count].events = events;
        ctx->pfds[count].revents = 0;
        ctx->poll_events[count] = event;
        count++;
    }

    if (count == 0) {
        if (timeout > 0) {
            Sleep((DWORD) timeout);
        }
        return 0;
    }

    fired = WSAPoll(ctx->pfds, count, timeout);
    if (fired <= 0) {
        return fired;
    }

    for (i = 0; i < count; i++) {
        revents = ctx->pfds[i].revents;
        if (revents == 0) {
            continue;
        }

        mask = 0;
        if (revents & (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
            mask |= MK_EVENT_READ;
        }
        if (revents & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
            mask |= MK_EVENT_WRITE;
        }
        if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
            mask |= MK_EVENT_CLOSE;
        }

        if (mask == 0) {
            continue;
        }

        ctx->fired[loop->n_events].fd = ctx->poll_events[i]->fd;
        ctx->fired[loop->n_events].mask = mask;
        ctx->fired[loop->n_events].data = ctx->poll_events[i];
        loop->n_events++;
    }

    return loop->n_events;
}

static inline char *_mk_event_backend()
{
    return "win32";
}
