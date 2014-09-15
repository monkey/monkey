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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <monkey/mk_event.h>
#include <monkey/mk_memory.h>

#if defined(__linux__) && !defined(LINUX_KQUEUE)
    #include "mk_event_epoll.c"
#else
    #include "mk_event_kqueue.c"
#endif

/*
 * Initialize the global Event structure used by threads to access the
 * global file descriptor table.
 */
int mk_event_initalize()
{
    int i;
    int ret;
    mk_event_fdt_t *efdt;
    struct rlimit rlim;

    /*
     * Event File Descriptor Table (EFDT)
     * ----------------------------------
     * The main requirement for this implementation is that we need to maintain
     * a state of each file descriptor registered events, such as READ, WRITE,
     * SLEEPING, etc. This is required not by Monkey core but is a fundamental
     * piece to let plugins perform safe operations over file descriptors and
     * their events.
     *
     * The EFDT is created in the main process context and aims to be used by
     * every Worker thread. Once a connection arrives and it's notified to the
     * Worker, this last one will register the file descriptor status on the
     * EFDT.
     *
     * The EFDT is a fixed size array that contains entries for each possible
     * file descriptor number assigned for a TCP connection. In order to make
     * sure the assigned number can be used as an index of the array, we have
     * verified that the Linux Kernel always assigns a number in a range as
     * defined in __alloc_fd() on file file.c:
     *
     *   start: > 2
     *
     *   end  : rlim.rlim.cur
     *
     * The maximum number assigned is always the process soft limit for
     * RLIMIT_NOFILE, so basically we are safe trusting on this model.
     *
     * Note: as we make sure each file descriptor number is only handled by one
     * thread, there is no race conditions.
     */

    efdt = mk_mem_malloc_z(sizeof(mk_event_fdt_t));
    if (!efdt) {
        mk_err("Event: could not allocate memory for event FD Table");
        return -1;
    }

    /*
     * Despites what config->server_capacity says, we need to prepare to handle
     * a high number of file descriptors as process limit allows.
     */
    ret = getrlimit(RLIMIT_NOFILE, &rlim);
    if (ret == -1) {
        mk_libc_error("getrlimit");
        return -1;
    }
    efdt->size = rlim.rlim_cur;
    efdt->states = mk_mem_malloc_z(sizeof(struct mk_event_fd_state) * efdt->size);
    if (!efdt->states) {
        mk_err("Event: could not allocate memory for events states on FD Table");
        return -1;
    }

    /* mark all file descriptors as available */
    for (i = 0; i < efdt->size; i++) {
        efdt->states[i].fd   = -1;
        efdt->states[i].mask = MK_EVENT_EMPTY;
    }

    mk_events_fdt = efdt;
    return 0;
}

/* Create a new loop */
mk_event_loop_t *mk_event_loop_create(int size)
{
    void *backend;
    mk_event_loop_t *loop;

    backend = _mk_event_loop_create(size);
    if (!backend) {
        return NULL;
    }

    loop = mk_mem_malloc_z(sizeof(mk_event_loop_t));
    if (!loop) {
        return NULL;
    }

    loop->events = mk_mem_malloc_z(sizeof(mk_event_t) * size);
    if (!loop->events) {
        mk_mem_free(loop);
        return NULL;
    }

    loop->size   = size;
    loop->data   = backend;

    return loop;
}

/* Register or modify an event */
int mk_event_add(mk_event_loop_t *loop, int fd, int mask, void *data)
{
    int ret;
    mk_event_ctx_t *ctx;
    struct mk_event_fd_state *fds;

    ctx = loop->data;
    ret = _mk_event_add(ctx, fd, mask);
    if (ret == -1) {
        return -1;
    }

    fds = mk_event_get_state(fd);
    fds->mask |= mask;
    fds->data  = data;

    return 0;
}

/* Remove an event */
int mk_event_del(mk_event_loop_t *loop, int fd)
{
    int ret;
    mk_event_ctx_t *ctx;
    struct mk_event_fd_state *fds;

    ctx = loop->data;

    ret = _mk_event_del(ctx, fd);
    if (ret == -1) {
        return -1;
    }

    fds = mk_event_get_state(fd);
    fds->mask = MK_EVENT_EMPTY;
    fds->data = NULL;

    return 0;
}

/* Create a new timer in the loop */
int mk_event_timeout_create(mk_event_loop_t *loop, int expire)
{
    mk_event_ctx_t *ctx;

    ctx = loop->data;
    return _mk_event_timeout_create(ctx, expire);
}

/* Create a new channel to distribute signals */
int mk_event_channel_create(mk_event_loop_t *loop)
{
    mk_event_ctx_t *ctx;
    ctx = loop->data;

    return _mk_event_channel_create(ctx);
}

/* Poll events */
int mk_event_wait(mk_event_loop_t *loop)
{
    return _mk_event_wait(loop);
}
