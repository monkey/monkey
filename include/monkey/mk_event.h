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

#include <stdint.h>

#ifndef MK_EVENT_H
#define MK_EVENT_H

/* Event types */
#define MK_EVENT_EMPTY          -1
#define MK_EVENT_SLEEP           0
#define MK_EVENT_READ            1
#define MK_EVENT_WRITE           4
#define MK_EVENT_CLOSE          (16 | 8 | 8192)

/* The event queue size */
#define MK_EVENT_QUEUE_SIZE    256

/* Events behaviors */
#define MK_EVENT_LEVEL         256
#define MK_EVENT_EDGE          512

/*
 * Dirty Abstraction Workaround
 * ============================
 * the purpose of the mk_event interface is to wrap backend polling systems
 * such as epoll and kqueue. But both systems handle very different structures
 * to store the events once they are reported.
 *
 * The common approach would be to let each backend function to go
 * around each reported event and duplicate the info on our own
 * high level structure, but of course that have some performance penalty as the
 * worker will go around the events array twice: once for duplicate and
 * the other to process the events.
 *
 * The following workaround of course is optimized when running on Linux
 * where our high level structure is the same than the used by epoll. When
 * using the kqueue backend the code should do the double work on this.
 *
 * If you have a better idea which is not "ah!, you can use libuv", drop me
 * a line.
 */
typedef union _mk_epoll_data {
    void        *ptr;
    int          fd;
    uint32_t     u32;
    uint64_t     u64;
} _mk_epoll_data_t;

typedef struct  {
    uint32_t       events;      /* Epoll events */
    _mk_epoll_data_t data;        /* User data variable */
} mk_event_t;

/* ---- end of dirty workaround ---- */


/*
 * Events File Descriptor Table (EFDT)
 * ===================================
 * It exposes a global array to hold file descriptor statuses.
 */

struct mk_event_fd_state {
    int fd;
    int mask;
    void *data;
};

typedef struct {
    int size;
    struct mk_event_fd_state *states;
} mk_event_fdt_t;

/* ---- end of EFDT ---- */

typedef struct {
    int size;                  /* size of events array */
    int n_events;
    mk_event_t *events;        /* copy or reference of events triggered */
    void *data;                /* mk_event_ctx_t from backend */
} mk_event_loop_t;


mk_event_fdt_t *mk_events_fdt;

static inline struct mk_event_fd_state *mk_event_get_state(int fd)
{
    return &mk_events_fdt->states[fd];
}

int mk_event_initalize();
mk_event_loop_t *mk_event_loop_create(int size);
int mk_event_add(mk_event_loop_t *loop, int fd, int mask, void *data);
int mk_event_del(mk_event_loop_t *loop, int fd);
int mk_event_timeout_set(mk_event_loop_t *loop, int expire);
int mk_event_wait(mk_event_loop_t *loop);

#endif
