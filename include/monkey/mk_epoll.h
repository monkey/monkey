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
#include "mk_rbtree.h"

#ifndef MK_EPOLL_H
#define MK_EPOLL_H

/* Epoll States */
#define MK_EPOLL_HANGUP   0        /* just report connection error issues */
#define MK_EPOLL_READ     1        /* read only                           */
#define MK_EPOLL_WRITE    2        /* write only                          */
#define MK_EPOLL_RW       3        /* read/write                          */
#define MK_EPOLL_SLEEP    4        /* sleep mode, no events triggered     */
#define MK_EPOLL_WAKEUP   5        /* restore status previous sleep mode  */

/* Epoll timeout is 3 seconds */
#define MK_EPOLL_WAIT_TIMEOUT 3000

#define MK_EPOLL_LEVEL_TRIGGERED 2        /* default */
#define MK_EPOLL_EDGE_TRIGGERED  EPOLLET

/*
 * Once a connection is dropped, define
 * a reason.
 */
#define MK_EP_SOCKET_CLOSED   0
#define MK_EP_SOCKET_ERROR    1
#define MK_EP_SOCKET_TIMEOUT  2

/* Just in case RHDUP is not defined */
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

#define MK_EPOLL_STATE_INDEX_CHUNK 64

typedef struct
{
    int (*read) (int);
    int (*write) (int);
    int (*close) (int, int);
} mk_epoll_handlers;

/*
 * An epoll_state represents the state of the descriptor from
 * a Monkey core point of view.
 */
struct epoll_state
{
    int          fd;            /* File descriptor                    */
    uint8_t      mode;          /* Operation mode                     */
    uint32_t     events;        /* Events mask                        */
    unsigned int behavior;      /* Triggered behavior                 */

    struct rb_node _rb_head;
    struct mk_list _head;
};

struct epoll_state_index
{
    int size;

    struct rb_root rb_queue;
    struct mk_list busy_queue;
    struct mk_list av_queue;
};

/* Monkey epoll calls */
int mk_epoll_create();
void *mk_epoll_init(int server_fd, int efd, int max_events);
struct epoll_state *mk_epoll_state_get(int fd);

int mk_epoll_add(int efd, int fd, int mode, unsigned int behavior);
int mk_epoll_del(int efd, int fd);
int mk_epoll_change_mode(int efd, int fd, int mode, unsigned int behavior);

/* epoll state handlers */
struct epoll_state *mk_epoll_state_set(int fd, uint8_t mode,
                                       unsigned int behavior,
                                       uint32_t events);
int mk_epoll_state_init();

#endif
