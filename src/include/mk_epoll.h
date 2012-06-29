/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <sys/epoll.h>

#ifndef MK_EPOLL_H
#define MK_EPOLL_H

#define MK_EPOLL_READ     0
#define MK_EPOLL_WRITE    1
#define MK_EPOLL_RW       2
#define MK_EPOLL_DISABLE  3

/* Epoll timeout is 3 seconds */
#define MK_EPOLL_WAIT_TIMEOUT 3000

#define MK_EPOLL_LEVEL_TRIGGERED 2        /* default */
#define MK_EPOLL_EDGE_TRIGGERED  EPOLLET

#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

typedef struct
{
    int (*read) (int);
    int (*write) (int);
    int (*error) (int);
    int (*close) (int);
    int (*timeout) (int);
} mk_epoll_handlers;

int mk_epoll_create(int max_events);
void *mk_epoll_init(int efd, mk_epoll_handlers * handler, int max_events);

mk_epoll_handlers *mk_epoll_set_handlers(void (*read) (int),
                                         void (*write) (int),
                                         void (*error) (int),
                                         void (*close) (int),
                                         void (*timeout) (int));

int mk_epoll_add(int efd, int fd, int mode, int behavior);
int mk_epoll_del(int efd, int fd);
int mk_epoll_change_mode(int efd, int fd, int mode, int behavior);

#endif
