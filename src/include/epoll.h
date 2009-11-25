/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2008, Eduardo Silva P.
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <sys/epoll.h>

#define MK_EPOLL_READ 0
#define MK_EPOLL_WRITE 1
#define MK_EPOLL_RW 2

#define MK_EPOLL_WAIT_TIMEOUT 3000

#define MK_EPOLL_BEHAVIOR_DEFAULT 2 
#define MK_EPOLL_BEHAVIOR_TRIGGERED 3

typedef struct {
        int (*read)(void *);
        int (*write)(void *);
        int (*error)(void *);
        int (*close)(void *);
        int (*timeout)(void *);
} mk_epoll_handlers;

int mk_epoll_create(int max_events);
void *mk_epoll_init(int efd, mk_epoll_handlers *handler, int max_events);

mk_epoll_handlers *mk_epoll_set_handlers(void (*read)(void *),
                                         void (*write)(void *),
                                         void (*error)(void *),
                                         void (*close)(void *),
                                         void (*timeout)(void *));

int mk_epoll_add_client(int efd, int socket, int mode);
int mk_epoll_socket_change_mode(int efd, int socket, int mode);

