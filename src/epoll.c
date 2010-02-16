/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "monkey.h"
#include "socket.h"
#include "clock.h"
#include "request.h"
#include "config.h"
#include "scheduler.h"
#include "epoll.h"

#define MAX_EVENTS 5000

mk_epoll_handlers *mk_epoll_set_handlers(void (*read) (int),
                                         void (*write) (int),
                                         void (*error) (int),
                                         void (*close) (int),
                                         void (*timeout) (int))
{
    mk_epoll_handlers *handler;

    handler = malloc(sizeof(mk_epoll_handlers));
    handler->read = (void *) read;
    handler->write = (void *) write;
    handler->error = (void *) error;
    handler->close = (void *) close;
    handler->timeout = (void *) timeout;

    return handler;
}

int mk_epoll_create(int max_events)
{
    int efd;

    efd = epoll_create(max_events);
    if (efd == -1) {
        perror("epoll_create");
    }

    return efd;
}

void *mk_epoll_init(int efd, mk_epoll_handlers * handler, int max_events)
{
    int i, fd, ret = -1;
    int num_fds;
    int fds_timeout;
    struct epoll_event events[max_events];
    struct sched_list_node *sched;

    /* Get thread conf */
    sched = mk_sched_get_thread_conf();

    pthread_mutex_lock(&mutex_wait_register);
    pthread_mutex_unlock(&mutex_wait_register);

    fds_timeout = log_current_utime + config->timeout;

    while (1) {
        num_fds = epoll_wait(efd, events, max_events, MK_EPOLL_WAIT_TIMEOUT);

        for (i = 0; i < num_fds; i++) {
            fd = events[i].data.fd;

            // Case 1: Error condition
            if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                (*handler->error) (fd);
                continue;
            }

            if (events[i].events & EPOLLIN) {
                ret = (*handler->read) (fd);
            }
            else if (events[i].events & EPOLLOUT) {
                ret = (*handler->write) (fd);
            }

            if (ret < 0) {
                (*handler->close) (fd);
            }
        }

        /* Check timeouts and update next one */
        if (log_current_utime >= fds_timeout) {
            mk_sched_check_timeouts(sched);
            fds_timeout = log_current_utime + config->timeout;
        }
    }
}

int mk_epoll_add_client(int efd, int socket, int init_mode, int behavior)
{
    int ret;
    struct epoll_event event;


    event.events = EPOLLERR | EPOLLHUP;
    event.data.fd = socket;

    if (behavior == MK_EPOLL_BEHAVIOR_TRIGGERED) {
        event.events |= EPOLLET;
    }

    switch (init_mode) {
    case MK_EPOLL_READ:
        event.events |= EPOLLIN;
        break;
    case MK_EPOLL_WRITE:
        event.events |= EPOLLOUT;
        break;
    case MK_EPOLL_RW:
        event.events |= EPOLLIN | EPOLLOUT;
        break;
    }

    ret = epoll_ctl(efd, EPOLL_CTL_ADD, socket, &event);
    if (ret < 0) {
        perror("epoll_ctl");
    }
    return ret;
}

int mk_epoll_socket_change_mode(int efd, int socket, int mode)
{
    int ret;
    struct epoll_event event;

    event.events = EPOLLET | EPOLLERR | EPOLLHUP;
    event.data.fd = socket;

    switch (mode) {
    case MK_EPOLL_READ:
        event.events |= EPOLLIN;
        break;
    case MK_EPOLL_WRITE:
        event.events |= EPOLLOUT;
        break;
    case MK_EPOLL_RW:
        event.events |= EPOLLIN | EPOLLOUT;
        break;
    }

    ret = epoll_ctl(efd, EPOLL_CTL_MOD, socket, &event);
    if (ret < 0) {
        perror("\nepoll_ctl");
    }
    return ret;
}
