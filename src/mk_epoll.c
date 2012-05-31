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
#include "mk_socket.h"
#include "mk_clock.h"
#include "mk_request.h"
#include "mk_config.h"
#include "mk_scheduler.h"
#include "mk_epoll.h"
#include "mk_utils.h"
#include "mk_macros.h"

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
        mk_err("epoll_create() failed");
    }

    return efd;
}

void *mk_epoll_init(int efd, mk_epoll_handlers * handler, int max_events)
{
    int i, fd, ret = -1;
    int num_fds;
    int fds_timeout;

    struct epoll_event *events;
    struct sched_list_node *sched;

    /* Get thread conf */
    sched = mk_sched_get_thread_conf();

    fds_timeout = log_current_utime + config->timeout;
    events = mk_mem_malloc_z(max_events*sizeof(struct epoll_event));

    pthread_mutex_lock(&mutex_worker_init);
    sched->initialized = 1;
    pthread_mutex_unlock(&mutex_worker_init);

    while (1) {
        ret = -1;
        num_fds = epoll_wait(efd, events, max_events, MK_EPOLL_WAIT_TIMEOUT);

        for (i = 0; i < num_fds; i++) {
            fd = events[i].data.fd;

            if (events[i].events & EPOLLIN) {
                MK_TRACE("[FD %i] EPoll Event READ", fd);
                ret = (*handler->read) (fd);
            }
            else if (events[i].events & EPOLLOUT) {
                MK_TRACE("[FD %i] EPoll Event WRITE", fd);
                ret = (*handler->write) (fd);
            }
            else if (events[i].events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
                MK_TRACE("[FD %i] EPoll Event EPOLLHUP/EPOLLER", fd);
                ret = (*handler->error) (fd);
            }

            if (ret < 0) {
                MK_TRACE("[FD %i] Epoll Event FORCE CLOSE | ret = %i", fd, ret);
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

int mk_epoll_add(int efd, int fd, int init_mode, int behavior)
{
    int ret;
    struct epoll_event event = {0, {0}};

    event.data.fd = fd;
    event.events = EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    if (behavior == MK_EPOLL_EDGE_TRIGGERED) {
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

    ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    if (ret < 0 && errno != EEXIST) {
        MK_TRACE("[FD %i] epoll_ctl()", fd, strerror(errno));
        return ret;
    }

    return ret;
}

int mk_epoll_del(int efd, int fd)
{
    int ret;

    ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
    MK_TRACE("Epoll, removing fd %i from efd %i", fd, efd);

    if (ret < 0) {
        perror("epoll_ctl");
    }
    return ret;
}

int mk_epoll_change_mode(int efd, int fd, int mode, int behavior)
{
    int ret;
    struct epoll_event event = {0, {0}};

    event.events = EPOLLERR | EPOLLHUP;
    event.data.fd = fd;

    if (behavior == MK_EPOLL_EDGE_TRIGGERED) {
        event.events |= EPOLLET;
    }

    switch (mode) {
    case MK_EPOLL_READ:
        MK_TRACE("[FD %i] EPoll changing mode to READ", fd);
        event.events |= EPOLLIN;
        break;
    case MK_EPOLL_WRITE:
        MK_TRACE("[FD %i] EPoll changing mode to WRITE", fd);
        event.events |= EPOLLOUT;
        break;
    case MK_EPOLL_RW:
        MK_TRACE("[FD %i] Epoll changing mode to READ/WRITE", fd);
        event.events |= EPOLLIN | EPOLLOUT;
        break;
    }

    ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    if (ret < 0) {
        perror("epoll_ctl");
    }
    return ret;
}
