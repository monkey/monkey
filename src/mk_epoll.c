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

pthread_key_t mk_epoll_state_k;

/*
 * Initialize the epoll state index per worker thread, every index struct contains
 * a fixed array of epoll_state entries and two mk_list to represent an available and
 * busy queue for each entry
 */
int mk_epoll_state_init()
{
    int i;
    struct epoll_state *es;
    struct epoll_state_index *index;

    index = mk_mem_malloc_z(sizeof(struct epoll_state_index));
    index->size  = MK_EPOLL_STATE_INDEX_CHUNK;
    mk_list_init(&index->busy_queue);
    mk_list_init(&index->av_queue);

    for (i = 0; i < index->size; i++) {
        es = mk_mem_malloc_z(sizeof(struct epoll_state));
        mk_list_add(&es->_head, &index->av_queue);
    }

    return pthread_setspecific(mk_epoll_state_k, (void *) index);
}

inline struct epoll_state *mk_epoll_state_set(int efd, int fd, uint8_t mode,
                                              uint8_t  behavior,
                                              uint32_t events)
{
    int i;
    struct epoll_state_index *index;
    struct epoll_state *es_entry = NULL, *es_tmp;
    struct mk_list *head;

    index = (struct epoll_state_index *) pthread_getspecific(mk_epoll_state_k);

    /*
     * Lets check if we are in the thread context, if dont, this can be the
     * situation when the file descriptor is new and comes from the parent
     * server loop and is just being assigned to the worker thread
     */
    if (mk_unlikely(!index)) {
        return NULL;
    }

    mk_list_foreach(head, &index->busy_queue) {
        es_entry = mk_list_entry(head, struct epoll_state, _head);
        if (es_entry->instance == efd && es_entry->fd == fd) {
            break;
        }
        es_entry = NULL;
    }

    /* Add new entry to the list */
    if (!es_entry) {

        /* check if we have available slots */
        if (mk_list_is_empty(&index->av_queue) == 0) {

            /* We need to grow the epoll_states list */
            for (i = 0; i < MK_EPOLL_STATE_INDEX_CHUNK; i++) {
                es_tmp = mk_mem_malloc(sizeof(struct epoll_state));
                mk_list_add(&es_tmp->_head, &index->av_queue);
            }
            MK_TRACE("state index size=%i, grow from %i to %i",
                     index->size, index->size + MK_EPOLL_STATE_INDEX_CHUNK);
            index->size += MK_EPOLL_STATE_INDEX_CHUNK;

        }

        /* New entry */
        es_entry = mk_list_entry_first(&index->av_queue, struct epoll_state, _head);
        es_entry->instance = efd;
        es_entry->fd       = fd;
        es_entry->mode     = mode;
        es_entry->behavior = behavior;
        es_entry->events   = events;

        /* Unlink from available queue and link to busy queue */
        mk_list_del(&es_entry->_head);
        mk_list_add(&es_entry->_head, &index->busy_queue);

        return es_entry;
    }

    /*
     * Sleep mode: the sleep mode disable the events in the epoll queue so the Kernel
     * will not trigger any events, when mode == MK_EPOLL_SLEEP, the epoll_state events
     * keeps the previous events state which can be used in the MK_EPOLL_WAKEUP routine.
     *
     * So we just touch the events and behavior state fields if mode != MK_EPOLL_SLEEP.
     */
    if (mode != MK_EPOLL_SLEEP) {
        es_entry->events   = events;
        es_entry->behavior = behavior;
    }

    /* Update current mode */
    es_entry->mode = mode;

    return es_entry;
}

static struct epoll_state *mk_epoll_state_get(int efd, int fd)
{
    struct epoll_state_index *index;
    struct epoll_state *es_entry;
    struct mk_list *head, *tmp;

    index = pthread_getspecific(mk_epoll_state_k);
    mk_list_foreach_safe(head, tmp, &index->busy_queue) {
        es_entry = mk_list_entry(head, struct epoll_state, _head);
        if (es_entry->instance == efd && es_entry->fd == fd) {
            return es_entry;
        }
    }

    return NULL;
}

static int mk_epoll_state_del(int efd, int fd)
{
    struct epoll_state_index *index;
    struct epoll_state *es_entry;
    struct mk_list *head, *tmp;

    index = pthread_getspecific(mk_epoll_state_k);
    mk_list_foreach_safe(head, tmp, &index->busy_queue) {
        es_entry = mk_list_entry(head, struct epoll_state, _head);
        if (es_entry->instance == efd && es_entry->fd == fd) {
            mk_list_del(&es_entry->_head);
            mk_list_add(&es_entry->_head, &index->av_queue);
            return 0;
        }
    }

    return -1;
}

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
    case MK_EPOLL_SLEEP:
        event.events = 0;
        break;
    }

    /* Add to epoll queue */
    ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    if (mk_unlikely(ret < 0 && errno != EEXIST)) {
        MK_TRACE("[FD %i] epoll_ctl() %s", fd, strerror(errno));
        return ret;
    }

    /* Add to event state list */
    mk_epoll_state_set(efd, fd, init_mode, behavior, event.events);

    return ret;
}

int mk_epoll_del(int efd, int fd)
{
    int ret;

    ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
    MK_TRACE("Epoll, removing fd %i from efd %i", fd, efd);

#ifdef TRACE
    if (ret < 0) {
        MK_TRACE("[FD %i] epoll_ctl() = %i", fd, ret);
        perror("epoll_ctl");
    }
#endif

    /* remove epoll state */
    mk_epoll_state_del(efd, fd);

    return ret;
}

int mk_epoll_change_mode(int efd, int fd, int mode, int behavior)
{
    int ret;
    struct epoll_event event = {0, {0}};
    struct epoll_state *state;

    event.events = EPOLLERR | EPOLLHUP;
    event.data.fd = fd;

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
    case MK_EPOLL_SLEEP:
        MK_TRACE("[FD %i] Epoll changing mode to DISABLE", fd);
        event.events = 0;
        break;
    case MK_EPOLL_WAKEUP:
        state = mk_epoll_state_get(efd, fd);
        if (state && state->mode == MK_EPOLL_SLEEP) {
            event.events = state->events;
            behavior     = state->behavior;
        }
        else {
            mk_err("[FD %i] MK_EPOLL_WAKEUP error", fd);
            exit(EXIT_FAILURE);
        }
        break;
    }

    if (behavior == MK_EPOLL_EDGE_TRIGGERED) {
        event.events |= EPOLLET;
    }

    /* Update epoll fd events */
    ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
#ifdef TRACE
    if (ret < 0) {
        MK_TRACE("[FD %i] epoll_ctl() = %i", fd, ret);
        perror("epoll_ctl");
    }
#endif

    /* Update state */
    mk_epoll_state_set(efd, fd, mode, behavior, event.events);
    return ret;
}
