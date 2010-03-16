/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P. <edsiper@gmail.com>
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
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

#include "monkey.h"
#include "connection.h"
#include "scheduler.h"
#include "memory.h"
#include "epoll.h"
#include "request.h"
#include "cache.h"
#include "config.h"
#include "clock.h"
#include "signals.h"
#include "plugin.h"
#include "utils.h"

/* Register thread information */
int mk_sched_register_thread(pthread_t tid, int efd)
{
    int i;
    struct sched_list_node *sr, *aux;

    sr = mk_mem_malloc_z(sizeof(struct sched_list_node));
    sr->tid = tid;
    sr->pid = -1;
    sr->epoll_fd = efd;
    sr->queue = mk_mem_malloc_z(sizeof(struct sched_connection) *
                                config->worker_capacity);
    sr->request_handler = NULL;
    sr->next = NULL;

    for (i = 0; i < config->worker_capacity; i++) {
        /* Pre alloc IPv4 memory buffer */
        sr->queue[i].ipv4.data = mk_mem_malloc_z(16);
        sr->queue[i].status = MK_SCHEDULER_CONN_AVAILABLE;
    }

    if (!sched_list) {
        sr->idx = 1;
        sched_list = sr;
        return 0;
    }

    aux = sched_list;
    while (aux->next) {
        aux = aux->next;
    }
    sr->idx = aux->idx + 1;
    aux->next = sr;

    return 0;
}

/*
 * Create thread which will be listening 
 * for incomings file descriptors
 */
int mk_sched_launch_thread(int max_events)
{
    int efd;
    pthread_t tid;
    pthread_attr_t attr;
    sched_thread_conf *thconf;
    pthread_mutex_t mutex_wait_register;

    /* Creating epoll file descriptor */
    efd = mk_epoll_create(max_events);
    if (efd < 1) {
        return -1;
    }

    /* Thread stuff */
    pthread_mutex_init(&mutex_wait_register, (pthread_mutexattr_t *) NULL);
    pthread_mutex_lock(&mutex_wait_register);

    thconf = mk_mem_malloc(sizeof(sched_thread_conf));
    thconf->epoll_fd = efd;
    thconf->max_events = max_events;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, mk_sched_launch_epoll_loop,
                       (void *) thconf) != 0) {
        perror("pthread_create");
        return -1;
    }

    /* Register working thread */
    mk_sched_register_thread(tid, efd);
    pthread_mutex_unlock(&mutex_wait_register);

    return 0;
}

/* created thread, all this calls are in the thread context */
void *mk_sched_launch_epoll_loop(void *thread_conf)
{
    sched_thread_conf *thconf;
    struct sched_list_node *thinfo;
    mk_epoll_handlers *handler;

    /* Avoid SIGPIPE signals */
    mk_signal_thread_sigpipe_safe();

    thconf = thread_conf;

    /* Init specific thread cache */
    mk_cache_thread_init();
    mk_plugin_worker_startup();

    /* Epoll event handlers */
    handler = mk_epoll_set_handlers((void *) mk_conn_read,
                                    (void *) mk_conn_write,
                                    (void *) mk_conn_error,
                                    (void *) mk_conn_close,
                                    (void *) mk_conn_timeout);

    /* Nasty way to export task id */
    usleep(1000);
    thinfo = mk_sched_get_thread_conf();
    while (!thinfo) {
        thinfo = mk_sched_get_thread_conf();
    }

    /* Glibc doesn't export to user space the gettid() syscall */
    thinfo->pid = syscall(__NR_gettid);

    mk_sched_set_thread_poll(thconf->epoll_fd);
    mk_epoll_init(thconf->epoll_fd, handler, thconf->max_events);

    return 0;
}

struct request_idx *mk_sched_get_request_index()
{
    return pthread_getspecific(request_index);
}

void mk_sched_set_request_index(struct request_idx *ri)
{
    pthread_setspecific(request_index, (void *) ri);
}

void mk_sched_set_thread_poll(int epoll)
{
    pthread_setspecific(epoll_fd, (void *) epoll);
}

int mk_sched_get_thread_poll()
{
    return (int) pthread_getspecific(epoll_fd);
}

struct sched_list_node *mk_sched_get_thread_conf()
{
    struct sched_list_node *node;
    pthread_t current;

    current = pthread_self();
    node = sched_list;
    while (node) {
        if (pthread_equal(node->tid, current) != 0) {
            return node;
        }
        node = node->next;
    }

    return NULL;
}

int mk_sched_add_client(struct sched_list_node *sched, int remote_fd)
{
    unsigned int i, ret;

    /* Look for an available slot */
    for (i = 0; i < config->worker_capacity; i++) {
        if (sched->queue[i].status == MK_SCHEDULER_CONN_AVAILABLE) {
            /* Set IP */
            mk_socket_get_ip(remote_fd, sched->queue[i].ipv4.data);
            mk_pointer_set( &sched->queue[i].ipv4, sched->queue[i].ipv4.data );

            /* Before to continue, we need to run plugin stage 20 */
            ret = mk_plugin_stage_run(MK_PLUGIN_STAGE_20,
                                      remote_fd,
                                      &sched->queue[i], NULL, NULL);

            /* Close connection, otherwise continue */
            if (ret == MK_PLUGIN_RET_CLOSE_CONX) {
                mk_conn_close(remote_fd);
                return MK_PLUGIN_RET_CLOSE_CONX;
            }

            /* Socket and status */
            sched->queue[i].socket = remote_fd;
            sched->queue[i].status = MK_SCHEDULER_CONN_PENDING;
            sched->queue[i].arrive_time = log_current_utime;

            mk_epoll_add_client(sched->epoll_fd, remote_fd, MK_EPOLL_READ,
                                MK_EPOLL_BEHAVIOR_TRIGGERED);
            return 0;
        }
    }

    return -1;
}

int mk_sched_remove_client(struct sched_list_node *sched, int remote_fd)
{
    struct sched_connection *sc;

    sc = mk_sched_get_connection(sched, remote_fd);
    if (sc) {
        /* Close socket and change status */
        close(remote_fd);
        sc->status = MK_SCHEDULER_CONN_AVAILABLE;
        return 0;
    }
    return -1;
}

struct sched_connection *mk_sched_get_connection(struct sched_list_node
                                                 *sched, int remote_fd)
{
    int i;

    if (!sched) {
        sched = mk_sched_get_thread_conf();
        if (!sched) {
            close(remote_fd);
            return NULL;
        }
    }

    for (i = 0; i < config->worker_capacity; i++) {
        if (sched->queue[i].socket == remote_fd) {
            return &sched->queue[i];
        }
    }

    return NULL;
}

int mk_sched_check_timeouts(struct sched_list_node *sched)
{
    int i, client_timeout;
    struct request_idx *req_idx;
    struct client_request *req_cl;

    /* PENDING CONN TIMEOUT */
    for (i = 0; i < config->worker_capacity; i++) {
        if (sched->queue[i].status == MK_SCHEDULER_CONN_PENDING) {
            client_timeout = sched->queue[i].arrive_time + config->timeout;

            /* Check timeout */
            if (client_timeout <= log_current_utime) {
#ifdef TRACE
                MK_TRACE("Scheduler, closing fd %i due TIMEOUT", 
                         sched->queue[i].socket);
#endif
                mk_sched_remove_client(sched, sched->queue[i].socket);
            }
        }
    }

    /* PROCESSING CONN TIMEOUT */
    req_idx = mk_sched_get_request_index();
    req_cl = req_idx->first;

    while (req_cl) {
        if (req_cl->status == MK_REQUEST_STATUS_INCOMPLETE) {
            if (req_cl->counter_connections == 0) {
                client_timeout = req_cl->init_time + config->timeout;
            }
            else {
                client_timeout = req_cl->init_time + config->keep_alive_timeout;
            }

            /* Check timeout */
            if (client_timeout <= log_current_utime) {
#ifdef TRACE
                MK_TRACE("Scheduler, closing fd %i due to timeout (incomplete)",
                         req_cl->socket);
#endif
                close(req_cl->socket);
            }
        }
        req_cl = req_cl->next;
    }

    return 0;
}

int mk_sched_update_conn_status(struct sched_list_node *sched,
                                int remote_fd, int status)
{
    int i;
    
    if (!sched) {
        return -1;
    }
    
    for (i = 0; i < config->workers; i++) {
        if (sched->queue[i].socket == remote_fd) {
            sched->queue[i].status = status;
            return 0;
        }
    }
    return 0;
}
