
/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P. <edsiper@gmail.com>
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
    struct sched_list_node *sl, *last;

    sl = mk_mem_malloc_z(sizeof(struct sched_list_node));
    sl->tid = tid;
    sl->pid = -1;
    sl->epoll_fd = efd;
    sl->active_connections = 0;
    sl->queue = mk_mem_malloc_z(sizeof(struct sched_connection) *
                                config->worker_capacity);
    sl->request_handler = NULL;

    for (i = 0; i < config->worker_capacity; i++) {
        /* Pre alloc IPv4 memory buffer */
	sl->queue[i].ipv4.data = mk_mem_malloc_z(16);
        sl->queue[i].status = MK_SCHEDULER_CONN_AVAILABLE;

        if (!sl->queue[i].ipv4.data) {
          mk_error(MK_ERROR_FATAL, "Could not initialize memory for IP cache queue. Aborting");
        }
    }

    if (!sched_list) {
        sl->idx = 1;

        /* Alloc and init list */
        sched_list = mk_mem_malloc(sizeof(struct mk_list));
        if (!sched_list) {
            mk_error(MK_ERROR_FATAL, "Could not initialize memory for Scheduler list. Aborting");
        }

        mk_list_init(sched_list);

        mk_list_add(&sl->_head, sched_list);
        return 0;
    }

    /* Update index with last node from the sched_list */
    last = mk_list_entry_last(sched_list, struct sched_list_node, _head);
    sl->idx = last->idx + 1;

    /* Add node to list */
    mk_list_add(&sl->_head, sched_list);

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
    thconf->epoll_max_events = max_events*2;
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

void mk_sched_thread_lists_init()
{
    struct mk_list *cs_list;

    /* client_session mk_list */
    cs_list = mk_mem_malloc(sizeof(struct mk_list));
    mk_list_init(cs_list);
    mk_sched_set_request_list(cs_list);
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
    mk_sched_thread_lists_init();
    mk_cache_thread_init();

    /* Plugin thread context calls */
    mk_plugin_event_init_list();
    mk_plugin_core_thread();

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
    mk_epoll_init(thconf->epoll_fd, handler, thconf->epoll_max_events);

    return 0;
}

struct mk_list *mk_sched_get_request_list()
{
    return pthread_getspecific(request_list);
}

void mk_sched_set_request_list(struct mk_list *list)
{
    pthread_setspecific(request_list, (void *) list);
}

void mk_sched_set_thread_poll(int epoll)
{
    pthread_setspecific(epoll_fd, (void *) (size_t) epoll);
}

int mk_sched_get_thread_poll()
{
    return (size_t) pthread_getspecific(epoll_fd);
}

struct sched_list_node *mk_sched_get_thread_conf()
{
    struct mk_list *list_node;
    struct sched_list_node *node;
    pthread_t current;

    current = pthread_self();

    mk_list_foreach(list_node, sched_list) {
        node = mk_list_entry(list_node, struct sched_list_node, _head);
        if (pthread_equal(node->tid, current) != 0) {
            return node;
        }
    }

    return NULL;
}

int mk_sched_add_client(int remote_fd)
{
    unsigned int i, ret;
    struct mk_list *sched_head;
    struct sched_list_node *node=NULL, *sched=NULL;

    sched = mk_list_entry_first(sched_list, struct sched_list_node, _head);

    /* Look for worker with less overhead */
    mk_list_foreach(sched_head, sched_list) {
      node = mk_list_entry(sched_head, struct sched_list_node, _head);
    
      if (node->active_connections == 0) {
        sched = node;
        break;
      }
      else {
        if (node->active_connections < sched->active_connections) {
          sched = node;
        }
      }
    }

#ifdef TRACE
    MK_TRACE("[FD %i] Balance to WID %i", remote_fd, sched->idx);
#endif

    for (i = 0; i < config->worker_capacity; i++) {
        if (sched->queue[i].status == MK_SCHEDULER_CONN_AVAILABLE) {
#ifdef TRACE
            MK_TRACE("[FD %i] Add", remote_fd);
#endif
            /* Set IP */
            mk_socket_get_ip(remote_fd, sched->queue[i].ipv4.data);
            mk_pointer_set(&sched->queue[i].ipv4, sched->queue[i].ipv4.data);

            /* Before to continue, we need to run plugin stage 10 */
            ret = mk_plugin_stage_run(MK_PLUGIN_STAGE_10,
                                      remote_fd,
                                      &sched->queue[i], NULL, NULL);

            /* Close connection, otherwise continue */
            if (ret == MK_PLUGIN_RET_CLOSE_CONX) {
                mk_conn_close(remote_fd);
                return MK_PLUGIN_RET_CLOSE_CONX;
            }

            /* Socket and status */
            sched->active_connections++;
            sched->queue[i].socket = remote_fd;
            sched->queue[i].status = MK_SCHEDULER_CONN_PENDING;
            sched->queue[i].arrive_time = log_current_utime;

            mk_epoll_add(sched->epoll_fd, remote_fd, MK_EPOLL_READ,
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
#ifdef TRACE
        MK_TRACE("[FD %i] Scheduler remove", remote_fd);
#endif
        /* Close socket and change status */
        close(remote_fd);

        /* Invoke plugins in stage 50 */
        mk_plugin_stage_run(MK_PLUGIN_STAGE_50, remote_fd, NULL, NULL, NULL);

        /* Change node status */
        sched->active_connections--;
        sc->status = MK_SCHEDULER_CONN_AVAILABLE;
        sc->socket = -1;
        return 0;
    }
#ifdef TRACE
    else {
        MK_TRACE("[FD %i] Not found", remote_fd);
    }
#endif
    return -1;
}

struct sched_connection *mk_sched_get_connection(struct sched_list_node
                                                 *sched, int remote_fd)
{
    int i;

    if (!sched) {
        sched = mk_sched_get_thread_conf();
        if (!sched) {
#ifdef TRACE
            MK_TRACE("[FD %i] No scheduler information", remote_fd);
#endif 
            close(remote_fd);
            return NULL;
        }
    }

    for (i = 0; i < config->worker_capacity; i++) {
        if (sched->queue[i].socket == remote_fd) {
            return &sched->queue[i];
        }
    }

#ifdef TRACE
    MK_TRACE("[FD %i] not found in scheduler list", remote_fd);
#endif

    return NULL;
}

int mk_sched_check_timeouts(struct sched_list_node *sched)
{
    int i, client_timeout;
    struct client_session *cs_node;
    struct mk_list *cs_list, *cs_head, *cs_temp;

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
    cs_list = mk_sched_get_request_list();

    mk_list_foreach_safe(cs_head, cs_temp, cs_list) {
        cs_node = mk_list_entry(cs_head, struct client_session, _head);

        if (cs_node->status == MK_REQUEST_STATUS_INCOMPLETE) {
            if (cs_node->counter_connections == 0) {
                client_timeout = cs_node->init_time + config->timeout;
            }
            else {
                client_timeout = cs_node->init_time + config->keep_alive_timeout;
            }

            /* Check timeout */
            if (client_timeout <= log_current_utime) {
#ifdef TRACE
                MK_TRACE("[FD %i] Scheduler, closing due to timeout (incomplete)",
                         cs_node->socket);
#endif
                close(cs_node->socket);
                mk_sched_remove_client(sched, cs_node->socket);
                mk_session_remove(cs_node->socket);
            }
        }
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
