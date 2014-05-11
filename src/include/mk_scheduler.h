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

#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mk_list.h"
#include "mk_lib.h"
#include "mk_rbtree.h"

#ifndef MK_SCHEDULER_H
#define MK_SCHEDULER_H

#define MK_SCHEDULER_CONN_AVAILABLE  -1
#define MK_SCHEDULER_CONN_PENDING     0
#define MK_SCHEDULER_CONN_PROCESS     1
#define MK_SCHEDULER_SIGNAL_DEADBEEF  0xDEADBEEF

/*
 * Scheduler balancing mode:
 *
 * - Fair Balancing: use a single socket and upon accept
 *   new connections, lookup the less loaded thread and
 *   assign the socket to that specific epoll queue.
 *
 * - ReusePort: Use new Linux Kernel 3.14 feature that
 *   allows thread to share binded address on a lister
 *   socket. We let the Kernel to decide how to balance.
 */
#define MK_SCHEDULER_FAIR_BALANCING   0
#define MK_SCHEDULER_REUSEPORT        1

extern __thread struct rb_root *cs_list;

struct sched_connection
{
    struct rb_node _rb_head; /* red-black tree head */

    int socket;              /* file descriptor     */
    int status;              /* connection status   */
    time_t arrive_time;      /* arrived time        */
    struct mk_list _head;    /* list head           */
    uint32_t events;         /* epoll events        */
};

/* Global struct */
struct sched_list_node
{
    unsigned long long accepted_connections;
    unsigned long long closed_connections;

    /* Just used on MK_SCHEDULER_REUSEPORT mode */
    int server_fd;

    /*
     * Red-Black tree queue to perform fast lookup over
     * the scheduler busy queue
     */
    struct rb_root rb_queue;

    /* Available and busy queue */
    struct mk_list busy_queue;
    struct mk_list av_queue;

    short int idx;
    unsigned char initialized;
    int epoll_fd;

    pthread_t tid;
    pid_t pid;

    struct client_session *request_handler;

    /*
     * This variable is used to signal the active workers,
     * just available because of ULONG_MAX bug described
     * on mk_scheduler.c .
     */
    int signal_channel;

#ifdef SHAREDLIB
    mklib_ctx ctx;
#endif
};


/* global scheduler list */
struct sched_list_node *sched_list;

/* Struct under thread context */
typedef struct
{
    int server_fd;
    int epoll_fd;
    int epoll_max_events;
    int max_events;

#ifdef SHAREDLIB
    mklib_ctx ctx;
#endif
} sched_thread_conf;

pthread_key_t MK_EXPORT worker_sched_node;
extern pthread_mutex_t mutex_worker_init;
pthread_mutex_t mutex_port_init;

void mk_sched_init();
int mk_sched_launch_thread(int max_events, pthread_t *tout, mklib_ctx ctx);
void *mk_sched_launch_epoll_loop(void *thread_conf);
struct sched_list_node *mk_sched_get_handler_owner(void);

// Re-declared here, because we can't include mk_request.h
extern pthread_key_t request_list;

static inline struct rb_root *mk_sched_get_request_list()
{
    return cs_list;
}

static inline struct sched_list_node *mk_sched_get_thread_conf()
{
    return pthread_getspecific(worker_sched_node);
}

void mk_sched_update_thread_status(struct sched_list_node *sched,
                                   int active, int closed);


int mk_sched_check_timeouts(struct sched_list_node *sched);
int mk_sched_add_client(int remote_fd);
int mk_sched_add_client_reuseport(int remote_fd, struct sched_list_node *sched);
int mk_sched_register_client(int remote_fd, struct sched_list_node *sched);
int mk_sched_remove_client(struct sched_list_node *sched, int remote_fd);
struct sched_connection *mk_sched_get_connection(struct sched_list_node
                                                     *sched, int remote_fd);
int mk_sched_update_conn_status(struct sched_list_node *sched, int remote_fd,
                                int status);
int mk_sched_sync_counters();

#endif
