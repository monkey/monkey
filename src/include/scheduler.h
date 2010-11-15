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

#ifndef MK_SCHEDULER_H
#define MK_SCHEDULER_H

#include "list.h"
#include <pthread.h>

#define MK_SCHEDULER_CONN_AVAILABLE -1
#define MK_SCHEDULER_CONN_PENDING 0
#define MK_SCHEDULER_CONN_PROCESS 1

struct sched_connection
{
    int socket;
    int status;
    mk_pointer ipv4;
    time_t arrive_time;
};

/* Global struct */
struct sched_list_node
{
    short int idx;
    pthread_t tid;
    pid_t pid;
    int epoll_fd;
    unsigned int active_connections;

    struct sched_connection *queue;
    struct client_session *request_handler;

    struct mk_list _head;
};

struct mk_list *sched_list;

/* Struct under thread context */
typedef struct
{
    int epoll_fd;
    int epoll_max_events;
    int max_events;
} sched_thread_conf;

pthread_key_t epoll_fd;

int mk_sched_register_thread(pthread_t tid, int epoll_fd);
int mk_sched_launch_thread(int max_events);
void *mk_sched_launch_epoll_loop(void *thread_conf);
struct sched_list_node *mk_sched_get_handler_owner();

struct mk_list *mk_sched_get_request_list();
void mk_sched_set_request_list(struct mk_list *list);

int mk_sched_get_thread_poll();
void mk_sched_set_thread_poll(int epoll);

struct sched_list_node *mk_sched_get_thread_conf();
void mk_sched_update_thread_status(struct sched_list_node *sched,
                                   int active, int closed);


int mk_sched_check_timeouts(struct sched_list_node *sched);
int mk_sched_add_client(int remote_fd);
int mk_sched_remove_client(struct sched_list_node *sched, int remote_fd);
struct sched_connection *mk_sched_get_connection(struct sched_list_node
                                                 *sched, int remote_fd);
int mk_sched_update_conn_status(struct sched_list_node *sched, int remote_fd,
                                int status);

#endif
