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

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/time.h>
#include <sys/resource.h>

#include "monkey.h"
#include "config.h"
#include "scheduler.h"
#include "epoll.h"
#include "socket.h"
#include "plugin.h"
#include "utils.h"
#include "macros.h"

/* Return the number of clients that can be attended
 * at the same time per worker thread
 */
int mk_server_worker_capacity(int nworkers)
{
    int max, avl;
    struct rlimit lim;

    /* Limit by system */
    getrlimit(RLIMIT_NOFILE, &lim);
    max = lim.rlim_cur;

    /* Minimum of fds needed by Monkey:
     * --------------------------------
     * 3 fds: stdin, stdout, stderr
     * 1 fd for main socket server
     * 1 fd for epoll array (per thread)
     * 1 fd for worker logger when writing to FS
     * 2 fd for worker logger pipe
     */

    avl = max - (3 + 1 + nworkers + 1 + 2);

    /* The avl is divided by two as we need to consider
     * a possible additional FD for each plugin working
     * on the same request.
     */
    return ((avl / 2) / nworkers);
}

/* Here we launch the worker threads to attend clients */
void mk_server_launch_workers()
{
    int i;

    /* Launch workers */
    for (i = 0; i < config->workers; i++) {
        mk_sched_launch_thread(i, config->worker_capacity);
    }
}

void mk_server_loop(int server_fd)
{
    int remote_fd;
    struct sockaddr_in sockaddr;

    /* Activate TCP_DEFER_ACCEPT */
    if (mk_socket_set_tcp_defer_accept(server_fd) != 0) {
            mk_warn("TCP_DEFER_ACCEPT failed");
    }

    mk_info("HTTP Server started");
    
    while (1) {
        remote_fd = mk_socket_accept(server_fd, sockaddr);

        if (remote_fd == -1) {
            continue;
        }

#ifdef TRACE
        MK_TRACE("New connection arrived: FD %i", remote_fd);

        struct mk_list *sched_head;
        struct sched_list_node *node;

        MK_TRACE("Worker Status");
        mk_list_foreach(sched_head, sched_list) {
            node = mk_list_entry(sched_head, struct sched_list_node, _head);
            MK_TRACE(" WID %i / conx = %i", node->idx, node->active_connections);
        }
#endif

        /* Assign socket to worker thread */
        mk_sched_add_client(remote_fd);
    }
}
