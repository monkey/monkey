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

#include "monkey.h"
#include "http.h"
#include "connection.h"
#include "scheduler.h"
#include "epoll.h"
#include "request.h"
#include "socket.h"
#include "plugin.h"
#include "utils.h"

#include <string.h>
#include <stdio.h>

int mk_conn_read(int socket)
{
    int ret;
    struct client_request *cr;
    struct sched_list_node *sched;

    /* Plugin hook */
    ret = mk_plugin_event_read(socket);
#ifdef TRACE
    MK_TRACE("Check plugin hook | ret = %i", ret);
#endif
    if (ret != MK_PLUGIN_RET_EVENT_NOT_ME) {
        return ret;
    }        

    sched = mk_sched_get_thread_conf();

    cr = mk_request_client_get(socket);
    if (!cr) {
        /* Note: Linux don't set TCP_NODELAY socket flag by default, 
         * also we set the client socket on non-blocking mode
         */
        mk_socket_set_tcp_nodelay(socket);
        mk_socket_set_nonblocking(socket);

        cr = mk_request_client_create(socket);

        /* Update requests counter */
        mk_sched_update_thread_status(NULL,
                                      MK_SCHEDULER_ACTIVE_UP,
                                      MK_SCHEDULER_CLOSED_DOWN);
    }
    else {
        /* If cr struct already exists, that could means that we 
         * are facing a keepalive connection, need to verify, if it 
         * applies we increase the thread status for active connections
         */
        if (cr->counter_connections > 1 && cr->body_length == 0) {
            mk_sched_update_thread_status(NULL,
                                          MK_SCHEDULER_ACTIVE_UP,
                                          MK_SCHEDULER_CLOSED_NONE);
        }
    }

    /* Read incomming data */
    ret = mk_handler_read(socket, cr);

    if (ret > 0) {
        if (mk_http_pending_request(cr) == 0) {
            mk_epoll_socket_change_mode(sched->epoll_fd,
                                        socket, MK_EPOLL_WRITE);
        }
        else if (cr->body_length + 1 >= MAX_REQUEST_BODY) {
            /* Request is incomplete and our buffer is full, 
             * close connection 
             */
            mk_request_client_remove(socket);
            return -1;
        }
    }
    return ret;
}

int mk_conn_write(int socket)
{
    int ret = -1, ka;
    struct client_request *cr;
    struct sched_list_node *sched;

    /* Plugin hook */
    ret = mk_plugin_event_write(socket);
#ifdef TRACE
    MK_TRACE("Check plugin hook | ret = %i", ret);
#endif
    if (ret != MK_PLUGIN_RET_EVENT_NOT_ME) {
        return ret;
    }  

#ifdef TRACE
    MK_TRACE("Normal connection write handling...");
#endif

    sched = mk_sched_get_thread_conf();
    mk_sched_update_conn_status(sched, socket, MK_SCHEDULER_CONN_PROCESS);

    /* Get node from schedule list node which contains
     * the information regarding to the current client/socket
     */
    cr = mk_request_client_get(socket);

    if (!cr) {
        return -1;
    }

    ret = mk_handler_write(socket, cr);
    ka = mk_http_keepalive_check(socket, cr);

    /* if ret < 0, means that some error
     * happened in the writer call, in the
     * other hand, 0 means a successful request
     * processed, if ret > 0 means that some data
     * still need to be send.
     */

    if (ret <= 0) {
        mk_request_free_list(cr);

        /* We need to ask to http_keepalive if this 
         * connection can continue working or we must 
         * close it.
         */

        mk_sched_update_thread_status(sched,
                                      MK_SCHEDULER_ACTIVE_DOWN,
                                      MK_SCHEDULER_CLOSED_UP);

        if (ka < 0 || ret < 0) {
            mk_request_client_remove(socket);
            return -1;
        }
        else {
            mk_request_ka_next(cr);
            mk_epoll_socket_change_mode(sched->epoll_fd,
                                        socket, MK_EPOLL_READ);
            return 0;
        }
    }
    else if (ret > 0) {
        return 0;
    }

    /* avoid to make gcc cry :_( */
    return -1;
}

int mk_conn_error(int socket)
{
    struct client_request *cr;
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("Connection Handler, error on FD %i", socket);
#endif 

    sched = mk_sched_get_thread_conf();
    mk_sched_remove_client(NULL, socket);
    cr = mk_request_client_get(socket);
    if (cr) {
        mk_request_client_remove(socket);
    }

    return 0;
}

int mk_conn_close(int socket)
{
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("Connection Handler, closed on FD %i", socket);
#endif

    sched = mk_sched_get_thread_conf();
    mk_sched_remove_client(sched, socket);

    return 0;
}

int mk_conn_timeout(int socket)
{
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("Connection Handler, timeout on FD %i", socket);
#endif

    sched = mk_sched_get_thread_conf();
    mk_sched_check_timeouts(sched);

    return 0;
}
