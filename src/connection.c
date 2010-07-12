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

#ifdef TRACE
    MK_TRACE("Connection Handler, read on FD %i", socket);
#endif

    /* Plugin hook */
    ret = mk_plugin_event_read(socket);
    if (ret != MK_PLUGIN_RET_EVENT_NOT_ME) {
        if (ret == MK_PLUGIN_RET_END || ret == MK_PLUGIN_RET_CLOSE_CONX){
            return -1;
        }
        return ret;
    }        

    sched = mk_sched_get_thread_conf();

    cr = mk_request_client_get(socket);
    if (!cr) {
        /* Note: Linux don't set TCP_NODELAY socket flag by default, 
         */
        mk_socket_set_tcp_nodelay(socket);

        /* Create client */
        cr = mk_request_client_create(socket);
    }

    /* Read incomming data */
    ret = mk_handler_read(socket, cr);

    if (ret > 0) {
        if (mk_http_pending_request(cr) == 0) {
            mk_epoll_change_mode(sched->epoll_fd,
                                 socket, MK_EPOLL_WRITE);
        }
        else if (cr->body_length + 1 >= config->max_request_size) {
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
    int ret = -1;
    struct client_request *cr;
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("[FD %i] Connection Handler, write", socket);
#endif

    /* Plugin hook */
    ret = mk_plugin_event_write(socket);
#ifdef TRACE
    MK_TRACE("Check plugin hook | ret = %i", ret);
#endif
    if (ret != MK_PLUGIN_RET_EVENT_NOT_ME) {
        return ret;
    }  

#ifdef TRACE
    MK_TRACE("[FD %i] Normal connection write handling", socket);
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

    /* if ret < 0, means that some error
     * happened in the writer call, in the
     * other hand, 0 means a successful request
     * processed, if ret > 0 means that some data
     * still need to be send.
     */
    if (ret < 0) {
        mk_request_free_list(cr);
        mk_request_client_remove(socket);
        return -1;
    }
    else if (ret == 0) {
        if (mk_http_request_end(socket) < 0) {
            mk_request_free_list(cr);
            return -1;
        }
        else {
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
    int ret = -1;
    struct client_request *cr;
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("Connection Handler, error on FD %i", socket);
#endif 

    /* Plugin hook */
    ret = mk_plugin_event_error(socket);
    if (ret != MK_PLUGIN_RET_EVENT_NOT_ME) {
        if (ret == MK_PLUGIN_RET_END || ret == MK_PLUGIN_RET_CLOSE_CONX){
#ifdef TRACE
            MK_TRACE("CLOSING REQUEST");
#endif
            return -1;
        }
        return ret;
    } 

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
    int ret = -1;
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("[FD %i] Connection Handler, closed", socket);
#endif

    /* Plugin hook */
    ret = mk_plugin_event_close(socket);
    if (ret != MK_PLUGIN_RET_EVENT_NOT_ME) {
        return ret;
    } 
    sched = mk_sched_get_thread_conf();
    mk_sched_remove_client(sched, socket);
    return 0;
}

int mk_conn_timeout(int socket)
{
    int ret = -1;
    struct sched_list_node *sched;

#ifdef TRACE
    MK_TRACE("[FD %i] Connection Handler, timeout", socket);
#endif

    /* Plugin hook */
    ret = mk_plugin_event_timeout(socket);
    if (ret != MK_PLUGIN_RET_EVENT_NOT_ME) {
        return ret;
    } 

    sched = mk_sched_get_thread_conf();
    mk_sched_check_timeouts(sched);

    return 0;
}
