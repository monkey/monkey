/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#include <monkey/monkey.h>
#include <monkey/mk_http.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_macros.h>

int mk_conn_read(int socket)
{
    int ret;
    int status;
    struct mk_http_session *cs;
    struct mk_http_request *sr;
    struct sched_list_node *sched;

    MK_TRACE("[FD %i] Connection Handler / read", socket);

    /* Plugin hook */
    ret = mk_plugin_event_read(socket);

    switch (ret) {
    case MK_PLUGIN_RET_EVENT_OWNED:
        return MK_PLUGIN_RET_CONTINUE;
    case MK_PLUGIN_RET_EVENT_CLOSE:
        return -1;
    case MK_PLUGIN_RET_EVENT_CONTINUE:
        break; /* just return controller to invoker */
    }

    sched = mk_sched_get_thread_conf();
    cs = mk_http_session_get(socket);
    if (!cs) {
        /* Check if is this a new connection for the Scheduler */
        if (!mk_sched_get_connection(sched, socket)) {
            MK_TRACE("[FD %i] Registering new connection");
            if (mk_sched_register_client(socket, sched) == -1) {
                MK_TRACE("[FD %i] Close requested", socket);
                return -1;
            }
            /*
             * New connections are not registered yet into the
             * events loop, we need to do it manually:
             */
            mk_event_add(sched->loop, socket, MK_EVENT_READ, NULL);
            return 0;
        }

        /* Create session for the client */
        MK_TRACE("[FD %i] Create session", socket);
        cs = mk_http_session_create(socket, sched);
        if (!cs) {
            return -1;
        }
    }

    /* Invoke the read handler, on this case we only support HTTP (for now :) */
    ret = mk_http_handler_read(socket, cs);
    if (ret > 0) {
        if (mk_list_is_empty(&cs->request_list) == 0) {
            /* Add the first entry */
            sr = &cs->sr_fixed;
            mk_list_add(&sr->_head, &cs->request_list);
            mk_http_request_init(cs, sr);
        }
        else {
            sr = mk_list_entry_first(&cs->request_list, struct mk_http_request, _head);
        }

        status = mk_http_parser(sr, &cs->parser,
                                cs->body, cs->body_length);
        if (status == MK_HTTP_PARSER_OK) {
            MK_TRACE("[FD %i] HTTP_PARSER_OK", socket);
            mk_http_status_completed(cs);
            mk_event_add(sched->loop, socket, MK_EVENT_WRITE, NULL);
        }
        else if (status == MK_HTTP_PARSER_ERROR) {
            if (mk_list_is_empty(&cs->channel.streams) != 0) {
                mk_channel_write(&cs->channel);
            }
            mk_http_session_remove(socket);
            MK_TRACE("[FD %i] HTTP_PARSER_ERROR", socket);
            return -1;
        }
        else {
            MK_TRACE("[FD %i] HTTP_PARSER_PENDING", socket);
        }
    }

    if (ret == -EAGAIN) {
        return 1;
    }

    return ret;
}

int mk_conn_write(int socket)
{
    int ret = -1;
    struct mk_http_session *cs;
    struct sched_list_node *sched;
    struct sched_connection *conx;

    MK_TRACE("[FD %i] Connection Handler / write", socket);

    /* Plugin hook */
    ret = mk_plugin_event_write(socket);
    switch(ret) {
    case MK_PLUGIN_RET_EVENT_OWNED:
        return MK_PLUGIN_RET_CONTINUE;
    case MK_PLUGIN_RET_EVENT_CLOSE:
        return -1;
    case MK_PLUGIN_RET_EVENT_CONTINUE:
        break; /* just return controller to invoker */
    }

    MK_TRACE("[FD %i] Normal connection write handling", socket);

    sched = mk_sched_get_thread_conf();
    conx = mk_sched_get_connection(sched, socket);
    if (!conx) {
        MK_TRACE("[FD %i] Registering new connection");
        if (mk_sched_register_client(socket, sched) == -1) {
            MK_TRACE("[FD %i] Close requested", socket);
            return -1;
        }

        mk_event_add(sched->loop, socket, MK_EVENT_READ, NULL);
        return 0;
    }

    mk_sched_update_conn_status(sched, socket, MK_SCHEDULER_CONN_PROCESS);

    /* Get node from schedule list node which contains
     * the information regarding to the current client/socket
     */
    cs = mk_http_session_get(socket);
    if (!cs) {
        /* This is a ghost connection that doesn't exist anymore.
         * Closing it could accidentally close some other thread's
         * socket, so pass it to remove_client that checks it's ours.
         */
        mk_sched_drop_connection(socket);
        return 0;
    }

    ret = mk_http_handler_write(socket, cs);

    /*
     * if ret < 0, means that some error happened in the writer call,
     * in the other hand, 0 means a successful request processed, if
     * ret > 0 means that some data still need to be send.
     */
    if (ret < MK_CHANNEL_ERROR) {
        mk_sched_drop_connection(socket);
        return -1;
    }
    else if (ret == MK_CHANNEL_DONE) {
        MK_TRACE("[FD %i] Request End", socket);
        return mk_http_request_end(socket);
    }
    else if (ret == MK_CHANNEL_FLUSH) {
        return 0;
    }

    /* avoid to make gcc cry :_( */
    return -1;
}

int mk_conn_close(int socket, int event)
{
    MK_TRACE("[FD %i] Connection Handler, closed", socket);

    /*
     * Remove the socket from the scheduler and make sure
     * to disable all notifications.
     */
    mk_sched_drop_connection(socket);

    /*
     * Plugin hook: this is a wrap-workaround to do not
     * break plugins until the whole interface events and
     * return values are re-worked.
     */
    if (event == MK_EP_SOCKET_CLOSED) {
        mk_plugin_event_close(socket);
    }
    else if (event == MK_EP_SOCKET_ERROR) {
        mk_plugin_event_error(socket);
    }
    else if (event == MK_EP_SOCKET_TIMEOUT) {
        mk_plugin_event_timeout(socket);
    }

    return 0;
}
