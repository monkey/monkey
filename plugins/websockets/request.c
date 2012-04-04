/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <pthread.h>
#include <stdio.h>

#include "MKPlugin.h"
#include "request.h"
#include "ws.h"

/* Create a ws_request node */
struct mk_ws_request *mk_ws_request_create(int socket_fd,
                                           struct client_session *cs,
                                           struct session_request *sr,
                                           unsigned int subprotocol_id)
{
    struct mk_ws_request *new;

    new = mk_api->mem_alloc(sizeof(struct mk_ws_request));
    new->socket_fd = socket_fd;
    new->cs = cs;
    new->sr = sr;
    new->subprotocol_id = subprotocol_id;
    new->payload = NULL;
    new->payload_len = 0;

    return new;
}

void mk_ws_request_add(struct mk_ws_request *wr)
{
    /* websocket request list (thread context) */
    struct mk_list *wr_list;

    /* Get thread data */
    wr_list = (struct mk_list *) pthread_getspecific(_mkp_data);

    /* Add node to list */
    mk_list_add(&wr->_head, wr_list);

    /* Update thread key */
    pthread_setspecific(_mkp_data, wr_list);
}

/* 
 * It register the request and connection data, if it doesn't
 * exists it will be create it, otherwise will return the pointer
 * to the mk_ws_request struct node
 */
struct mk_ws_request *mk_ws_request_get(int socket_fd)
{
    struct mk_ws_request *wr_node;
    struct mk_list *wr_list, *wr_head;

    /* Get thread data */
    wr_list = pthread_getspecific(_mkp_data);

    /* No connection previously was found */
    if(mk_list_is_empty(wr_list) == 0) {
        return NULL;
    }

    mk_list_foreach(wr_head, wr_list) {
        wr_node = mk_list_entry(wr_head, struct mk_ws_request, _head);
        if(wr_node->socket_fd == socket_fd){
            return wr_node;
        }
    }

    return NULL;
}

void mk_ws_request_update(int socket, struct mk_ws_request *wr)
{
    struct mk_ws_request *wr_node;
    struct mk_list *wr_list, *wr_head;

    wr_list = pthread_getspecific(_mkp_data);
    if (mk_list_is_empty(wr_list) == 0) {
        return;
    }

    mk_list_foreach(wr_head, wr_list) {
        wr_node = mk_list_entry(wr_head, struct mk_ws_request, _head);
        if (wr_node->socket_fd == socket) {
            /* Update data */
            pthread_setspecific(_mkp_data, wr_list);
            return;
            }
    }
}

/* 
 * Remove a ws_request from the main list, return 0 on success or -1
 * when for some reason the request was not found
 */
int mk_ws_request_delete(int socket)
{
    struct mk_ws_request *wr_node;
    struct mk_list *wr_list, *wr_temp, *wr_head;

    PLUGIN_TRACE("[FD %i] remove request from list", socket);

    wr_list = pthread_getspecific(_mkp_data);
    if (mk_list_is_empty(wr_list) == 0) {
        return -1;
    }

    mk_list_foreach_safe(wr_head, wr_temp, wr_list) {
        wr_node = mk_list_entry(wr_head, struct mk_ws_request, _head);
        
        if (wr_node->socket_fd == socket) {
            mk_list_del(wr_head);
            mk_api->mem_free(wr_node);
            pthread_setspecific(_mkp_data, wr_list);
            return 0;
        }
    }

    return -1;
}

/*
 * Initialize the index list for palm_request and then set the
 * list HEAD to the thread key _mkp_data.
 */
void mk_ws_request_init()
{
    struct mk_list *ws_request_list;

    ws_request_list = mk_api->mem_alloc(sizeof(struct mk_list));
    mk_list_init(ws_request_list);
    pthread_setspecific(_mkp_data, ws_request_list);
}
