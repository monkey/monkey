/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P.
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

#include "plugin.h"
#include "patas.h"

struct mk_patas_conx *mk_patas_connection_create(int remote_socket, int proxy_socket,
                                                 struct mk_patas_node *node)
{
    struct mk_patas_conx *new;

    new = mk_api->mem_alloc(sizeof(struct mk_patas_conx));
    new->node = node;
    new->remote_socket = remote_socket;
    new->proxy_socket = proxy_socket;

    new->buffer = mk_api->mem_alloc(MK_PATAS_BUF_SIZE);
    new->buffer_size = MK_PATAS_BUF_SIZE;

    return new;
}

void mk_patas_connection_add(struct mk_patas_conx *pc)
{
    /* Patas request list (thread context) */
    struct mk_list *pc_list;

    /* Get thread data */
    pc_list = (struct mk_list *) pthread_getspecific(_mkp_data);

    /* Add node to list */
    mk_list_add(&pc->_head, pc_list);

    /* Update thread key */
    pthread_setspecific(_mkp_data, pc_list);
}

/* It register the request and connection data, if it doesn't
 * exists it will be create it, otherwise will return the pointer
 * to the mk_palm_request struct node
 */
struct mk_patas_conx *mk_patas_connection_get(int socket)
{
    struct mk_patas_conx *pc_node;
    struct mk_list *pc_list, *pc_head;

    /* Get thread data */
    pc_list = pthread_getspecific(_mkp_data);

    /* No connection previously was found */
    if(mk_list_is_empty(pc_list) == 0) {
        return NULL;
    }

    mk_list_foreach(pc_head, pc_list) {
        pc_node = mk_list_entry(pc_head, struct mk_patas_conx, _head);
        if (pc_node->remote_socket == socket || pc_node->proxy_socket == socket) {
            return pc_node;
        }
    }

    return NULL;
}

void mk_patas_connection_delete(int socket)
{
    struct mk_patas_conx *pc_node;
    struct mk_list *pc_list, *pc_temp, *pc_head;

    pc_list = pthread_getspecific(_mkp_data);
    if (mk_list_is_empty(pc_list) == 0) {
        return;
    }

    mk_list_foreach_safe(pc_head, pc_temp, pc_list) {
        pc_node = mk_list_entry(pc_head, struct mk_patas_conx, _head);
        
        if (pc_node->remote_socket == socket || pc_node->proxy_socket == socket) {
            mk_list_del(pc_head);

            if (pc_node->proxy_socket == socket) {
                mk_api->sched_remove_client(pc_node->remote_socket);
                pc_node->remote_socket = -1;
            }

            if (pc_node->remote_socket > 0) {
                close(pc_node->remote_socket);
            }

            if (pc_node->proxy_socket > 0) {
                close(pc_node->proxy_socket);
            }

            mk_api->mem_free(pc_node->buffer);
            mk_api->mem_free(pc_node);

            pthread_setspecific(_mkp_data, pc_list);
            return;
        }
    }
}

void mk_palm_request_init()
{
    struct mk_list *palm_request_list;

    palm_request_list = mk_api->mem_alloc(sizeof(struct mk_list));
    mk_list_init(palm_request_list);
    pthread_setspecific(_mkp_data, palm_request_list);
}
