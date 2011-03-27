/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P.
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
#include "palm.h"

struct mk_palm_request *mk_palm_request_create(int client_fd,
                                               int palm_fd,
                                               struct client_session *cs,
                                               struct session_request *sr,
                                               struct mk_palm *palm)
{
    struct mk_palm_request *new;

    new = mk_api->mem_alloc_z(sizeof(struct mk_palm_request));
    new->client_fd = client_fd;
    new->palm_fd = palm_fd;
    new->palm = palm;
    new->headers_sent = MK_FALSE;
    new->cs = cs;
    new->sr = sr;

    new->buffer_len = 0;
    new->buffer_offset = 0;

    return new;
}

void mk_palm_request_add(struct mk_palm_request *pr)
{
    /* palm request list (thread context) */
    struct mk_list *pr_list;

    /* Get thread data */
    pr_list = (struct mk_list *) pthread_getspecific(_mkp_data);

    /* Add node to list */
    mk_list_add(&pr->_head, pr_list);

    /* Update thread key */
    pthread_setspecific(_mkp_data, pr_list);
}

/* It register the request and connection data, if it doesn't
 * exists it will be create it, otherwise will return the pointer
 * to the mk_palm_request struct node
 */
struct mk_palm_request *mk_palm_request_get(int palm_fd)
{
    struct mk_palm_request *pr_node;
    struct mk_list *pr_list, *pr_head;

    /* Get thread data */
    pr_list = pthread_getspecific(_mkp_data);

    /* No connection previously was found */
    if(mk_list_is_empty(pr_list) == 0) {
        return NULL;
    }

    mk_list_foreach(pr_head, pr_list) {
        pr_node = mk_list_entry(pr_head, struct mk_palm_request, _head);
        if(pr_node->palm_fd == palm_fd){
            return pr_node;
        }
    }

    return NULL;
}

struct mk_palm_request *mk_palm_request_get_by_http(int socket)
{
    struct mk_palm_request *pr_node;
    struct mk_list *pr_list, *pr_head;

    /* Get thread data */
    pr_list = pthread_getspecific(_mkp_data);

    /* No connection previously was found */
    if(mk_list_is_empty(pr_list) == 0) {
        return NULL;
    }

    /* Look for node */
    mk_list_foreach(pr_head, pr_list) {
        pr_node = mk_list_entry(pr_head, struct mk_palm_request, _head);
        if(pr_node->client_fd == socket){
            return pr_node;
        }
    }

    return NULL;
}

void mk_palm_request_update(int socket, struct mk_palm_request  *pr)
{
    struct mk_palm_request *pr_node;
    struct mk_list *pr_list, *pr_head;

    pr_list = pthread_getspecific(_mkp_data);
    if (mk_list_is_empty(pr_list) == 0) {
        return;
    }

    mk_list_foreach(pr_head, pr_list) {
        pr_node = mk_list_entry(pr_head, struct mk_palm_request, _head);
        if (pr_node->palm_fd == socket) {
            pr_node->bytes_sent = pr->bytes_sent;
            pr_node->bytes_read = pr->bytes_read;
            pr_node->headers_sent = pr->headers_sent;

            /* Update data */
            pthread_setspecific(_mkp_data, pr_list);
            return;
            }
    }
}

void mk_palm_request_delete(int socket)
{
    struct mk_palm_request *pr_node;
    struct mk_list *pr_list, *pr_temp, *pr_head;

    pr_list = pthread_getspecific(_mkp_data);
    if (mk_list_is_empty(pr_list) == 0) {
        return;
    }

    mk_list_foreach_safe(pr_head, pr_temp, pr_list) {
        pr_node = mk_list_entry(pr_head, struct mk_palm_request, _head);
        
        if (pr_node->palm_fd == socket) {
            mk_list_del(pr_head);
            mk_api->mem_free(pr_node);
            pthread_setspecific(_mkp_data, pr_list);
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
