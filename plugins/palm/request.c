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

#include "config.h"
#include "plugin.h"
#include "monkey.h"
#include "palm.h"

struct mk_palm_request *mk_palm_request_create(int client_fd,
                                               int palm_fd,
                                               struct client_request *cr,
                                               struct request *sr,
                                               struct mk_palm *palm)
{
    struct mk_palm_request *new;

    new = mk_api->mem_alloc(sizeof(struct mk_palm_request));
    new->client_fd = client_fd;
    new->palm_fd = palm_fd;
    new->palm = palm;
    new->bytes_sent = 0;
    new->bytes_read = 0;
    new->headers_sent = VAR_OFF;
    new->cr = cr;
    new->sr = sr;
    new->next = NULL;

    return new;
}

void mk_palm_request_add(struct mk_palm_request *pr)
{
    struct mk_palm_request *pr_list, *aux;

    /* Get thread data */
    pr_list = pthread_getspecific(_mk_plugin_data);

    /* No connection previously was found */
    if(!pr_list) {
        pthread_setspecific(_mk_plugin_data, pr);
        return;
    }

    /* Add Node */
    aux = pr_list;
    while(aux->next){
        aux = aux->next;
    }

    aux->next = pr;
    pthread_setspecific(_mk_plugin_data, pr_list);
}

/* It register the request and connection data, if it doesn't
 * exists it will be create it, otherwise will return the pointer
 * to the mk_palm_request struct node
 */
struct mk_palm_request *mk_palm_request_get(int socket)
{
    struct mk_palm_request *pr, *aux;

    /* Get thread data */
    pr = pthread_getspecific(_mk_plugin_data);

    /* No connection previously was found */
    if(!pr) {
        return NULL;
    }

    /* Look for node */
    aux = pr;
    while(aux){
        if(aux->client_fd == socket){
            return aux;
        }
        aux = aux->next;
    }

    return NULL;
}

void mk_palm_request_update(int socket, struct mk_palm_request  *pr)
{
    struct mk_palm_request *aux, *list;

    list = pthread_getspecific(_mk_plugin_data);

    if (!list) {
        return;
    }

    aux = list;
    while (aux) {
        if (aux->client_fd == socket) {
            aux->bytes_sent = pr->bytes_sent;
            aux->bytes_read = pr->bytes_read;
            aux->headers_sent = pr->headers_sent;

            /* Update data */
            pthread_setspecific(_mk_plugin_data, list);
            return;
        }
        aux = aux->next;
    }
}

void mk_palm_request_delete(int socket)
{
    struct mk_palm_request *aux, *prev, *list;

    list = pthread_getspecific(_mk_plugin_data);

    if (!list) {
        return;
    }

    aux = list;
    while(aux) {
        if (aux->client_fd == socket) {
            /* first node */
            if (aux == list) {
                list = aux->next;
            }
            else {
                prev = list;
                while(prev->next != aux) {
                    prev = prev->next;
                }
                prev->next = aux->next;
            }
            mk_api->mem_free(aux);
            return;
        }
        aux = aux->next;
    }
}

void mk_palm_free_request(int sockfd)
{
    struct mk_palm_request *pr;

    /* get palm request node */
    pr = mk_palm_request_get(sockfd);

    /* close palm socket */
    mk_api->socket_close(pr->palm_fd);

    /* delete palm request node */
    mk_palm_request_delete(sockfd);
}
