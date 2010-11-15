/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2010, Eduardo Silva P. <edsiper@gmail.com>
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

/* Common  */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* Networking - I/O*/
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

/* Plugin */
#include "MKPlugin.h"
#include "patas.h"
#include "connection.h"

MONKEY_PLUGIN("patas",               /* shortname */
              "Patas Monkey",        /* name */ 
              "0.12.0",              /* version */
              MK_PLUGIN_CORE_THCTX); /* hook for thread context call */

/* get thread connections list */
struct mk_list *mk_patas_conx_get()
{
    return pthread_getspecific(_mkp_data);
}

/* set thread connections list */
void mk_patas_conx_set(struct mk_list *list)
{
    pthread_setspecific(_mkp_data, (void *) list);
}

/* invoked in thread context */
void mk_patas_conx_init()
{
    struct mk_list *thread_conx_list;

    /* connection list */
    thread_conx_list = mk_api->mem_alloc(sizeof(struct mk_list));
    mk_list_init(thread_conx_list);

    /* set data to thread key */
    mk_patas_conx_set(thread_conx_list);
}

/* Read configuration parameters */
int mk_patas_conf(char *confdir)
{
    int val_port;
    char *val_host;
    unsigned long len;
    char *conf_path;

    struct mk_config_section *section;
    struct mk_config_entry *entry;
    struct mk_patas_node *node;

    /* Init nodes list */
    mk_patas_nodes_list = mk_api->mem_alloc(sizeof(struct mk_list));
    mk_list_init(mk_patas_nodes_list);

    /* Read configuration */
    mk_api->str_build(&conf_path, &len, "%s/patas.conf", confdir);
    conf = mk_api->config_create(conf_path);
    section = mk_api->config_section_get(conf, "NODE");

    while (section) { 
        entry = section->entry;
        val_host = NULL;
        val_port = -1;

        while (entry) {
            /* Passing to internal struct */
            if (strcasecmp(entry->key, "IP") == 0) {
                val_host = entry->val;
            }
            else if (strcasecmp(entry->key, "Port") == 0) {
                val_port = atoi(entry->val);
            }

            if (val_host && val_port > 0) {
                /* alloc node */
                node = mk_api->mem_alloc(sizeof(struct mk_patas_node));
#ifdef TRACE
                PLUGIN_TRACE("Balance Node: %s:%i", val_host, val_port);
#endif
                node->host = val_host;
                node->port = val_port;

                /* add node to list */
                mk_list_add(&node->_head, mk_patas_nodes_list);
                mk_patas_n_nodes++;
            }
            
            entry = entry->next;
        }
        section = section->next;
    }

    mk_api->mem_free(conf_path);
    return 0;
}

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;

    /* Read configuration */
    mk_patas_conf(confdir);

    /* Init mutex */
    pthread_mutex_init(&mutex_patas_target, (pthread_mutexattr_t *) NULL);

    mk_patas_n_nodes = 0;
    mk_patas_nodes_head = NULL;

    return 0;
}

void _mkp_exit()
{
}

void _mkp_core_prctx()
{
    struct mk_list *head;

    /* Count available nodes */
    mk_list_foreach(head, mk_patas_nodes_list) {
        mk_patas_n_nodes++;
    }
}

void _mkp_core_thctx()
{
    mk_patas_conx_init();
}

int _mkp_event_read(int socket)
{
    int connect_tries = 0;
    int sent=0, bytes=-1, av_bytes=-1, ret;
    int temp_socket = -1, to_socket = 0;
    struct mk_patas_node *node = NULL;
    struct mk_patas_conx *conx = NULL;

    conx = mk_patas_connection_get(socket);

    /* New connection arrived */
    if (!conx) {
        node = mk_patas_node_next_target();
        conx = mk_patas_connection_create(socket, -1, node);
        mk_patas_connection_add(conx);
    }
    else {
        node = conx->node;
    }

    /* Check amount of data available */
    ret = ioctl(socket, FIONREAD, &av_bytes);
    if (ret == -1) {
#ifdef TRACE
        PLUGIN_TRACE("[FD %i] ioctl()", socket);
        perror("ioctl");
#endif
        return MK_PLUGIN_RET_EVENT_CLOSE;
    }

    if (av_bytes == 0) {
        if (socket == conx->proxy_socket) {
            return MK_PLUGIN_RET_EVENT_CLOSE;
        }
        return MK_PLUGIN_RET_EVENT_CONTINUE;
    }

#ifdef TRACE
    PLUGIN_TRACE("[FD %i] available bytes: %i", socket, av_bytes);
#endif

    if (conx->remote_socket == socket) {
        to_socket = conx->proxy_socket;
    }
    else if (conx->proxy_socket == socket) {
        to_socket = conx->remote_socket;
    }

    sent = 0;

    do {
        bytes = read(socket, conx->buffer, conx->buffer_size);
#ifdef TRACE
        PLUGIN_TRACE("[FD %i] bytes read: %i", socket, bytes);
#endif    
        
        /* EOF */
        if (bytes == 0) {
            if (socket == conx->proxy_socket) {
            return MK_PLUGIN_RET_EVENT_CLOSE;
            }
            return MK_PLUGIN_RET_EVENT_OWNED;
        }
        else if (bytes < 0) {
            return MK_PLUGIN_RET_EVENT_CLOSE;
        }

        /* Connect to node server */
        if (conx->proxy_socket == -1) {
            while (temp_socket == -1) {
                temp_socket = mk_patas_node_connect(node);
                connect_tries++;

                if (temp_socket == -1) {
                    if (connect_tries >= mk_patas_n_nodes) {
#ifdef TRACE
                        PLUGIN_TRACE("Drop connection %i, no available nodes", socket);
#endif
                        return MK_PLUGIN_RET_EVENT_CLOSE;
                    }
                    else {
                        node = mk_patas_node_next_target();
                        conx->node = node;
                        temp_socket = mk_patas_node_connect(node);
                    }
                }
            }
#ifdef TRACE
            PLUGIN_TRACE("[FD %i] connect to node %s:%i", 
                         temp_socket, node->host, node->port);
#endif
            conx->proxy_socket = to_socket = temp_socket;
            
            /* Add node socket to epoll thread array */
            mk_api->event_add(temp_socket, MK_EPOLL_READ, NULL, NULL, NULL);
        }
    
        conx->buffer_len = bytes;
        bytes = write(to_socket, conx->buffer, conx->buffer_len);

#ifdef TRACE
        PLUGIN_TRACE("[FD %i] bytes written: %i", to_socket, bytes);
#endif
        
        if (bytes == -1) {
            return MK_PLUGIN_RET_EVENT_CLOSE;
        }
        
        sent += bytes;

    } while (sent < av_bytes);

    return MK_PLUGIN_RET_EVENT_OWNED;
}

int hangup(int socket)
{
    /* 
     * Determinate actions to take depending on which 
     * socket the event was raised: remote or proxy
     */

    mk_patas_connection_delete(socket);

    return MK_PLUGIN_RET_EVENT_CONTINUE;
}

int _mkp_event_close(int socket)
{

#ifdef TRACE
    PLUGIN_TRACE("[FD %i] close", socket);
#endif

    return hangup(socket);
}


int _mkp_event_error(int socket)
{

#ifdef TRACE
    PLUGIN_TRACE("[FD %i] error", socket);
#endif

    return hangup(socket);
}

int _mkp_event_timeout(int socket)
{

#ifdef TRACE
    PLUGIN_TRACE("[FD %i] timeout", socket);
#endif

    return hangup(socket);
}

/* 
 * Return the next target node to balance a new incoming
 * connection
 */
struct mk_patas_node *mk_patas_node_next_target()
{
    struct mk_patas_node *node;

    /* Mutex lock */
    pthread_mutex_lock(&mutex_patas_target);

    if (!mk_patas_nodes_head) {
        node = mk_list_entry_first(mk_patas_nodes_list, struct mk_patas_node, _head);
        mk_patas_nodes_head = mk_patas_nodes_list->next;
    }
    else {
        node = mk_list_entry_next(mk_patas_nodes_head, struct mk_patas_node, 
                                  _head, mk_patas_nodes_list);
    }

    /* Mutex unlock */
    pthread_mutex_unlock(&mutex_patas_target);

#ifdef TRACE
    PLUGIN_TRACE("next target node: %s:%i", node->host, node->port);
#endif

    return node;
}

int mk_patas_node_connect(struct mk_patas_node *node)
{
    int res;
    int socket;
    struct sockaddr_in *remote;

    /* create socket */
    socket = mk_api->socket_create();

    remote = (struct sockaddr_in *)
        mk_api->mem_alloc_z(sizeof(struct sockaddr_in));
    remote->sin_family = AF_INET;

    res = inet_pton(AF_INET, node->host, (void *) (&(remote->sin_addr.s_addr)));

    if (res < 0) {
        mk_api->error(MK_ERROR_WARNING, "Can't set remote->sin_addr.s_addr");
        mk_api->mem_free(remote);
        return -1;
    }
    else if (res == 0) {
        mk_api->error(MK_ERROR_WARNING, "Invalid IP address");
        mk_api->mem_free(remote);
        return -1;
    }

    remote->sin_port = htons(node->port);
    if (connect(socket, (struct sockaddr *) remote, sizeof(struct sockaddr)) == -1) {
        close(socket);

#ifdef TRACE
        mk_api->error(MK_ERROR_WARNING, "Could not connect to node: %s:%i\n", 
                      node->host, node->port);
#endif

        return -1;
    }

    return socket;
}
