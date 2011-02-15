/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2010-2011, Eduardo Silva P. <edsiper@gmail.com>
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
#include <netdb.h>
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
              VERSION,              /* version */
              MK_PLUGIN_CORE_THCTX | MK_PLUGIN_STAGE_30); /* hook for thread context call */

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

int mk_patas_validate_node(const char *host, int port)
{
    int i, j;
    char local_addr[16], node_addr[16];
    struct hostent local, *node;
    struct in_addr **node_addr_list, **local_addr_list;

    memcpy(&local, gethostbyname("localhost"), sizeof(struct hostent));
    node = gethostbyname(host);

    if (!node) {
        mk_api->error(MK_WARNING, "Could not determinate hostname");
        return -1;
    }

    local_addr_list = (struct in_addr **) local.h_addr_list;
    node_addr_list = (struct in_addr **) node->h_addr_list;

    for (i=0; local_addr_list[i] != NULL; i++) {
        inet_ntop(PF_INET, local.h_addr_list[i], local_addr, 16 );

        for (j=0; node_addr_list[j] != NULL; j++) {
            inet_ntop(PF_INET, node->h_addr_list[j], node_addr, 16);

            if (strcmp(local_addr, node_addr) == 0 && mk_api->config->serverport == port) {
                mk_api->error(MK_WARNING, "Node %s:%i = localhost:%i, skip node\n",
                              host, port, port);
                return -1;
            }
        }
    }

    return 0;
}

/* Read configuration parameters */
int mk_patas_conf(char *confdir)
{
    int res;
    int val_port;
    char *val_host;
    char *val_uri;
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
        val_uri = NULL;

        /* Get section values */
        val_host = mk_api->config_section_getval(section, "IP", MK_CONFIG_VAL_STR);
        val_port = (int) mk_api->config_section_getval(section, "Port", MK_CONFIG_VAL_NUM);
        val_uri  = mk_api->config_section_getval(section, "Uri", MK_CONFIG_VAL_LIST);

        if (val_host && val_uri && val_port > 0) {
            /* validate that node:ip is not pointing this server */
            if (mk_patas_validate_node(val_host, val_port) < 0) {
                break;
            }

            /* alloc node */
            node = mk_api->mem_alloc(sizeof(struct mk_patas_node));
            node->host = val_host;
            node->port = val_port;
                
            /* pre-socket stuff */
            node->sockaddr = mk_api->mem_alloc_z(sizeof(struct sockaddr_in));
            node->sockaddr->sin_family = AF_INET;

            res = inet_pton(AF_INET, node->host, 
                            (void *) (&(node->sockaddr->sin_addr.s_addr)));
            if (res < 0) {
                mk_api->error(MK_WARNING, "Can't set remote->sin_addr.s_addr");
                mk_api->mem_free(node->sockaddr);
                return -1;
            }
            else if (res == 0) {
                mk_api->error(MK_WARNING, "Invalid IP address");
                mk_api->mem_free(node->sockaddr);
                return -1;
            }

            node->sockaddr->sin_port = htons(node->port);
                
            /* add node to list */
            PLUGIN_TRACE("Balance Node: %s:%i", val_host, val_port);

            mk_list_add(&node->_head, mk_patas_nodes_list);
            mk_patas_n_nodes++;
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

static int mk_patas_write_pending_to_remote(int socket, struct mk_patas_conx *conx)
{
    int bytes;

    if (!conx) {
        return MK_PLUGIN_RET_EVENT_NEXT;
    }
    
    if (conx->buf_pending_node > 0) {
        PLUGIN_TRACE("PENDING: %i", conx->buf_pending_node);
        bytes = write(conx->socket_remote, 
                      conx->buf_node + (conx->buf_len_node - conx->buf_pending_node),
                      conx->buf_pending_node);

        PLUGIN_TRACE("  written: %i", bytes);

        if (bytes >= 0) {
            conx->buf_pending_node -= bytes;
        }
        else {
            switch(errno) {
            case EAGAIN:
                PLUGIN_TRACE("EAGAIN");
                return MK_PLUGIN_RET_EVENT_OWNED;
            default:
                return MK_PLUGIN_RET_EVENT_CLOSE;
            }
        }
    }

    return MK_PLUGIN_RET_EVENT_OWNED;
}

static int mk_patas_read_from_node(int socket, int av_bytes, struct mk_patas_conx *conx)
{
    int bytes = -1;
    int read_limit = 0;

    PLUGIN_TRACE("[FD %i] Reading from NODE", socket);

    /* Process pending data */
    if (conx->buf_pending_node > 0) {
        PLUGIN_TRACE("     Pending %i bytes", conx->buf_pending_node);
        return mk_patas_write_pending_to_remote(socket, conx);
    }

    /* check Node EOF, at this point no pending data should exists */
    if (av_bytes == 0) {
        return MK_PLUGIN_RET_EVENT_CLOSE;
    }

    if (av_bytes < conx->buf_size_node) {
        read_limit = av_bytes;
    }
    else {
        read_limit = conx->buf_size_node;
    }

    bytes = read(conx->socket_node, conx->buf_node, read_limit);
    if (bytes <= 0) {
        PLUGIN_TRACE("[FD %i] Node END", conx->socket_node);
        close(conx->socket_node);
        conx->socket_node = -1;
        return MK_PLUGIN_RET_EVENT_OWNED;
    }
    else {
        conx->buf_len_node = bytes;
    }

    PLUGIN_TRACE("[FD %i] read %i bytes", socket, bytes);

    /* Write node data to remote client */
    bytes = write(conx->socket_remote, conx->buf_node, conx->buf_len_node);

    PLUGIN_TRACE("[FD %i] written %i/%i bytes ", 
                 conx->socket_remote, bytes, conx->buf_len_node);

    if (bytes == 0) {
        return MK_PLUGIN_RET_EVENT_CLOSE;
    }
    else if (bytes < 0) {
#ifdef TRACE
        mk_api->errno_print(errno);
#endif
        switch(errno) {
        case EAGAIN:
            /* 
             * Could not write because can block on socket, 
             * let's set as pending 
             */
            PLUGIN_TRACE("EAGAIN");
            conx->buf_pending_node += conx->buf_len_node;
            return MK_PLUGIN_RET_EVENT_OWNED;
        case EPIPE:
            return MK_PLUGIN_RET_EVENT_CLOSE;

        }
    }

    if (bytes == conx->buf_len_node) { 
        conx->buf_len_node = 0;
    }
    else {
        conx->buf_pending_node = conx->buf_len_node - bytes;
    }

    return MK_PLUGIN_RET_EVENT_OWNED;
}

int _mkp_stage_30(struct plugin *plugin, struct client_session *cs, 
                  struct session_request *sr)
{

    PLUGIN_TRACE("[FD %i] STAGE 30", cs->socket);
    return MK_PLUGIN_RET_CONTINUE;
}
/*
int _mkp_event_write(int socket)
{
    struct mk_patas_conx *conx = NULL;

#ifdef TRACE
    PLUGIN_TRACE("[FD %i] Writting to REMOTE", socket);
#endif

    conx = mk_patas_connection_get(socket);
    if (!conx) {
        return MK_PLUGIN_RET_EVENT_NEXT;
    }
    
    return mk_patas_write_pending_to_remote(socket, conx);
}
*/
int _mkp_event_read(int socket)
{
    int av_bytes=-1, ret;
    struct mk_patas_conx *conx = NULL;

    return MK_PLUGIN_RET_EVENT_NEXT;

    /* Get connection node */
    conx = mk_patas_connection_get(socket);

    /* Check amount of data available */
    ret = ioctl(socket, FIONREAD, &av_bytes);
    if (ret == -1) {
        PLUGIN_TRACE("[FD %i] ERROR ioctl(FIONREAD)", socket);
        return MK_PLUGIN_RET_EVENT_OWNED;
    }

    PLUGIN_TRACE("[FD %i] available bytes: %i", socket, av_bytes);

    /* Map right handler */
    if (!conx || conx->socket_remote == socket) {
        //return mk_patas_read_from_remote(socket, av_bytes, conx);
    }
    else if (conx->socket_node == socket) {
        return mk_patas_read_from_node(socket, av_bytes, conx);
    }

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

    PLUGIN_TRACE("[FD %i] close", socket);
    return hangup(socket);
}


int _mkp_event_error(int socket)
{
    PLUGIN_TRACE("[FD %i] error", socket);
    return hangup(socket);
}

int _mkp_event_timeout(int socket)
{
    PLUGIN_TRACE("[FD %i] timeout", socket);
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
        mk_patas_nodes_head = mk_patas_nodes_list;
    }
    
    node = mk_list_entry_next(mk_patas_nodes_head, struct mk_patas_node, _head,
                              mk_patas_nodes_list);

    /* Mutex unlock */
    pthread_mutex_unlock(&mutex_patas_target);


    PLUGIN_TRACE("next target node: %s:%i", node->host, node->port);
    return node;
}
