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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define MK_PATAS_BUF_SIZE 65536

/* Configuration nodes */
struct mk_patas_node {

    /* Node data */
    char *host;
    unsigned int port;
    struct sockaddr_in *sockaddr;

    /* Monkey list */
    struct mk_list _head;
};

struct mk_list *mk_patas_nodes_list;
struct mk_list *mk_patas_nodes_head;
pthread_mutex_t mutex_patas_target;
int mk_patas_n_nodes;

/* Connections */
struct mk_patas_conx {

    int socket_remote;
    int socket_node;

    /* Remote buffers */
    unsigned char buf_remote[MK_PATAS_BUF_SIZE];
    unsigned int buf_size_remote;
    unsigned long buf_len_remote;

    /* Node buffers */
    unsigned char buf_node[MK_PATAS_BUF_SIZE];
    unsigned int buf_size_node;
    unsigned long buf_len_node;
    unsigned long buf_pending_node;

    /* Target node */
    struct mk_patas_node *node;

    /* Monkey list head */
    struct mk_list _head;
};

/* Thread key to hold mk_patas_conx nodes */
pthread_key_t _mkp_data;

struct plugin_api *mk_api;
struct mk_config *conf;

/* functions */
struct mk_patas_node *mk_patas_node_next_target();
int mk_patas_node_connect(struct mk_patas_node *node);
