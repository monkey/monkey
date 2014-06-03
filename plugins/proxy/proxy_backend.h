/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
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

#ifndef PROXY_BACKEND_H
#define PROXY_BACKEND_H

#define PROXY_POOL_CONNECTING  -1
#define PROXY_POOL_AVAILABLE    0
#define PROXY_POOL_BUSY         1
#define PROXY_POOL_DEAD         2

/* Represents a connection to a specific machine */
struct proxy_backend_conx {
    int fd;                          /* socket */
    int status;                      /* connection status */
    struct proxy_backend_pool *pool; /* reverse pool lookup */
    struct rb_node _rb_head;         /* red-black tree head */
    struct mk_list _head;            /* head link to available or busy queues */
};

/* A backend pool is a group of connections to a target machine */
struct proxy_backend_pool {
    int connections;
    struct proxy_backend *backend;
    struct mk_list av_conx;
    struct mk_list busy_conx;
    struct mk_list _head;
};

int proxy_conx_insert(struct proxy_backend_conx *conx);
int proxy_conx_remove(struct proxy_backend_conx *conx);
struct proxy_backend_conx *proxy_conx_get(int fd);
struct proxy_backend_conx *proxy_conx_get_available(struct proxy_backend *backend);
int proxy_conx_set_available(struct proxy_backend_conx *conx);


int proxy_backend_worker_init();

/* Worker scope variables */
extern __thread struct mk_list worker_proxy_pool;
extern __thread struct rb_root worker_connections;

#endif
