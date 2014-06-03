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

#include "MKPlugin.h"
#include "proxy.h"
#include "proxy_conf.h"
#include "proxy_backend.h"
#include "proxy_network.h"

/* inherit from proxy_backend.h */
__thread struct mk_list worker_proxy_pool;
__thread struct rb_root worker_connections;

/* Register a connection in the global rbtree */
int proxy_conx_insert(struct proxy_backend_conx *conx)
{
    struct rb_node **new = &(worker_connections.rb_node);
    struct rb_node *parent = NULL;
    struct proxy_backend_conx *this;

    /* Figure out where to put new node */
    while (*new) {
        this = container_of(*new, struct proxy_backend_conx, _rb_head);

        parent = *new;
        if (conx->fd < this->fd)
            new = &((*new)->rb_left);
        else if (conx->fd > this->fd)
            new = &((*new)->rb_right);
        else {
            break;
        }
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&conx->_rb_head, parent, new);
    rb_insert_color(&conx->_rb_head, &worker_connections);

    return 0;
}

int proxy_conx_remove(struct proxy_backend_conx *conx)
{
    /* Unlink from the red-black tree */
    rb_erase(&conx->_rb_head, &worker_connections);
    return 0;
}

struct proxy_backend_conx *proxy_conx_get_available(struct proxy_backend *backend)
{
    struct proxy_backend_pool *pool;
    struct proxy_backend_conx *conx;
    struct mk_list *head;

    mk_list_foreach(head, &worker_proxy_pool) {
        pool = mk_list_entry(head, struct proxy_backend_pool, _head);
        if (pool->backend == backend) {
            break;
        }
        else {
            pool = NULL;
        }
    }

    if (!pool) {
        return NULL;
    }

    if (mk_list_is_empty(&pool->av_conx) == 0) {
        return NULL;
    }

    conx = mk_list_entry_first(&pool->av_conx, struct proxy_backend_conx, _head);
    conx->status = PROXY_POOL_BUSY;
    mk_list_del(&conx->_head);
    mk_list_add(&conx->_head, &conx->pool->busy_conx);
    mk_api->event_socket_change_mode(conx->fd,
                                     MK_EPOLL_WRITE,
                                     MK_EPOLL_LEVEL_TRIGGERED);
    return conx;
}

int proxy_conx_set_available(struct proxy_backend_conx *conx)
{
    conx->status = PROXY_POOL_AVAILABLE;
    mk_list_del(&conx->_head);
    mk_list_add(&conx->_head, &conx->pool->av_conx);
    mk_api->event_socket_change_mode(conx->fd,
                                     MK_EPOLL_HANGUP,
                                     MK_EPOLL_LEVEL_TRIGGERED);
    return 0;
}

struct proxy_backend_conx *proxy_conx_get(int fd)
{
    struct rb_node *node;
    struct proxy_backend_conx *this;

    node = worker_connections.rb_node;
    while (node) {
        this = container_of(node, struct proxy_backend_conx, _rb_head);
        if (fd < this->fd)
            node = node->rb_left;
		else if (fd > this->fd)
            node = node->rb_right;
		else {
            return this;
        }
	}

    return NULL;
}

/* create a specific number of connections for the given backend */
int proxy_backend_start_conxs(struct proxy_backend *backend,
                              int connections)
{
    int i;
    int ret;
    struct proxy_backend_pool *pool;
    struct proxy_backend_conx *conx;

    /* Only HTTP backends are supported at the moment */
    if (backend->protocol != PROXY_PROTOCOL_HTTP) {
        mk_warn("Backend '%s' have an unsupported protocol: %i",
                backend->name, backend->protocol);
        return -1;
    }

    PLUGIN_TRACE("Backend '%s' => %i connections", backend->name, connections);

    /* Prepare backend pool */
    pool = mk_api->mem_alloc(sizeof(struct proxy_backend_pool));
    pool->backend = backend;
    pool->connections = connections;
    mk_list_init(&pool->av_conx);
    mk_list_init(&pool->busy_conx);
    mk_list_add(&pool->_head, &worker_proxy_pool);

    for (i = 0; i < connections; i++) {
        conx = mk_api->mem_alloc(sizeof(struct proxy_backend_conx));
        conx->fd     = proxy_net_socket_create();
        conx->status = PROXY_POOL_CONNECTING;
        conx->pool   = pool;

        if (conx->fd == -1) {
            mk_err("Proxy: could not create socket");
            mk_api->mem_free(conx);
            continue;
        }

        /* Set the socket non-blocking */
        proxy_net_socket_nonblock(conx->fd);

        /* Connect to... */
        ret = proxy_net_connect(conx->fd, backend->host, backend->cport);
        if ((ret == -1 && errno == EINPROGRESS) || ret == 0) {
            /* Add the in-progress connection to the busy queue */
            mk_list_add(&conx->_head, &pool->busy_conx);
            proxy_conx_insert(conx);

            /* Register the socket into the worker epoll(7) loop */
            mk_api->event_add(conx->fd,
                              MK_EPOLL_WRITE,
                              proxy_plugin,
                              MK_EPOLL_LEVEL_TRIGGERED);
            continue;
        }

        /* Raise an error */
        mk_err("Proxy: error connecting to %s:%s",
               backend->host, backend->cport);
        close(conx->fd);
        mk_api->mem_free(conx);
    }

    return 0;
}

/* Initialize connections to each backend defined at a worker level */
int proxy_backend_worker_init()
{
    int min;
    int diff = 0;
    int workers;
    int connections;
    struct mk_list *head;
    struct proxy_backend *backend;

    /* Initialize worker pool */
    mk_list_init(&worker_proxy_pool);
    memset(&worker_connections, '\0', sizeof(struct rb_root));

    /* Initialize backends */
    workers = mk_api->config->workers;
    mk_list_foreach(head, &proxy_config.backends) {
        backend = mk_list_entry(head, struct proxy_backend, _head);

        /*
         * Calculate the number of connections this worker will have
         * for the backend in question
         */
        if (backend->_av_diff > 0) {
            if (backend->_av_diff < workers) {
                diff = 1;
                backend->_av_diff--;
            }
        }
        else {
            diff = 0;
        }

        min = (backend->_total_conx / workers) + diff;

        if (backend->_av_conx < min) {
            connections = backend->_av_conx;
            backend->_av_conx = 0;
        }
        else {
            connections = min;
            backend->_av_conx -= connections;
        }

        if (connections == 0) {
            mk_warn("Proxy: worker connections is zero. Increasing to one");
            connections = 1;
        }
        proxy_backend_start_conxs(backend, connections);
    }

    return 0;
}
