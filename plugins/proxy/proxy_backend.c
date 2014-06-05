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

/*
 * Given a backend connection context, perform the connection to the
 * backend and prepare internals.
 */
static inline int proxy_conx_init(struct proxy_backend_conx *conx,
                                  struct proxy_backend_pool *pool)
{
    int ret;
    struct proxy_backend *backend;

    conx->fd     = proxy_net_socket_create();
    conx->status = PROXY_POOL_CONNECTING;
    conx->pool   = pool;

    if (conx->fd == -1) {
        mk_err("Proxy: could not create socket");
        return -1;
    }

    /* Set the socket non-blocking */
    proxy_net_socket_nonblock(conx->fd);

    /* Connect to... */
    backend = pool->backend;
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
        return 0;
    }

    close(conx->fd);
    return -1;
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
    pool->status      = PROXY_BACKEND_ALIVE;
    pool->backend     = backend;
    pool->failures    = 0;
    pool->connections = connections;
    mk_list_init(&pool->av_conx);
    mk_list_init(&pool->busy_conx);
    mk_list_add(&pool->_head, &worker_proxy_pool);

    for (i = 0; i < connections; i++) {
        conx = mk_api->mem_alloc(sizeof(struct proxy_backend_conx));
        ret = proxy_conx_init(conx, pool);
        if (ret == 0) {
            continue;
        }

        /* Handle exception*/
        mk_err("Proxy: error connecting to %s:%s",
               backend->host, backend->cport);
        mk_api->mem_free(conx);
    }

    return 0;
}

/* Suspend a backend */
int proxy_backend_suspend(struct proxy_backend_pool *pool)
{
    pool->status = PROXY_BACKEND_SUSPENDED;

    mk_err("Proxy: suspending backend %s (%s:%i)",
           pool->backend->name,
           pool->backend->host, pool->backend->port);

    return 0;
}

/* Triggered when a new connection to a backend fails */
int proxy_conx_failure(struct proxy_backend_conx *conx)
{
    struct proxy_backend_pool *pool = conx->pool;

    /* Register the failure in the backend context */
    pool->failures++;

    if ((pool->failures % (PROXY_BACKEND_FAILURES/4)) == 0) {
        mk_warn("Proxy: %3i errors connecting to %s (%s:%i)",
                pool->failures,
                pool->backend->name,
                pool->backend->host, pool->backend->port);
    }

    if (pool->failures >= PROXY_BACKEND_FAILURES) {
        /*
         * The backend on the current Worker reached the maximum number of
         * allowed failures between each successful connection. This backend
         * will be suspeded by PROXY_BACKEND_SUSPEND number of seconds.
         */
         proxy_backend_suspend(pool);
    }
    return proxy_conx_close(conx, MK_TRUE);
}


/* Remove a backend connection from the pool */
int proxy_conx_close(struct proxy_backend_conx *conx, int event_del)
{
    /*
     * Remove FD from epoll, close the file descriptor, cleanup the
     * queue and remove the entry from the rbtree.
     */
    PLUGIN_TRACE("[FD %i] Closing connection", conx->fd);

    if (event_del == MK_TRUE) {
        mk_api->event_del(conx->fd);
    }

    close(conx->fd);
    mk_list_del(&conx->_head);
    proxy_conx_remove(conx);

    /*
     * Now the connection have been cleared, the next step is to determinate
     * if a new connection should be re-established.
     */
    if (conx->pool->backend->keepalive == MK_TRUE &&
        conx->pool->status == PROXY_BACKEND_ALIVE) {
        PLUGIN_TRACE("[FD %i] Re-establish KeepAlive connection",
                     conx->fd);
        proxy_conx_init(conx, conx->pool);
    }
    else {
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

        /* Start connections for this backend */
        proxy_backend_start_conxs(backend, connections);
    }

    return 0;
}
