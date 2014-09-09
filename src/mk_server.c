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

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <monkey/monkey.h>
#include <monkey/mk_config.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_epoll.h>
#include <monkey/mk_socket.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_macros.h>
#include <monkey/mk_server.h>
#include <monkey/mk_event.h>

/* Return the number of clients that can be attended
 * at the same time per worker thread
 */
unsigned int mk_server_worker_capacity(unsigned short nworkers)
{
    unsigned int max, avl;
    struct rlimit lim;

    /* Limit by system */
    getrlimit(RLIMIT_NOFILE, &lim);
    max = lim.rlim_cur;

    /* Minimum of fds needed by Monkey:
     * --------------------------------
     * 3 fds: stdin, stdout, stderr
     * 1 fd for main socket server
     * 1 fd for epoll array (per thread)
     * 1 fd for worker logger when writing to FS
     * 2 fd for worker logger pipe
     */

    avl = max - (3 + 1 + nworkers + 1 + 2);

    /* The avl is divided by two as we need to consider
     * a possible additional FD for each plugin working
     * on the same request.
     */
    return ((avl / 2) / nworkers);
}

int mk_server_listen_check(struct mk_server_listen *listen, int server_fd)
{
    struct mk_server_listen_entry *listen_entry;
    unsigned int i;

    if (listen == NULL)
        goto error;

    for (i = 0; i < listen->count; i++) {
        listen_entry = &listen->listen_list[i];
        if (listen_entry->server_fd == server_fd)
            return 1;
    }
error:
    return 0;
}

int mk_server_listen_handler(struct sched_list_node *sched,
        struct mk_server_listen *listen,
        int server_fd)
{
    struct mk_server_listen_entry *listen_entry;
    struct sched_list_node *local_sched;
    unsigned int i;
    int client_fd = -1;
    int result;

    if (listen == NULL)
        goto error;

    local_sched = mk_sched_get_thread_conf();

    for (i = 0; i < listen->count; i++) {
        listen_entry = &listen->listen_list[i];
        if (listen_entry->server_fd != server_fd)
            continue;

        if (mk_sched_check_capacity(sched) == -1)
            goto error;

        client_fd = mk_socket_accept(server_fd);
        if (mk_unlikely(client_fd == -1)) {
            MK_TRACE("[server] Accept connection failed: %s", strerror(errno));
            goto error;
        }

        result = mk_epoll_add(sched->epoll_fd,
                client_fd,
                MK_EPOLL_READ,
                MK_EPOLL_LEVEL_TRIGGERED);
        if (mk_unlikely(result != 0)) {
            mk_err("[server] Add to epoll failed: %s", strerror(errno));
            goto error;
        }

        if (sched == local_sched) {
            result = mk_sched_register_client(client_fd, sched);
            if (mk_unlikely(result != 0)) {
                mk_err("[server] Failed to register client.");
                goto error;
            }
        }

        sched->accepted_connections++;
        MK_TRACE("[server] New connection arrived: FD %i", client_fd);
        return client_fd;
    }
error:
    if (client_fd != -1)
        mk_socket_close(client_fd);
    return -1;
}

void mk_server_listen_free(struct mk_server_listen *server_listen)
{
    free(server_listen->listen_list);
    server_listen->listen_list = NULL;
    server_listen->count = 0;
}

int mk_server_listen_init(struct server_config *config,
                          struct mk_server_listen *server_listen)
{
    int i = 0;
    unsigned int count = 0;
    int server_fd;
    int reuse_port;
    struct mk_list *head;
    struct mk_config_listener *listen;
    struct mk_server_listen_entry *listen_list = NULL;

    if (config == NULL)
        goto error;
    if (server_listen == NULL)
        goto error;

    reuse_port = config->scheduler_mode == MK_SCHEDULER_REUSEPORT;

    mk_list_foreach(head, &config->listeners) {
        count++;
    }

    listen_list = calloc(count, sizeof(*listen_list));
    if (listen_list == NULL) {
        mk_err("[server] Calloc failed: %s", strerror(errno));
        goto error;
    }

    mk_list_foreach(head, &config->listeners) {
        listen = mk_list_entry(head, struct mk_config_listener, _head);

        server_fd = mk_socket_server(listen->port,
                listen->address,
                reuse_port);
        if (server_fd >= 0) {
            if (mk_socket_set_tcp_defer_accept(server_fd) != 0) {
                mk_warn("[server] Could not set TCP_DEFER_ACCEPT");
            }
            listen_list[i].listen = listen;
            listen_list[i].server_fd = server_fd;
        }
        else {
            listen_list[i].server_fd = -1;
            mk_warn("[server] Failed to bind server socket to %s:%s.",
                    listen->address,
                    listen->port);
        }
        i += 1;
    }

    server_listen->count = count;
    server_listen->listen_list = listen_list;
    return 0;
error:
    if (listen_list != NULL) free(listen_list);
    return -1;
}

#ifndef SHAREDLIB

/* Here we launch the worker threads to attend clients */
void mk_server_launch_workers()
{
    int i;
    pthread_t skip;

    /* Launch workers */
    for (i = 0; i < config->workers; i++) {
        mk_sched_launch_thread(config->worker_capacity, &skip, NULL);
    }
}

/*
 * This function is called from the Scheduler and runs in a thread
 * context. This is the real thread server loop.
 */
void mk_server_worker_loop()
{
    int timeout_fd;
    mk_event_loop_t *evl;
    struct sched_list_node *sched;

    evl = mk_event_loop_create(MK_EVENT_QUEUE_SIZE);
    if (!evl) {
        return;
    }

    /* Get thread conf */
    sched = mk_sched_get_thread_conf();

    /* create a new timeout file descriptor */
    timeout_fd = mk_event_timeout_set(evl, config->timeout);
}

void mk_server_loop(void)
{
    struct sched_list_node *sched;
    struct mk_server_listen listen;
    struct pollfd *fds;
    int ret;
    unsigned int i;
    unsigned int count;

    /* Rename worker */
    mk_utils_worker_rename("monkey: server");

    mk_info("HTTP Server started");

    /* check balancing mode, for reuse port just stay here forever */
    if (config->scheduler_mode == MK_SCHEDULER_REUSEPORT) {
        while (1) sleep(60);
    }

    if (mk_server_listen_init(config, &listen)) {
        mk_err("Failed to initialize listen sockets.");
        return;
    }

    fds = calloc(listen.count, sizeof(*fds));
    if (fds == NULL) {
        mk_err("Failed to initialize listen sockets.");
        mk_server_listen_free(&listen);
        return;
    }
    count = listen.count;
    for (i = 0; i < count; i++) {
        fds[i].events = POLLIN | POLLERR | POLLHUP;
        fds[i].fd = listen.listen_list[i].server_fd;
    }

    while (1) {
        ret = poll(fds, count, 30000);
        if (mk_unlikely(ret < 0)) {
            mk_err("[server] Error in poll(): %s", strerror(errno));
            continue;
        }
        else if (mk_unlikely(ret == 0)) {
            continue;
        }

        for (i = 0; i < count; i++) {
            if (fds[i].revents == 0) {
                continue;
            }
            else if (fds[i].revents & POLLIN) {
                // Accept connection
                sched = mk_sched_next_target();
                if (sched != NULL) {
                    mk_server_listen_handler(sched, &listen, fds[i].fd);
                }
                else {
                    mk_warn("[server] Over capacity.");
                }
            }
            else if (fds[i].revents & (POLLERR | POLLHUP)) {
                // Error occurred
                mk_err("[server] Error on socket %d: %s",
                        fds[i].fd,
                        strerror(errno));
            }
            fds[i].revents = 0;
        }

#ifdef TRACE
        struct sched_list_node *node;

        node = sched_list;
        for (i=0; i < (unsigned int)config->workers; i++) {
            MK_TRACE("Worker Status");
            MK_TRACE(" WID %i / conx = %llu", node[i].idx, node[i].accepted_connections - node[i].closed_connections);
        }
#endif
    }
}

#endif // !SHAREDLIB
