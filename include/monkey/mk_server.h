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

#include "mk_socket.h"
#include "mk_config.h"

#ifndef MK_SERVER_H
#define MK_SERVER_H

struct mk_server_listen_entry
{
    struct mk_config_listener *listen;
    int server_fd;
};

struct mk_server_listen
{
    unsigned int count;
    struct mk_server_listen_entry *listen_list;
};

static inline int mk_server_cork_flag(int fd, int state)
{
    if (config->manual_tcp_cork == MK_FALSE) {
        return 0;
    }

    return mk_socket_set_cork_flag(fd, state);
}

struct sched_list_node;
int mk_server_listen_check(struct mk_server_listen *listen, int server_fd);
int mk_server_listen_handler(struct sched_list_node *sched,
        struct mk_server_listen *listen,
        int server_fd);
void mk_server_listen_free(struct mk_server_listen *server_listen);
int mk_server_listen_init(struct server_config *config,
        struct mk_server_listen *server_listen);
unsigned int mk_server_capacity(unsigned short nworkers);
void mk_server_launch_workers(void);
void mk_server_loop(void);
void mk_server_worker_loop(struct mk_server_listen *listen);

#endif
