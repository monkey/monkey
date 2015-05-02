/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#ifndef MK_SERVER_H
#define MK_SERVER_H

#include <monkey/mk_socket.h>
#include <monkey/mk_config.h>
#include <monkey/mk_event.h>

#define MK_SERVER_SIGNAL_START     0xEEEEEEEE

struct mk_server_listen
{
    struct mk_event event;

    int server_fd;
    struct mk_config_listener *listen;
    struct mk_list _head;
};

struct mk_server_timeout {
    struct mk_event event;
};

extern __thread struct mk_list *server_listen;
extern __thread struct mk_server_timeout *server_timeout;

struct mk_sched_worker;

static inline int mk_server_cork_flag(int fd, int state)
{
    if (mk_config->manual_tcp_cork == MK_FALSE) {
        return 0;
    }

    return mk_socket_set_cork_flag(fd, state);
}


int mk_server_listen_check(struct mk_server_listen *listen, int server_fd);
int mk_server_listen_handler(struct mk_sched_worker *sched,
                             int server_fd);
void mk_server_listen_free();
struct mk_list *mk_server_listen_init(struct mk_server_config *config);
unsigned int mk_server_capacity();
void mk_server_launch_workers(void);
void mk_server_loop();
void mk_server_loop_balancer();
void mk_server_worker_loop();

#endif
