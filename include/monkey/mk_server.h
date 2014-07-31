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

static inline int mk_server_cork_flag(int fd, int state)
{
    if (config->manual_tcp_cork == MK_FALSE) {
        return 0;
    }

    return mk_socket_set_cork_flag(fd, state);
}


unsigned int mk_server_worker_capacity(unsigned short nworkers);
void mk_server_launch_workers(void);
void mk_server_loop(int server_fd);

#endif
