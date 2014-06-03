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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "MKPlugin.h"

int proxy_net_socket_create()
{
    int fd;

    /* create the socket and set the nonblocking flag status */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd <= 0) {
        perror("socket");
        return -1;
    }
    mk_api->socket_set_tcp_nodelay(fd);

    return fd;
}

int proxy_net_socket_nonblock(int fd)
{
    return mk_api->socket_set_nonblocking(fd);
}

int proxy_net_connect(int fd, char *host, char *port)
{
    int ret;
    struct addrinfo *hints = NULL;
    struct addrinfo *res = NULL;

    hints = mk_api->mem_alloc_z(sizeof(struct addrinfo));
    hints->ai_family   = AF_UNSPEC;
    hints->ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(host, port, hints, &res);
    mk_api->mem_free(hints);

    if (ret != 0) {
        errno = 0;
        printf("[network] get address failed: fd=%i host=%s port=%s\n",
               fd, host, port);
        return -1;
    }

    ret = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    return ret;
}
