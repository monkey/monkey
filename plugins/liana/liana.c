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
#include <string.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netdb.h>
#include <fcntl.h>

#include "MKPlugin.h"

MONKEY_PLUGIN("liana",         /* shortname */
              "Liana Network", /* name */
              VERSION,         /* version */
              MK_PLUGIN_NETWORK_IO); /* hooks */

int _mkp_init(struct plugin_api **api, char *confdir)
{
    (void) confdir;

    mk_api = *api;
    return 0;
}

void _mkp_exit()
{
}

int _mkp_network_io_accept(int server_fd)
{
    int remote_fd;
    struct sockaddr sock_addr;
    socklen_t socket_size = sizeof(struct sockaddr);

#ifdef ACCEPT_GENERIC
    remote_fd = accept(server_fd, &sock_addr, &socket_size);
    mk_api->socket_set_nonblocking(remote_fd);
#else
    remote_fd = accept4(server_fd, &sock_addr, &socket_size, SOCK_NONBLOCK | SOCK_CLOEXEC);
#endif

    return remote_fd;
}

int _mkp_network_io_read(int socket_fd, void *buf, int count)
{
    ssize_t bytes_read;

    bytes_read = read(socket_fd, (void *)buf, count);
    return bytes_read;
}

int _mkp_network_io_write(int socket_fd, const void *buf, size_t count )
{
    ssize_t bytes_sent = -1;

    bytes_sent = write(socket_fd, buf, count);

    return bytes_sent;
}

int _mkp_network_io_writev(int socket_fd, struct mk_iov *mk_io)
{
    ssize_t bytes_sent = -1;

    bytes_sent = mk_api->iov_send(socket_fd, mk_io);

    return bytes_sent;
}

int _mkp_network_io_close(int socket_fd)
{
    close(socket_fd);
    return 0;
}

int _mkp_network_io_create_socket(int domain, int type, int protocol)
{
    int socket_fd;

#ifdef SOCK_CLOEXEC
    socket_fd = socket(domain, type | SOCK_CLOEXEC, protocol);
#else
    socket_fd = socket(domain, type, protocol);
    fcntl(socket_fd, F_SETFD, FD_CLOEXEC);
#endif

    return socket_fd;
}

/* We need to know how to solve the problem with AF_INET and AF_INET6 */
int _mkp_network_io_connect(char *host, int port)
{
    int ret;
    int socket_fd = -1;
    char *port_str = 0;
    unsigned long len;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    mk_api->str_build(&port_str, &len, "%d", port);

    ret = getaddrinfo(host, port_str, &hints, &res);
    mk_api->mem_free(port_str);
    if(ret != 0) {
        mk_err("Can't get addr info: %s", gai_strerror(ret));
        return -1;
    }
    for(rp = res; rp != NULL; rp = rp->ai_next) {
        socket_fd = _mkp_network_io_create_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if( socket_fd == -1) {
            mk_warn("Error creating client socket, retrying");
            continue;
        }

        if (connect(socket_fd,
                    (struct sockaddr *) rp->ai_addr, rp->ai_addrlen) == -1) {
            close(socket_fd);
            mk_err("Can't connect to %s, retrying", host);
            continue;
        }

        break;
    }
    freeaddrinfo(res);

    if (rp == NULL)
        return -1;

    return socket_fd;
}

int _mkp_network_io_send_file(int socket_fd, int file_fd, off_t *file_offset,
                              size_t file_count)
{
    ssize_t bytes_written = -1;

    bytes_written = sendfile(socket_fd, file_fd, file_offset, file_count);

    if (mk_unlikely(bytes_written == -1)) {
        PLUGIN_TRACE("[FD %i] error from sendfile() = -1", socket_fd);
        return -1;
    }

    return bytes_written;
}

int _mkp_network_io_bind(int socket_fd, const struct sockaddr *addr, socklen_t addrlen, int backlog)
{
    int ret;

    ret = bind(socket_fd, addr, addrlen);
    if( ret == -1 ) {
        mk_warn("Error binding socket");
        return ret;
    }

    /*
     * Enable TCP_FASTOPEN by default: if for some reason this call fail,
     * it will not affect the behavior of the server, in order to succeed,
     * Monkey must be running in a Linux system with Kernel >= 3.7 and the
     * tcp_fastopen flag enabled here:
     *
     *     # cat /proc/sys/net/ipv4/tcp_fastopen
     *
     * To enable this feature just do:
     *
     *     # echo 1 > /proc/sys/net/ipv4/tcp_fastopen
     */
    if (mk_api->config->kernel_features & MK_KERNEL_TCP_FASTOPEN) {
        ret = mk_api->socket_set_tcp_fastopen(socket_fd);
        if (ret == -1) {
            mk_warn("Could not set TCP_FASTOPEN");
        }
    }

    ret = listen(socket_fd, backlog);
    if(ret == -1 ) {
        mk_warn("Error setting up the listener");
        return -1;
    }

    return ret;
}

int _mkp_network_io_server(int port, char *listen_addr, int reuse_port)
{
    int socket_fd = -1;
    int ret;
    char *port_str = 0;
    unsigned long len;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    mk_api->str_build(&port_str, &len, "%d", port);

    ret = getaddrinfo(listen_addr, port_str, &hints, &res);
    mk_api->mem_free(port_str);
    if(ret != 0) {
        mk_err("Can't get addr info: %s", gai_strerror(ret));
        return -1;
    }

    for(rp = res; rp != NULL; rp = rp->ai_next) {
        socket_fd = _mkp_network_io_create_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if( socket_fd == -1) {
            mk_warn("Error creating server socket, retrying");
            continue;
        }

        mk_api->socket_set_tcp_nodelay(socket_fd);
        mk_api->socket_reset(socket_fd);

        /* Check if reuse port can be enabled on this socket */
        if (reuse_port == MK_TRUE &&
            (mk_api->config->kernel_features & MK_KERNEL_SO_REUSEPORT)) {
            ret = mk_api->socket_set_tcp_reuseport(socket_fd);
            if (ret == -1) {
                mk_warn("Could not use SO_REUSEPORT, using fair balancing mode");
                mk_api->config->scheduler_mode = MK_SCHEDULER_FAIR_BALANCING;
            }
        }

        ret = _mkp_network_io_bind(socket_fd, rp->ai_addr, rp->ai_addrlen, MK_SOMAXCONN);
        if(ret == -1) {
            mk_err("Cannot listen on %s:%i\n", listen_addr, port);
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (rp == NULL)
        return -1;

    return socket_fd;
}
