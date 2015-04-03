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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

#if defined (__linux__)
#include <sys/sendfile.h>
#endif

#include <monkey/mk_api.h>

int mk_liana_plugin_init(struct plugin_api **api, char *confdir)
{
    (void) confdir;
    mk_api = *api;
    return 0;
}

int mk_liana_plugin_exit()
{
    return 0;
}

int mk_liana_buffer_size()
{
    return -1;
}

int mk_liana_read(int socket_fd, void *buf, int count)
{
    ssize_t bytes_read;

    bytes_read = read(socket_fd, (void *)buf, count);
    return bytes_read;
}

int mk_liana_write(int socket_fd, const void *buf, size_t count )
{
    ssize_t bytes_sent = -1;

    bytes_sent = write(socket_fd, buf, count);

    return bytes_sent;
}

int mk_liana_writev(int socket_fd, struct mk_iov *mk_io)
{
    ssize_t bytes_sent = -1;

    bytes_sent = mk_api->iov_send(socket_fd, mk_io);

    return bytes_sent;
}

int mk_liana_close(int socket_fd)
{
    close(socket_fd);
    return 0;
}

int mk_liana_create_socket(int domain, int type, int protocol)
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
int mk_liana_connect(char *host, int port)
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
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        socket_fd = mk_liana_create_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if( socket_fd == -1) {
            mk_warn("Error creating client socket, retrying");
            continue;
        }

        if (connect(socket_fd,
                    (struct sockaddr *) rp->ai_addr, rp->ai_addrlen) == -1) {
            close(socket_fd);
            continue;
        }

        break;
    }
    freeaddrinfo(res);

    if (rp == NULL)
        return -1;

    return socket_fd;
}

int mk_liana_send_file(int socket_fd, int file_fd, off_t *file_offset,
                              size_t file_count)
{
    ssize_t ret = -1;

#if defined (__linux__)
    ret = sendfile(socket_fd, file_fd, file_offset, file_count);
    if (ret == -1 && errno != EAGAIN) {
        mk_err("[FD %i] error from sendfile(): %s",
                socket_fd, strerror(errno));
    }
    return ret;
#elif defined (__APPLE__)
    off_t offset = *file_offset;
    off_t len = (off_t) file_count;

    ret = sendfile(file_fd, socket_fd, offset, &len, NULL, 0);
    if (ret == -1 && errno != EAGAIN) {
        mk_err("[FD %i] error from sendfile(): %s",
                socket_fd, strerror(errno));
    }
    else if (len > 0) {
        *file_offset += len;
        return len;
    }
    return ret;
#else
#error Sendfile not supported on platform
#endif
}

int mk_liana_bind(int socket_fd, const struct sockaddr *addr, socklen_t addrlen, int backlog)
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

int mk_liana_server(char *port, char *listen_addr, int reuse_port)
{
    int socket_fd = -1;
    int ret;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(listen_addr, port, &hints, &res);
    if(ret != 0) {
        mk_err("Can't get addr info: %s", gai_strerror(ret));
        return -1;
    }

    for(rp = res; rp != NULL; rp = rp->ai_next) {
        socket_fd = mk_liana_create_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

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

        ret = mk_liana_bind(socket_fd, rp->ai_addr, rp->ai_addrlen, MK_SOMAXCONN);
        if(ret == -1) {
            mk_err("Cannot listen on %s:%s\n", listen_addr, port);
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (rp == NULL)
        return -1;

    return socket_fd;
}

/* Network Layer plugin Callbacks */
struct mk_plugin_network mk_plugin_network_liana = {
    .read          = mk_liana_read,
    .write         = mk_liana_write,
    .writev        = mk_liana_writev,
    .close         = mk_liana_close,
    .connect       = mk_liana_connect,
    .send_file     = mk_liana_send_file,
    .create_socket = mk_liana_create_socket,
    .bind          = mk_liana_bind,
    .server        = mk_liana_server,
    .buffer_size   = mk_liana_buffer_size
};

struct mk_plugin mk_plugin_liana = {
    /* Identification */
    .shortname     = "liana",
    .name          = "Liana Network Layer",
    .version       = MK_VERSION_STR,
    .hooks         = MK_PLUGIN_NETWORK_LAYER,

    /* Init / Exit */
    .init_plugin   = mk_liana_plugin_init,
    .exit_plugin   = mk_liana_plugin_exit,

    /* Init Levels */
    .master_init   = NULL,
    .worker_init   = NULL,

    /* Type */
    .network       = &mk_plugin_network_liana
};
