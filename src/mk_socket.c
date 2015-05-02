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

#if defined(__APPLE__)
#define SOL_TCP IPPROTO_TCP
#endif

#include <monkey/monkey.h>
#include <monkey/mk_socket.h>
#include <monkey/mk_kernel.h>
#include <monkey/mk_file.h>
#include <monkey/mk_memory.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_macros.h>

#include <time.h>
#include <netinet/tcp.h>

static void mk_socket_safe_event_write(int socket)
{
    struct mk_sched_worker *sched;

    sched = mk_sched_get_thread_conf();
    MK_TRACE("[FD %i] Safe event write ON", socket);
    mk_event_add(sched->loop, socket,
                 MK_EVENT_CONNECTION, MK_EVENT_WRITE, NULL);
}

/*
 * Example from:
 * http://www.baus.net/on-tcp_cork
 */
int mk_socket_set_cork_flag(int fd, int state)
{
    MK_TRACE("Socket, set Cork Flag FD %i to %s", fd, (state ? "ON" : "OFF"));

#if defined (__linux__)
    return setsockopt(fd, SOL_TCP, TCP_CORK, &state, sizeof(state));
#elif defined (__APPLE__)
    return setsockopt(fd, SOL_TCP, TCP_NOPUSH, &state, sizeof(state));
#endif
}

int mk_socket_set_nonblocking(int sockfd)
{

    MK_TRACE("Socket, set FD %i to non-blocking", sockfd);

    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        mk_err("Can't set to non-blocking mode socket %i", sockfd);
        return -1;
    }
    fcntl(sockfd, F_SETFD, FD_CLOEXEC);

    return 0;
}

/*
 * Enable the TCP_FASTOPEN feature for server side implemented in Linux Kernel >= 3.7,
 * for more details read here:
 *
 *  TCP Fast Open: expediting web services: http://lwn.net/Articles/508865/
 */

int mk_socket_set_tcp_fastopen(int sockfd)
{
#if defined (__linux__)
    int qlen = 5;

    if (mk_kernel_runver >= MK_KERNEL_VERSION(3, 7, 0)) {
        return setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
    }
#endif
    (void) sockfd;
    return -1;
}

int mk_socket_set_tcp_nodelay(int sockfd)
{
    int on = 1;

    return setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
}

int mk_socket_set_tcp_defer_accept(int sockfd)
{
#if defined (__linux__)
    int timeout = 0;

    return setsockopt(sockfd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(int));
#else
    (void) sockfd;
    return -1;
#endif
}

int mk_socket_set_tcp_reuseport(int sockfd)
{
    int on = 1;
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
}

int mk_socket_close(int socket)
{
    return mk_config->network->close(socket);
}

int mk_socket_create()
{
    int sockfd;

    if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
        mk_libc_error("socket");
        return -1;
    }

    return sockfd;
}

int mk_socket_connect(char *host, int port)
{
    int sockfd;

    sockfd = mk_config->network->connect(host, port);

    return sockfd;
}

int mk_socket_reset(int socket)
{
    int status = 1;

    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &status, sizeof(int)) == -1) {
        mk_libc_error("socket");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/* Just IPv4 for now... */
int mk_socket_server(char *port, char *listen_addr, int reuse_port)
{
    int socket_fd;

    if (!mk_config->network) {
        mk_err("No network layer plugin was found. Aborting.");
        exit(EXIT_FAILURE);
    }

    socket_fd = mk_config->network->server(port, listen_addr, reuse_port);
    if (socket_fd < 0) {
        exit(EXIT_FAILURE);
    }

    return socket_fd;
}

/* NETWORK_IO plugin functions */
int mk_socket_sendv(int socket_fd, struct mk_iov *mk_io)
{
    int bytes;
    bytes = mk_config->network->writev(socket_fd, mk_io);

    if (mk_config->safe_event_write == MK_TRUE) {
        mk_socket_safe_event_write(socket_fd);
    }
    return bytes;
}

int mk_socket_send(int socket_fd, const void *buf, size_t count)
{
    int bytes;
    bytes = mk_config->network->write(socket_fd, buf, count);

    if (mk_config->safe_event_write == MK_TRUE) {
        mk_socket_safe_event_write(socket_fd);
    }
    return bytes;
}

int mk_socket_read(int socket_fd, void *buf, int count)
{
    return mk_config->network->read(socket_fd, (void *)buf, count);
}

int mk_socket_send_file(int socket_fd, int file_fd, off_t *file_offset,
                        size_t file_count)
{
    int bytes;

    bytes = mk_config->network->send_file(socket_fd, file_fd,
                                       file_offset, file_count);

    if (mk_config->safe_event_write == MK_TRUE) {
        mk_socket_safe_event_write(socket_fd);
    }
    return bytes;
}

int mk_socket_ip_str(int socket_fd, char **buf, int size, unsigned long *len)
{
    int ret;
    struct sockaddr_storage addr;
    socklen_t s_len = sizeof(addr);

    ret = getpeername(socket_fd, (struct sockaddr *) &addr, &s_len);

    if (mk_unlikely(ret == -1)) {
        MK_TRACE("[FD %i] Can't get addr for this socket", socket_fd);
        return -1;
    }

    errno = 0;

    if(addr.ss_family == AF_INET) {
        if((inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr,
                      *buf, size)) == NULL) {
            mk_warn("mk_socket_ip_str: Can't get the IP text form (%i)", errno);
            return -1;
        }
    }
    else if(addr.ss_family == AF_INET6) {
        if((inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr,
                      *buf, size)) == NULL) {
            mk_warn("mk_socket_ip_str: Can't get the IP text form (%i)", errno);
            return -1;
        }
    }

    *len = strlen(*buf);
    return 0;
}
