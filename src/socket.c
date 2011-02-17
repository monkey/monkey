/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "socket.h"
#include "memory.h"
#include "utils.h"
#include "plugin.h"
#include "monkey.h"
#include "macros.h"

static void mk_socket_safe_event_write(int socket)
{
    struct sched_list_node *sched;

    if (config->safe_event_write == MK_TRUE) {
        sched = mk_sched_get_thread_conf();
        MK_TRACE("[FD %i] Safe event write ON", socket);
        mk_epoll_change_mode(sched->epoll_fd, socket, MK_EPOLL_WRITE);
    }
}

/*
 * Example from:
 * http://www.baus.net/on-tcp_cork
 */
int mk_socket_set_cork_flag(int fd, int state)
{

    MK_TRACE("Socket, set Cork Flag FD %i to %s", fd, (state ? "ON" : "OFF"));

    return setsockopt(fd, SOL_TCP, TCP_CORK, &state, sizeof(state));
}

int mk_socket_set_nonblocking(int sockfd)
{

    MK_TRACE("Socket, set FD %i to non-blocking", sockfd);

    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0) | O_NONBLOCK) == -1) {
        perror("fcntl");
        return -1;
    }
    return 0;
}

int mk_socket_set_tcp_nodelay(int sockfd)
{
    int on = 1;

    return setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
}

int mk_socket_get_ip(int socket, char *ipv4)
{
    int ipv4_len = 16;
    socklen_t len;
    struct sockaddr_in m_addr;

    len = sizeof(m_addr);
    getpeername(socket, (struct sockaddr *) &m_addr, &len);
    inet_ntop(PF_INET, &m_addr.sin_addr, ipv4, ipv4_len);

    return 0;
}

int mk_socket_close(int socket)
{
    return close(socket);
}

int mk_socket_create()
{
    int sockfd;

    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("client: socket");
        return -1;
    }

    return sockfd;
}

int mk_socket_connect(int socket_fd, char *host, int port)
{
    int ret;

    ret = plg_netiomap->connect(socket_fd, host, port);

    return ret;
}

void mk_socket_reset(int socket)
{
    int status = 1;

    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &status, sizeof(int)) ==
        -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
}

/* Just IPv4 for now... */
int mk_socket_server(int port, char *listen_addr)
{
    int socket_fd;

    socket_fd = plg_netiomap->server(port, listen_addr);

    if (socket_fd < 0) {
        exit(EXIT_FAILURE);
    }

    return socket_fd;
}

/* NETWORK_IO plugin functions */
int mk_socket_accept(int server_fd, struct sockaddr_in sock_addr)
{
    return plg_netiomap->accept(server_fd, sock_addr);
}

int mk_socket_sendv(int socket_fd, struct mk_iov *mk_io, int to)
{
    int bytes;
    bytes = plg_netiomap->writev(socket_fd, mk_io);

    mk_socket_safe_event_write(socket_fd);
    return bytes;
}

int mk_socket_send(int socket_fd, const void *buf, size_t count)
{
    int bytes;
    bytes = plg_netiomap->write(socket_fd, buf, count);

    mk_socket_safe_event_write(socket_fd);
    return bytes;
}

int mk_socket_read(int socket_fd, void *buf, int count)
{
    return plg_netiomap->read(socket_fd, (void *)buf, count);
}

int mk_socket_send_file(int socket_fd, int file_fd, off_t *file_offset,
                        size_t file_count)
{
    int bytes;

    bytes = plg_netiomap->send_file(socket_fd, file_fd,
                                    file_offset, file_count);

    mk_socket_safe_event_write(socket_fd);
    return bytes;
}
