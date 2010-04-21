/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010 Eduardo Silva P. <edsiper@gmail.com>
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
#include "monkey.h"

/*
 * Example from:
 * http://www.baus.net/on-tcp_cork
 */
int mk_socket_set_cork_flag(int fd, int state)
{

#ifdef TRACE
    MK_TRACE("Socket, set Cork Flag FD %i to %s", fd, (state ? "ON" : "OFF"));
#endif

    return setsockopt(fd, SOL_TCP, TCP_CORK, &state, sizeof(state));
}

int mk_socket_set_nonblocking(int sockfd)
{

#ifdef TRACE
    MK_TRACE("Socket, set FD %i to non-blocking", sockfd);
#endif

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

int mk_socket_connect(int sockfd, char *server, int port)
{
    int res;
    struct sockaddr_in *remote;

    remote = (struct sockaddr_in *)
        mk_mem_malloc_z(sizeof(struct sockaddr_in));
    remote->sin_family = AF_INET;

    res = inet_pton(AF_INET, server, (void *) (&(remote->sin_addr.s_addr)));

    if (res < 0) {
        perror("Can't set remote->sin_addr.s_addr");
        mk_mem_free(remote);
        return -1;
    }
    else if (res == 0) {
        perror("Invalid IP address\n");
        mk_mem_free(remote);
        return -1;
    }

    remote->sin_port = htons(port);
    if (connect(sockfd,
                (struct sockaddr *) remote, sizeof(struct sockaddr)) == -1) {
        close(sockfd);
        perror("connect");
        return -1;
    }
    mk_mem_free(remote);
    return 0;
}

void mk_socket_reset(int socket)
{
    int status = 1;

    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &status, sizeof(int)) ==
        -1) {
        perror("setsockopt");
        exit(1);
    }
}

/* Just IPv4 for now... */
int mk_socket_server(int port, char *listen_addr)
{
    int fd;
    struct sockaddr_in local_sockaddr_in;

    /* Create server socket */
    fd = socket(PF_INET, SOCK_STREAM, 0);
    mk_socket_set_tcp_nodelay(fd);

    local_sockaddr_in.sin_family = AF_INET;
    local_sockaddr_in.sin_port = htons(port);
    inet_pton(AF_INET, listen_addr, &local_sockaddr_in.sin_addr.s_addr);
    memset(&(local_sockaddr_in.sin_zero), '\0', 8);

    /* Avoid bind issues, reset socket */
    mk_socket_reset(fd);

    if (bind(fd, (struct sockaddr *) &local_sockaddr_in,
             sizeof(struct sockaddr)) != 0) {
        perror("bind");
        printf("Error: Port %i cannot be used\n", port);
        exit(1);
    }

    /* Listen queue:
     * The queue limit is given by /proc/sys/net/core/somaxconn
     * we need to add a dynamic function to get that value on fly
     */
    if ((listen(fd, mk_utils_get_somaxconn())) != 0) {
        perror("listen");
        exit(1);
    }

    return fd;
}

int mk_socket_accept(int server_fd, struct sockaddr_in sock_addr)
{
    int remote_fd;
    socklen_t socket_size = sizeof(struct sockaddr_in);

    remote_fd = accept(server_fd, (struct sockaddr *) &sock_addr, &socket_size);

    return remote_fd;
}

int mk_socket_sendv(int socket_fd, struct mk_iov *mk_io, int to)
{
    ssize_t bytes_sent = -1;

    bytes_sent = mk_iov_send(socket_fd, mk_io, MK_IOV_SEND_TO_SOCKET);

    return bytes_sent;
}

int mk_socket_send(int socket_fd, const void *buf, size_t count )
{
    ssize_t bytes_sent = -1;

    bytes_sent = write(socket_fd, buf, count);

    return bytes_sent;
}

int mk_socket_read(int socket_fd, void *buf, int count)
{
    ssize_t bytes_read;

    bytes_read = read(socket_fd, (void *)buf, count);

    return bytes_read;
}

int mk_socket_send_file(int socket_fd, int file_fd, off_t *file_offset, 
                        size_t file_count)
{
    ssize_t bytes_written = -1;

    bytes_written = sendfile(socket_fd, file_fd, file_offset, file_count);

    if (bytes_written == -1) {
        perror( "error from sendfile" );
        return -1;
    }

    return bytes_written;
}
