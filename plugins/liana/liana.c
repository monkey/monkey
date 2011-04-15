/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P.
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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <fcntl.h>

#include "MKPlugin.h"

MONKEY_PLUGIN("liana",         /* shortname */
              "Liana Network", /* name */
              VERSION,        /* version */
              MK_PLUGIN_NETWORK_IO); /* hooks */

struct mk_config *conf;

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;
    return 0;
}

void _mkp_exit()
{
}

int _mkp_network_io_accept(int server_fd, struct sockaddr_in sock_addr)
{
    int remote_fd;
    socklen_t socket_size = sizeof(struct sockaddr_in);

#ifdef ACCEPT_GENERIC
    remote_fd = accept(server_fd, (struct sockaddr *) &sock_addr,
                       &socket_size);

    if (fcntl(remote_fd, F_SETFL, fcntl(remote_fd, F_GETFD, 0) | O_NONBLOCK) == -1) {
        mk_err("Can't set to non-blocking the socket");
    }
#else
    remote_fd = accept4(server_fd, (struct sockaddr *) &sock_addr,
                        &socket_size, SOCK_NONBLOCK);
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

int _mkp_network_io_connect(int socket_fd, char *host, int port)
{
    int res;
    struct sockaddr_in *remote;

    remote = (struct sockaddr_in *)
        mk_api->mem_alloc_z(sizeof(struct sockaddr_in));
    remote->sin_family = AF_INET;

    res = inet_pton(AF_INET, host, (void *) (&(remote->sin_addr.s_addr)));

    if (res < 0) {
        mk_warn("Cannot set remote->sin_addr.s_addr");
        mk_api->mem_free(remote);
        return -1;
    }
    else if (res == 0) {
        mk_warn("Invalid IP address");
        mk_api->mem_free(remote);
        return -1;
    }

    remote->sin_port = htons(port);
    if (connect(socket_fd,
                (struct sockaddr *) remote, sizeof(struct sockaddr)) == -1) {
        close(socket_fd);
        mk_err("connect");
        return -1;
    }

    mk_api->mem_free(remote);

    return 0;
}

int _mkp_network_io_send_file(int socket_fd, int file_fd, off_t *file_offset,
                              size_t file_count)
{
    ssize_t bytes_written = -1;

    bytes_written = sendfile(socket_fd, file_fd, file_offset, file_count);

    if (bytes_written == -1) {
        MK_TRACE("error from sendfile()");
        return -1;
    }

    return bytes_written;
}

int _mkp_network_io_create_socket(int domain, int type, int protocol)
{
    int socket_fd;

    socket_fd = socket(domain, type, protocol);

    return socket_fd;
}

int _mkp_network_io_bind(int socket_fd, const struct sockaddr *addr, socklen_t addrlen, int backlog)
{
    int ret;

    ret = bind(socket_fd, addr, addrlen);

    if( ret == -1 ) {
        mk_warn("Error binding socket");
        return ret;
    }

    ret = listen(socket_fd, backlog);

    if(ret == -1 ) {
        mk_warn("Error setting up the listener");
        return -1;
    }

    return ret;
}

int _mkp_network_io_server(int port, char *listen_addr)
{
    int socket_fd;
    int ret;
    struct sockaddr_in local_sockaddr_in;

    socket_fd = _mkp_network_io_create_socket(PF_INET, SOCK_STREAM, 0);
    if( socket_fd == -1) {
        mk_warn("Error creating server socket");
        return -1;
    }
    mk_api->socket_set_tcp_nodelay(socket_fd);

    local_sockaddr_in.sin_family = AF_INET;
    local_sockaddr_in.sin_port = htons(port);
    inet_pton(AF_INET, listen_addr, &local_sockaddr_in.sin_addr.s_addr);
    memset(&(local_sockaddr_in.sin_zero), '\0', 8);

    mk_api->socket_reset(socket_fd);

    ret = _mkp_network_io_bind(socket_fd, (struct sockaddr *) &local_sockaddr_in,
                               sizeof(struct sockaddr), MK_SOMAXCONN);

    if(ret == -1) {
        mk_err("Port %i cannot be used\n", port);
        return -1;
    }


    return socket_fd;
}
