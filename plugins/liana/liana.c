/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>

#include "config.h"
#include "plugin.h"

/* Plugin data for register */
mk_plugin_data_t _shortname = "liana";
mk_plugin_data_t _name = "Liana Network";
mk_plugin_data_t _version = "0.1";
mk_plugin_hook_t _hooks = MK_PLUGIN_NETWORK_IO;

struct plugin_api *mk_api;
struct mk_config *conf;

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;
    return 0;
}

int _mkp_exit()
{
    return 0;
}

int _mkp_network_io_accept(int server_fd, struct sockaddr_in sock_addr)
{
    int remote_fd;
    socklen_t socket_size = sizeof(struct sockaddr_in);

    remote_fd = accept4(server_fd, (struct sockaddr *) &sock_addr, 
                        &socket_size, SOCK_NONBLOCK);
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

    bytes_sent = (ssize_t) mk_api->iov_send(socket_fd, mk_io, MK_IOV_SEND_TO_SOCKET);

    return bytes_sent;
}

int _mkp_network_io_close(int socket_fd)
{
    close(socket_fd);
    return 0;
}

int _mkp_network_io_connect(char *host, int port)
{
    return 0;
}

int _mkp_network_io_send_file(int socket_fd, int file_fd, off_t *file_offset, 
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
