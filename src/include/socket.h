/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P. <edsiper@gmail.com>
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

#ifndef MK_SOCKET_H
#define MK_SOCKET_H

#include <sys/uio.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "iov.h"
#include "request.h"

/* Socket_Timeout() */
#define ST_RECV 0
#define ST_SEND 1

#define TCP_CORK_ON 1
#define TCP_CORK_OFF 0

int mk_socket_set_cork_flag(int fd, int state);
int mk_socket_set_tcp_nodelay(int sockfd);
int mk_socket_set_nonblocking(int sockfd);

int mk_socket_get_ip(int socket, char *ipv4);
int mk_socket_close(int socket);
int mk_socket_timeout(int s, char *buf, int len, int timeout, int recv_send);

int mk_socket_create();
int mk_socket_connect(int sockfd, char *server, int port);
void mk_socket_reset(int socket);
int mk_socket_server(int port, char *listen_addr);

int mk_socket_accept(int server_fd, struct sockaddr_in sock_addr);
int mk_socket_sendv(int socket_fd, struct mk_iov *mk_io, int to);
int mk_socket_send(int socket_fd, const void *buf, size_t count);
int mk_socket_read(int socket_fd, void *buf, int count);

#endif
