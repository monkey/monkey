/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2008, Eduardo Silva P.
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef MK_SOCKET_H
#define MK_SOCKET_H

/* Socket_Timeout() */
#define ST_RECV 0
#define ST_SEND 1

#define TCP_CORK_ON 1
#define TCP_CORK_OFF 0

int mk_socket_set_cork_flag(int fd, int state);
int mk_socket_set_tcp_nodelay(int sockfd);
int mk_socket_set_nonblocking(int sockfd);

char *mk_socket_get_ip(int socket);
int mk_socket_close(int socket);
int mk_socket_timeout(int s, char *buf, int len, 
		int timeout, int recv_send);

int mk_socket_create();
int mk_socket_connect(int sockfd, char *server, int port);
void mk_socket_reset(int socket);
int mk_socket_server(int port);

#endif

