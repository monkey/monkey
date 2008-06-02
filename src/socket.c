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

/* 
 * Example from:
 * http://www.baus.net/on-tcp_cork
 */

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

int mk_socket_set_cork_flag(int fd, int state)
{
	return setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
}
