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

typedef struct {
	int (*func_switch)(void *, void *);
	int read;
	int write;
} mk_epoll_calls;

int mk_epoll_create(int max_events);
void *mk_epoll_init(int epoll_fd, mk_epoll_calls *calls, int max_events);

mk_epoll_calls *mk_epoll_set_callers(void (*func_switch)(void *), int read, int write);

int mk_epoll_add_client(int epoll_fd, int socket);
int mk_epoll_set_ready_for_write(int epoll_fd, int socket);

