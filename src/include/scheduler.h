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

struct sched_list_node{
	short int idx;
	pthread_t tid;
	int epoll_fd;
	struct client_request *request_handler;
	struct sched_list_node *next;
};

struct sched_list_node *sched_list;

typedef struct {
	int epoll_fd;
	int max_events;
} sched_thread_conf;

pthread_key_t epoll_fd;

int mk_sched_register_thread(pthread_t tid, int epoll_fd);
int mk_sched_launch_thread(int max_events);
void *mk_sched_launch_epoll_loop(void *thread_conf);
struct sched_list_node *mk_sched_get_handler_owner();
struct client_request *mk_sched_get_request_handler();
void mk_sched_set_request_handler(struct client_request *hr);

int mk_sched_get_thread_poll();
void mk_sched_set_thread_poll(int epoll);

