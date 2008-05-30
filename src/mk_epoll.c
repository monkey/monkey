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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "monkey.h"

#define MAX_EVENTS 10000

mk_epoll_calls *mk_epoll_set_callers(void (*read)(void *), void (*write)(void *))
{
	mk_epoll_calls *calls;

	calls = malloc(sizeof(mk_epoll_calls));
	calls->func_read = (void *) read;
	calls->func_write = (void *) write;

	return calls;
}

int mk_epoll_create(int max_events)
{
	int epoll_fd;

	epoll_fd = epoll_create(max_events);
	if (epoll_fd == -1) {
		perror("epoll_create");
	}

	return epoll_fd;
}

void *mk_epoll_init(int epoll_fd, mk_epoll_calls *calls, int max_events)
{
	int i, ret;
	struct sched_list_node *sched_node;

	pthread_mutex_lock(&mutex_wait_register);
	
	sched_node = mk_sched_get_handler_owner();
	if(!sched_node)
	{
		printf("\nNODE NULL!");
		fflush(stdout);
	}

	pthread_mutex_unlock(&mutex_wait_register);
	
	sched_node->request_handler = NULL;
	while(1){
		struct epoll_event events[max_events];
		int num_fds = epoll_wait(epoll_fd, events, max_events, -1);

		for(i=0; i< num_fds; i++) {
			// Case 1: Error condition
			if (events[i].events & (EPOLLHUP | EPOLLERR)) {
				fputs("epoll: EPOLLERR", stderr);
				close(events[i].data.fd);
				continue;
			}
			assert(events[i].events & (EPOLLIN | EPOLLOUT));

			/*
			printf("\n*** EPOLL EVENT DEBUG: %i ***", events[i].data.fd);
			if(events[i].events & EPOLLIN)
			{
				printf("\nPOLLIN");
			}
			if(events[i].events & EPOLLOUT)
			{
				printf("\nPOLLOUT");
			}
			if(events[i].events & EPOLLET)
			{
				printf("\nPOLLET");
			}
			fflush(stdout);
			*/

			if(events[i].events & EPOLLIN)
			{
				//printf("\nCALL::READ DATA");
				//fflush(stdout);
				ret = (* calls->func_read)((void *)events[i].data.fd);
				if(ret<0){
					close(events[i].data.fd);
				}
			}
			if(events[i].events & EPOLLOUT)
			{
				//printf("\nCALL::WRITE DATA");
				//fflush(stdout);
				ret = (* calls->func_write)((void *)events[i].data.fd);
				if(ret == 0){
					close(events[i].data.fd);
				}
			}
		}
	}
}

int mk_epoll_add_client(int epoll_fd, int socket)
{
	int ret;
	struct epoll_event event;

	event.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLERR | EPOLLHUP;
	event.data.fd = socket;

	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket, &event);
	if(ret < 0)
	{
		perror("epoll_ctl");
	}
	return ret;
}

