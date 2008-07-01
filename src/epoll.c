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
#include "epoll.h"

#define MAX_EVENTS 5000

mk_epoll_calls *mk_epoll_set_callers(void (*func_switch)(void *),
		int read, int write)
{
	mk_epoll_calls *calls;

	calls = malloc(sizeof(mk_epoll_calls));
	calls->func_switch = (void *) func_switch;
	calls->read = (int) read;
	calls->write = (int) write;
	return calls;
}

int mk_epoll_create(int max_events)
{
	int efd;

	efd = epoll_create(max_events);
	if (efd == -1) {
		perror("epoll_create");
	}

	return efd;
}

void *mk_epoll_init(int efd, mk_epoll_calls *calls, int max_events)
{
	int i, ret;

	pthread_mutex_lock(&mutex_wait_register);
	pthread_mutex_unlock(&mutex_wait_register);
	
	while(1){
		struct epoll_event events[max_events];
		int num_fds = epoll_wait(efd, events, max_events, -1);

		for(i=0; i< num_fds; i++) {
			// Case 1: Error condition
			if (events[i].events & (EPOLLHUP | EPOLLERR)) {
				//fputs("\nepoll: EPOLLERR", stderr);
				close(events[i].data.fd);
				continue;
			}
			assert(events[i].events & (EPOLLIN | EPOLLOUT));

			if(events[i].events & EPOLLIN)
			{
				//printf("\nEPOLL::going read");
				//fflush(stdout);
				
				ret = (* calls->func_switch)((void *)calls->read, 
						(void *)events[i].data.fd);
				if(ret<0){
					close(events[i].data.fd);
				}
			}
			if(events[i].events & EPOLLOUT)
			{
				//printf("\nEPOLL::going write");
				//fflush(stdout);
				ret = (* calls->func_switch)((void *)calls->write,
						(void *)events[i].data.fd);
				if(ret<0){
					//printf("\nclosing...");
					//fflush(stdout);
					close(events[i].data.fd);
				}
			}
		}
	}
}

int mk_epoll_add_client(int efd, int socket, int mode)
{
	int ret;
	struct epoll_event event;

	event.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	event.data.fd = socket;

	if(mode == MK_EPOLL_BEHAVIOR_TRIGGERED)
	{
		event.events |= EPOLLET;
	}


	ret = epoll_ctl(efd, EPOLL_CTL_ADD, socket, &event);
	if(ret < 0)
	{
		perror("epoll_ctl");
	}
	return ret;
}

int mk_epoll_socket_change_mode(int efd, int socket, int mode)
{
	int ret;
	struct epoll_event event;
	
	event.events = EPOLLET | EPOLLERR | EPOLLHUP;
	event.data.fd = socket;

	switch(mode)
	{
		case MK_EPOLL_READ:
			event.events |= EPOLLIN;
			break;
		case MK_EPOLL_WRITE:
			event.events |= EPOLLOUT;
			break;
	}
	
	ret = epoll_ctl(efd, EPOLL_CTL_MOD, socket, &event);
	if(ret < 0)
	{
		perror("\nepoll_ctl");
	}
	return ret;
}

