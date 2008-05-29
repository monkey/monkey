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

#define MAX_EVENTS 32000

mk_epoll_calls *mk_epoll_set_callers(void (*read)(void *), void (*write)(void *))
{
	mk_epoll_calls *calls;

	calls = malloc(sizeof(mk_epoll_calls));
	calls->func_read = read;
	calls->func_write = write;

	return calls;
}
		
void epoll_init(int server, mk_epoll_calls *calls)
{
	int i, ret, epoll_fd;
	struct sockaddr remote_addr;
	struct epoll_event event;

	socklen_t addr_size = sizeof(remote_addr);
	epoll_fd = epoll_create(MAX_EVENTS);

	if (epoll_fd == -1) {
		perror("epoll_create");
	}

	event.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	event.data.fd = server;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server, &event) == -1) {
		perror("epoll_ctl");
	}

//void epoll_start_loop(int server, int epoll_fd)
	while(1){
		struct epoll_event events[MAX_EVENTS];
		int num_fds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

		event.events |= EPOLLOUT | EPOLLET;
		for(i=0; i< num_fds; i++) {
			// Case 1: Error condition
			if (events[i].events & (EPOLLHUP | EPOLLERR)) {
				fputs("epoll: EPOLLERR", stderr);
				close(events[i].data.fd);
				continue;
			}
			assert(events[i].events & (EPOLLIN | EPOLLOUT));

			// Case 2: Our server is receiving a connection
			if (events[i].data.fd == server) {
				int connection = accept(server, &remote_addr, &addr_size);
				
				//printf("**: NEW CLIENT SOCKET: %i", connection);
				//fflush(stdout);

				if (connection == -1) {
					if (errno != EAGAIN && errno != EWOULDBLOCK) {
						perror("accept");
					}
					continue;
				}
				
				setnonblocking(connection);

				// Add the connection to our epoll loop
				event.data.fd = connection;
				if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connection, 
							&event) == -1) {
				    perror("epoll_ctl");
				}
				continue;
			}

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
				ret = (* calls->func_read)(events[i].data.fd);
				if(ret<0){
					close(events[i].data.fd);
				}
			}
			if(events[i].events & EPOLLOUT)
			{
				//printf("\nCALL::WRITE DATA");
				//fflush(stdout);
				ret = (* calls->func_write)(events[i].data.fd);
				//if(ret<0){
				//	close(events[i].data.fd);
				//}
			}
		}
	}
}

