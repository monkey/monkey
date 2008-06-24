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
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <string.h>

#include "monkey.h"
#include "conn_switch.h"
#include "scheduler.h"
#include "memory.h"
#include "epoll.h"
#include "request.h"

/* Register thread information */
int mk_sched_register_thread(pthread_t tid, int efd)
{
	struct sched_list_node *sr, *aux;

	sr = mk_mem_malloc(sizeof(struct sched_list_node)); 
	sr->tid = tid;
	sr->epoll_fd = efd;
	sr->request_handler = NULL;
	sr->next = NULL;

	if(!sched_list)
	{
		sr->idx = 1;
		sched_list = sr;
		return 0;
	}

	aux = sched_list;
	while(aux->next)
	{
		aux = aux->next;
	}
	sr->idx = aux->idx + 1;
	aux->next = sr;
	return 0;
}

/*
 * Launch a thread which will be listening 
 * for incomings file descriptors
 */
int mk_sched_launch_thread(int max_events)
{
	int efd;
	pthread_t tid;
	pthread_attr_t attr;
	sched_thread_conf *thconf;
	pthread_mutex_t mutex_wait_register;

	/* Creating epoll file descriptor */
	efd = mk_epoll_create(max_events);
	if(efd < 1)
	{
		return -1;
	}
	
	/* Thread stuff */
	pthread_mutex_init(&mutex_wait_register,(pthread_mutexattr_t *) NULL);
	pthread_mutex_lock(&mutex_wait_register);

	thconf = mk_mem_malloc(sizeof(sched_thread_conf));
	thconf->epoll_fd = efd;
	thconf->max_events = max_events;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if(pthread_create(&tid, &attr, mk_sched_launch_epoll_loop,
				(void *) thconf)!=0)
	{
		perror("pthread_create");
		return -1;
	}

	/* Register working thread */
	mk_sched_register_thread(tid, efd);
	pthread_mutex_unlock(&mutex_wait_register);
	return 0;
}

void *mk_sched_launch_epoll_loop(void *thread_conf)
{
	sched_thread_conf *thconf;
     
	thconf = thread_conf;

	mk_epoll_calls *callers;
	callers = mk_epoll_set_callers((void *)mk_conn_switch,
			MK_CONN_SWITCH_READ, 
			MK_CONN_SWITCH_WRITE);

	mk_sched_set_thread_poll(thconf->epoll_fd);
	mk_epoll_init(thconf->epoll_fd, callers, thconf->max_events);
	return 0;
}

struct client_request *mk_sched_get_request_handler()
{
	return (struct client_request *) pthread_getspecific(request_handler);
}

void mk_sched_set_request_handler(struct client_request *hr)
{
	pthread_setspecific(request_handler, (void *)hr);
}

void mk_sched_set_thread_poll(int epoll)
{
	pthread_setspecific(epoll_fd, (void *) epoll);
}

int mk_sched_get_thread_poll()
{
	return (int) pthread_getspecific(epoll_fd);
}

