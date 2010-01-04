/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2008, Eduardo Silva P.
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
#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/time.h>
#include <sys/resource.h>

#include "monkey.h"
#include "config.h"
#include "scheduler.h"
#include "epoll.h"
#include "socket.h"
#include "plugin.h"

/* Return the number of clients that can be attended 
 * at the same time per worker thread
 */
int mk_server_worker_capacity(int nworkers)
{
        int max, avl;
        struct rlimit lim;

        /* Limit by system */
        getrlimit(RLIMIT_NOFILE, &lim);
        max = lim.rlim_cur;

        /* Minimum of fds needed by Monkey:
         * --------------------------------
         * 3 fds: stdin, stdout, stderr
         * 1 fd for main socket server
         * 1 fd for epoll array (per thread)
         * 1 fd for worker logger when writing to FS
         * 2 fd for worker logger pipe
         */

        avl = max - (3 + 1 + nworkers + 1 + 2); 
        return ((avl/2)/nworkers);
}

/* Here we launch the worker threads to attend clients */
void mk_server_launch_workers()
{
        int i;

        config->worker_capacity = mk_server_worker_capacity(config->workers);
        
        for(i=0; i<config->workers; i++)
        {
                mk_sched_launch_thread(config->worker_capacity);
        }
}

void mk_server_loop(int server_fd)
{
        int remote_fd;
        struct sockaddr_in sockaddr;
	struct sched_list_node *sched = sched_list;
	socklen_t socket_size = sizeof(struct sockaddr_in);

        while(1){
                remote_fd = accept(server_fd, (struct sockaddr *)&sockaddr,
                                   &socket_size);

                if(remote_fd == -1){
                        continue;
                }
                
                /* Assign socket to worker thread */
                mk_sched_add_client(sched, remote_fd);

                if(sched->next){
                        sched = sched->next;
                }
                else{
                        sched = sched_list;
                }
       }
}
