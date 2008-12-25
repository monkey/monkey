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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <resolv.h>

#include "monkey.h"
#include "socket.h"
#include <sys/time.h>

#include <string.h>

#include "epoll.h"
#include "scheduler.h"
#include "user.h"
#include "info.h"
#include "utils.h"
#include "logfile.h"
#include "signals.h"
#include "config.h"
#include "modules.h"
#include "memory.h"
#include "dir_html.h"
#include "clock.h"
#include "cache.h"
#include "worker.h"

#if defined(__DATE__) && defined(__TIME__)
	static const char MONKEY_BUILT[] = __DATE__ " " __TIME__;
#else
	static const char MONKEY_BUILT[] = "Unknown";
#endif

#define CONX_CLOSED 0
#define CONX_OPEN 1
		
void MonkeyPid()
{
        printf("\n** Server details **");
        printf("\nProcess PID: %i\n", getpid());
        fflush(stdout);
}

void Version()
{ 
	printf("Monkey HTTP Daemon %s\n",VERSION);
	printf("Built : %s\n", MONKEY_BUILT);
	printf("Home  : http://monkeyd.sourceforge.net\n");
	fflush(stdout);
}

void Help()
{
	printf("Usage : monkey [-c directory] [-D] [-v] [-h]\n\n");
	printf("Available options:\n");
	printf("  -b\t\trun Monkey in benchmark mode, limits are disabled\n");
	printf("  -c directory\tspecify directory from configuration files\n");
	printf("  -D\t\trun Monkey as daemon\n");
	printf("  -v\t\tshow version number\n");
	printf("  -h\t\tthis help\n\n");
	exit(0);
}


	
void set_benchmark_conf()
{
	const int max_int = 65000;

	config->max_keep_alive_request = max_int;
	config->maxclients = max_int;
	config->max_ip = 0;
}

/* MAIN */
int main(int argc, char **argv)
{
	int opt, remote_fd, benchmark_mode=FALSE;
	char daemon = 0;

	int i, num_threads;
	struct sched_list_node *sched;
	
	config = mk_mem_malloc(sizeof(struct server_config));
	config->file_config=0;
			
	opterr = 0;
	while ((opt = getopt(argc, argv, "bDvhc:")) != -1)
	{
		switch (opt) {
			case 'v': 
				Version() ; 
				exit(0); 
				break;
			case 'h':
				Help();
				break;
			case 'D':
				daemon = 1;
				break;
			case 'c':
				if (strlen(optarg) != 0) {
					config->file_config=optarg;
					break;
				}
			case 'b':
				benchmark_mode = TRUE;
				break;
			case '?':
				printf("Monkey: Invalid option or option needs an argument.\n");
				Help();
				break;
		}
	}   

	if(!config->file_config)
		config->file_config=MONKEY_PATH_CONF;
		
	Version();
        MonkeyPid();
	Init_Signals();
	mk_config_start_configure();

	/* 
        Benchmark mode overwrite some configuration directives in order 
        to disable some limit numbers as number of clients, request per 
        client, same ip connected, etc
	*/
	if(benchmark_mode)
	{
		printf("*** Running Monkey in Benchmark mode ***\n");
		fflush(stdout);
		set_benchmark_conf();
	}

        server_fd = mk_socket_server(config->serverport);

	/* logger-worker */ 
        mk_worker_spawn((void *)mk_logger_worker_init);
        /* Starting clock worker */
        mk_worker_spawn((void *)mk_clock_worker_init);

	/* Running Monkey as daemon */
	if(daemon)
	{
		set_daemon();
	}
		
	add_log_pid(); /* Register Pid of monkey */

#ifdef MOD_MYSQL
	mod_mysql_init();
#endif

	SetUIDGID(); 	/* Changing user */

	num_threads = 3;
	sched_list = NULL;

	mk_mem_pointers_init();

	pthread_key_create(&request_handler, NULL);
	pthread_key_create(&epoll_fd, NULL);
	pthread_key_create(&timer, NULL);
        pthread_key_create(&mk_cache_iov_log, NULL);
        pthread_key_create(&mk_cache_iov_header, NULL);

	for(i=0; i<num_threads; i++)
	{
		mk_sched_launch_thread(40);
	}

	sched = sched_list;
	socklen_t socket_size = sizeof(remote);

	while(1)
	{
		if((remote_fd=accept(server_fd, 
                                     (struct sockaddr *)&remote, 
                                     &socket_size))==-1)
		{
			perror("accept");
			continue;
		}

		mk_epoll_add_client(sched->epoll_fd, remote_fd, 
                                    MK_EPOLL_BEHAVIOR_TRIGGERED);
		
		if(sched->next)
		{
			sched = sched->next;
		}
		else{
			sched = sched_list;
		}
	}
	return 0;
}

