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
#include "server.h"

#ifdef CHEETAH
#include "cheetah.h"
#endif

#if defined(__DATE__) && defined(__TIME__)
	static const char MONKEY_BUILT[] = __DATE__ " " __TIME__;
#else
	static const char MONKEY_BUILT[] = "Unknown";
#endif

void mk_details()
{
        printf("* Process ID is %i", getpid());
        printf("\n* Server socket listening on Port %i", config->serverport);
        printf("\n* %i threads, %i client connections per thread, total %i\n", 
               config->workers, config->worker_capacity,
               config->workers*config->worker_capacity);
        fflush(stdout);
}

void mk_version()
{ 
	printf("Monkey HTTP Daemon %s\n",VERSION);
	printf("Built : %s\n", MONKEY_BUILT);
	printf("Home  : http://monkeyd.sourceforge.net\n");
	fflush(stdout);
}

void mk_help()
{
	printf("Usage : monkey [-c directory] [-D] [-v] [-h]\n\n");
	printf("Available options:\n");
	printf("  -b\t\trun Monkey in benchmark mode, limits are disabled\n");
	printf("  -c directory\tspecify directory from configuration files\n");
	printf("  -D\t\trun Monkey as daemon\n");
        printf("  -S\t\tLaunch Cheetah Shell!\n");
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
	int opt, benchmark_mode=FALSE;
	int cheetah = 0;
        int daemon = 0;
	
	config = mk_mem_malloc(sizeof(struct server_config));
	config->file_config=0;
			
	opterr = 0;
	while ((opt = getopt(argc, argv, "bDSvhc:")) != -1)
	{
		switch (opt) {
			case 'v': 
				mk_version() ; 
				exit(0); 
				break;
			case 'h':
				mk_help();
				break;
			case 'D':
				daemon = 1;
				break;
                        case 'S':
                                cheetah = 1;
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
				mk_help();
				break;
		}
	}   

        if(cheetah && daemon){
                printf("Monkey: cannot run Cheetah Shell with Monkey in Daemon mode\n");
                return -1;
        }

	if(!config->file_config)
		config->file_config=MONKEY_PATH_CONF;
		
	mk_version();
	mk_signal_init();
	mk_config_start_configure();

        mk_init_time = time(NULL);
        server_fd = mk_socket_server(config->serverport);

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

	/* Workers: logger and clock */ 
        mk_worker_spawn((void *)mk_logger_worker_init);
        mk_worker_spawn((void *)mk_clock_worker_init);

	/* Running Monkey as daemon */
	if(daemon)
	{
		mk_utils_set_daemon();
	}

        /* Register PID of Monkey */
	mk_logger_register_pid();

        
	mk_mem_pointers_init();

        /* Create thread keys */
	pthread_key_create(&request_index, NULL);
	pthread_key_create(&epoll_fd, NULL);
	pthread_key_create(&timer, NULL);
        pthread_key_create(&mk_cache_iov_log, NULL);
        pthread_key_create(&mk_cache_iov_header, NULL);
        pthread_key_create(&mk_cache_header_toc, NULL);

        /* Change process owner */
	mk_user_set_uidgid();

        mk_config_sanity_check();

        /* Launch monkey http workers */
        mk_server_launch_workers();

        /* Print server details */
        mk_details();

        /* Cheetah Shell */
#ifdef CHEETAH
        if(cheetah){
                mk_worker_spawn((void *)mk_cheetah_init);
        }
#endif

        /* Server loop, let's listen for incomming clients */
        mk_server_loop(server_fd);

	return 0;
}

