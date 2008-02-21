/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2003, Eduardo Silva P.
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

#include <pthread.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <resolv.h>

#include "monkey.h"
#include <sys/time.h>

#if defined(__DATE__) && defined(__TIME__)
	static const char MONKEY_BUILT[] = __DATE__ " " __TIME__;
#else
	static const char MONKEY_BUILT[] = "Unknown";
#endif

#define CONX_CLOSED 0
#define CONX_OPEN	1
		
void ResetSocket(int fd)
{
	int status=1;
	
	if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&status,sizeof(int))==-1) {
		perror("setsockopt");
		exit(1);
	}	
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


void thread_init(void *args)
{
	int request_response=0, socket;
    int request_keepalive;

	struct process *th=0;

    socket = (int) args;

    /* Alloc main thread info */
	th = (struct  process *) RegProc(pthread_self(), socket);
    th->cr = M_malloc(sizeof(struct client_request));
    th->cr->pipelined = FALSE;
    th->cr->counter_connections = 0;
    th->cr->socket = socket;
    th->cr->request = NULL;

	while(request_response==0){
		request_response = Get_Request(th->cr); /* Working in request... */
        if(!th->cr->request)
        {
            break;
        }

        request_keepalive = th->cr->request->keep_alive;
        free_list_requests(th->cr);

        /* Persistent connection: Exit */
        if(th->cr->counter_connections>=config->max_keep_alive_request || 
                           request_response==2 || request_response==-1)
        {
            break;
        }

		if(config->keep_alive==VAR_OFF || request_keepalive==VAR_OFF)
        {
			break;
		}
	}

	FreeThread(pthread_self()); /* Close socket & delete thread info from register */
	//pthread_exit(0); /* See you! */
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
	pthread_t tid;
	pthread_attr_t thread_attr;	
    mk_thread_pool *pool;

        struct process *check_ip;
        int ip_times=0, status_max_ip=CONX_OPEN;
        int sin_size;
        char *IP_client;

	struct sockaddr_in local_sockaddr_in;
			
	config = M_malloc(sizeof(struct server_config));
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
	Init_Signals();
	M_Config_start_configure();

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


	local_fd=socket(PF_INET,SOCK_STREAM,0);
	local_sockaddr_in.sin_family=AF_INET;
	local_sockaddr_in.sin_port=htons(config->serverport);
	local_sockaddr_in.sin_addr.s_addr=INADDR_ANY;
	memset(&(local_sockaddr_in.sin_zero),'\0',8);

	ResetSocket(local_fd);

	if(bind(local_fd,(struct sockaddr *)&local_sockaddr_in,sizeof(struct sockaddr))!=0){
		puts("Error: Port busy.");
		exit(1);
	}		     
	
	if((listen(local_fd, 1024))!=0) {
		perror("listen");
		exit(1);
	}

    /* Main log queue index list */
    //(struct log_queue *) _log_queue = NULL;

	/* threads attr / mutex */
	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	pthread_mutex_init(&mutex_thread_list,  (pthread_mutexattr_t *) NULL);
	pthread_mutex_init(&mutex_cgi_child,  (pthread_mutexattr_t *) NULL);
	pthread_mutex_init(&mutex_logfile, (pthread_mutexattr_t *) NULL);
	pthread_mutex_init(&mutex_thread_counter, (pthread_mutexattr_t *) NULL);
    pthread_mutex_init(&mutex_log_queue,  (pthread_mutexattr_t *) NULL);

    pthread_create(&tid, &thread_attr, logger_worker, NULL);

	/* Running Monkey as daemon */
	if(daemon)
		set_daemon();
		
	add_log_pid(); /* Register Pid of monkey */

#ifdef MOD_MYSQL
	mod_mysql_init();
#endif

	SetUIDGID(); 	/* Changing user */

	thread_counter=0;
    pool = mk_thread_pool_create(20);

	while(1) { /* Waiting for new connections */
				
		sin_size=sizeof(struct sockaddr_in);
		if((remote_fd=accept(local_fd,(struct sockaddr *)&remote, &sin_size))==-1){
			continue;
		}

		/* IP allowed ? ; Limit of connections 
		if(thread_counter > config->maxclients){
			close(remote_fd);
			continue;
		}
        */
		/*
    		Limit of maximum of connections from same IP address :
            This routine check every node of struct with a counter checking
			if the new connection exist more times than has been allowed in
			config->max_ip.
		*/
		IP_client = (char *) PutIP(remote_fd);
		if(!IP_client){
			close(remote_fd);
			M_free(IP_client);
			continue;			
		}

		check_ip=first_process;
		while(check_ip!=NULL && config->max_ip!=0) {
			if(strcasecmp(check_ip->ip_client, IP_client)==0){
				ip_times++;
			}
			if(ip_times>=config->max_ip){
				close(remote_fd);
				status_max_ip=CONX_CLOSED;
			}
			check_ip=check_ip->next;
		}

		if(status_max_ip==CONX_CLOSED)
			continue;

        mk_thread_pool_set(pool, thread_init,  (void *) remote_fd);
        continue;

        /*

		if(pthread_create(&tid, &thread_attr, thread_init, (void *) remote_fd)!=0){
			perror("pthread_create");
			close(remote_fd);
		}
		else{
			pthread_mutex_lock(&mutex_thread_counter);
			thread_counter++;
			pthread_mutex_unlock(&mutex_thread_counter);
		}
        */
	}
	return 0;
}
