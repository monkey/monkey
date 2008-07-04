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

#define _GNU_SOURCE
#include <fcntl.h>

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/times.h>

#include "monkey.h"
#include "http.h"
#include "http_status.h"
#include "logfile.h"
#include "memory.h"
#include "config.h"
#include "user.h"
#include "utils.h"
#include "epoll.h"
#include "header.h"

#include <sys/sysinfo.h>

void *start_worker_logger(void *args)
{
	int efd, max_events=config->nhosts;
	int i, bytes, err;
	struct host *h=0;
	int flog;
	long slen;
	int fdop = 0;
	int timeout;
	int clock_ticks;
	int clk;

	/* pipe_size:
	 * ---------- 
	 * Linux set a pipe size usingto the PAGE_SIZE, 
	 * check linux/include/pipe_fs_i.h for details:
	 *
	 *       #define PIPE_SIZE               PAGE_SIZE
	 *
	 * In the same header file we can found that every 
	 * pipe has 16 pages, so our real memory allocation
	 * is: (PAGE_SIZE*PIPE_BUFFERS)
	 */
	long pipe_size;
	
	/* buffer_limit:
	 * -------------
	 * it means the maximum data that a monkey log pipe can contain.
	 */
	long buffer_limit;

	/* Monkey allow just 50% of a pipe capacity */
	pipe_size = sysconf(_SC_PAGESIZE)*16;
	buffer_limit = (pipe_size*0.75);

	/* Creating poll */
	efd = mk_epoll_create(max_events);
	h = config->hosts;
	while(h)
	{
		mk_epoll_add_client(efd, h->logpipe[0], MK_EPOLL_BEHAVIOR_DEFAULT);
		h = h->next;
	}

	/* set initial timeout */
	clock_ticks = sysconf(_SC_CLK_TCK);
	timeout = times(NULL) + clock_ticks;
	
	/* Reading pipe buffer */
	while(1)
	{
		usleep(1000);

		struct epoll_event events[max_events];
		int num_fds = epoll_wait(efd, events, max_events, -1);

		clk = times(NULL);

		if(!h)
		{
			h = config->hosts;
		}

		for(i=0; i< num_fds; i++)
		{
			while(h)
			{
				if(events[i].data.fd==h->logpipe[0]){
					break;
				}
				h = h->next;
			}

			if(!h)
			{
				printf("\nERROR matching host/epoll_fd");
				fflush(stdout);
				continue;
			}
				
			err = ioctl(h->logpipe[0], FIONREAD, &bytes);
			if(err == -1)
			{
				perror("err");
			}
		
			if(bytes < buffer_limit && clk<timeout)
			{
				continue;
			}
			else
			{
				timeout = clk+clock_ticks;
				//fdop++;
				flog = open(h->access_log_path, 
						O_WRONLY | O_CREAT , 0644);
			
				if(flog==-1)
				{
					perror("open");
					continue;
				}

				lseek(flog, 0, SEEK_END);
				slen = splice(events[i].data.fd, NULL, flog,
						NULL, bytes, SPLICE_F_MOVE);
				if(slen==-1)
				{
					perror("splice");
				}
				close(flog);
				//printf("\nfdop: %i", fdop);
				//fflush(stdout);
			}
		}
	}
}

/* Registra en archivos de logs: accesos
 y errores */
int write_log(struct log_info *log, int host_pipe)
{
	unsigned long len;
	FILE *log_file=0;
	char *buf;
	struct mk_iov *iov;

	if(log->status!=S_LOG_ON){
		return 0;
	}
	
	iov = mk_iov_create(20);

	/* Register a successfull request */
	if(log->final_response==M_HTTP_OK || log->final_response==M_REDIR_MOVED_T)
	{
			mk_iov_add_entry(iov, log->ip, 0, SPACE, MK_IOV_NOT_FREE_BUF);
			mk_iov_add_entry(iov, "-", 1, SPACE, MK_IOV_NOT_FREE_BUF);
			mk_iov_add_entry(iov, log->datetime, 0, SPACE, MK_IOV_NOT_FREE_BUF);
			
			buf = mk_http_method_check_str(log->method);
			mk_iov_add_entry(iov, buf, strlen(buf), SPACE, MK_IOV_NOT_FREE_BUF);
			mk_iov_add_entry(iov, log->uri, strlen(log->uri), SPACE, MK_IOV_NOT_FREE_BUF);
                        
			buf = mk_http_protocol_check_str(log->protocol);
			mk_iov_add_entry(iov, buf, strlen(buf), SPACE, MK_IOV_NOT_FREE_BUF);

			m_build_buffer(&buf, &len, "%i", log->final_response);
                        mk_iov_add_entry(iov, buf, len, SPACE, MK_IOV_FREE_BUF);

			buf = m_build_buffer(&buf, &len, "%i\n", log->size);
			mk_iov_add_entry(iov, buf, len, SPACE, MK_IOV_FREE_BUF);

			mk_iov_send(host_pipe, iov);
			mk_iov_free(iov);
	}
	else{ /* Regiter some error */
		if((log_file=fopen(log->host_conf->error_log_path,"a"))==NULL){
			pthread_mutex_unlock(&mutex_logfile);
			return -1;
		}
		fprintf(log_file, "%s - %s  %s\n", log->ip, log->datetime, log->error_msg);
	}
	return 0;	
}

/* Write Monkey's PID */
int add_log_pid()
{
	FILE *pid_file;
		
	remove(config->pid_file_path);
	config->pid_status=VAR_OFF;
	if((pid_file=fopen(config->pid_file_path,"w"))==NULL){
		puts("Error: I can't log pid of monkey");
		exit(1);
	}
	fprintf(pid_file,"%i", getpid());
	fclose(pid_file);
	config->pid_status=VAR_ON;

	return 0;	
}

/* Elimina log del PID */
int remove_log_pid()
{
		SetEGID_BACK();
		return remove(config->pid_file_path);
}

/* Calcula y formatea la salida de la fecha y 
	hora de conexi�n (Por Daniel R. Ome) */
char *PutTime() {

   time_t      fec_hora;
   static char data[255];

   if ( (fec_hora = time(NULL)) == -1 )
      return 0;

   strftime(data, 255, "[%d/%b/%G %T %z]",
               (struct tm *)localtime((time_t *) &fec_hora));

   return (char *) data;
}

char *BaseName(char *name)
{
   char *base;

   base = rindex (name, '/');
   
   return base ? base : name;
}
