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
 *  Youu should have received a copy of the GNU General Public License
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
#include "iov.h"
#include "clock.h"
#include "http.h"
#include "cache.h"

#include <sys/sysinfo.h>

void mk_logger_target_add(int fd, char *target)
{
        struct log_target *new, *aux;

        new = mk_mem_malloc(sizeof(struct log_target));
        new->fd = fd;
        new->target = target;
        new->next = NULL;

        if(!lt)
        {
                lt = new;
                return;
        }

        aux = lt;
        while(aux->next)
                aux = aux->next;

        aux->next = new;
}

struct log_target *mk_logger_match(int fd)
{
        struct log_target *aux;

        aux = lt;

        while(aux)
        {
                if(aux->fd == fd)
                {
                        return aux;
                }
                aux = aux->next;
        }

        return NULL;
}


void *mk_logger_worker_init(void *args)
{
        int efd, max_events=config->nhosts;
        int i, bytes, err;
        struct log_target *target=0;
        struct host *h=0;
        int flog;
        long slen;
        int timeout;
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

        /* Monkey allow just 75% of a pipe capacity */
        pipe_size = sysconf(_SC_PAGESIZE)*16;
        buffer_limit = (pipe_size*0.75);

        /* Creating poll */
        efd = mk_epoll_create(max_events);

        h = config->hosts;
        while(h)
        {
                /* Add access log file */
                mk_epoll_add_client(efd, h->log_access[0], 
                                MK_EPOLL_BEHAVIOR_DEFAULT);
                mk_logger_target_add(h->log_access[0], h->access_log_path);

                /* Add error log file */
                mk_epoll_add_client(efd, h->log_error[0],
                                MK_EPOLL_BEHAVIOR_DEFAULT);
                mk_logger_target_add(h->log_error[0], h->error_log_path);

                h = h->next;
        }

        timeout = time(NULL) + 3;
        
        /* Reading pipe buffer */
        while(1)
        {
                usleep(1200);

                struct epoll_event events[max_events];
                int num_fds = epoll_wait(efd, events, max_events, -1);

                clk = time(NULL);

                if(!h)
                {
                        h = config->hosts;
                }

                for(i=0; i< num_fds; i++)
                {
                        target = mk_logger_match(events[i].data.fd);

                        if(!target)
                        {
                                printf("\nERROR matching host/epoll_fd");
                                fflush(stdout);
                                continue;
                        }
                                
                        err = ioctl(target->fd, FIONREAD, &bytes);
                        if(err == -1)
                        {
                                perror("err");
                        }
                
                        
                        if(bytes < buffer_limit && clk<=timeout)
                        {
                                break;
                        }
                        else
                        {
                                timeout = clk+3;
                                flog = open(target->target, 
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
                        }
                }
        }
}

struct mk_iov *mk_logger_iov_get()
{
        return (struct mk_iov *) pthread_getspecific(mk_cache_iov_log);
}

void mk_logger_iov_free(struct mk_iov *iov)
{
        mk_iov_free_marked(iov);
}

/* Registra en archivos de logs: accesos
 y errores */
int mk_logger_write_log(struct log_info *log, struct host *h)
{
        struct mk_iov *iov;
        mk_pointer *status, method, protocol;

        if(log->status!=S_LOG_ON)
        {
                return 0;
        }

        iov = mk_logger_iov_get();
        
        /* client IP address */
        mk_iov_add_entry(iov, log->ip.data, log->ip.len, 
                         mk_logfile_iov_dash, MK_IOV_NOT_FREE_BUF);

        /* Date/time when object was requested */
        mk_iov_add_entry(iov, log_current_time.data, log_current_time.len, 
                         mk_iov_space,
                         MK_IOV_NOT_FREE_BUF);

        /* Register a successfull request */
        if(log->final_response==M_HTTP_OK || log->final_response==M_REDIR_MOVED_T)
        {
                /* HTTP method required */
                method = mk_http_method_check_str(log->method);
                mk_iov_add_entry(iov, method.data, method.len, mk_iov_space, 
                                 MK_IOV_NOT_FREE_BUF);

                /* HTTP URI required */
                mk_iov_add_entry(iov, log->uri.data, log->uri.len, 
                                 mk_iov_space, MK_IOV_NOT_FREE_BUF);


                if(log->protocol)
                {
                        protocol = mk_http_protocol_check_str(log->protocol);
                        mk_iov_add_entry(iov, protocol.data, protocol.len, 
                                         mk_iov_space, 
                                         MK_IOV_NOT_FREE_BUF);
                }

                /* HTTP status code */
                status = (mk_pointer *)
                        mk_http_status_get(log->final_response);
                mk_iov_add_entry(iov, status->data, status->len, 
                                 mk_iov_space, 
                                 MK_IOV_NOT_FREE_BUF);

                /* object size */
                mk_iov_add_entry(iov, 
                                 log->size_p.data, 
                                 log->size_p.len, 
                                 mk_iov_lf,
                                 MK_IOV_NOT_FREE_BUF);
                
                /* Send info to pipe */
                mk_iov_send(h->log_access[1], iov, MK_IOV_SEND_TO_PIPE);
        }
        else{ /* Register some error */
                mk_iov_add_entry(iov, 
                                 log->error_msg.data, 
                                 log->error_msg.len, 
                                 mk_iov_lf,
                                 MK_IOV_NOT_FREE_BUF);
                mk_iov_send(h->log_error[1], iov, MK_IOV_SEND_TO_PIPE);

        }
        mk_logger_iov_free(iov);
        return 0;       
}

/* Write Monkey's PID */
int mk_logger_register_pid()
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
int mk_logger_remove_pid()
{
                mk_user_undo_uidgid();
                return remove(config->pid_file_path);
}
