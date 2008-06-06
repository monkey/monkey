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

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "monkey.h"
#include "http.h"
#include "http_status.h"

void *start_worker_logger(void *args)
{
    struct log_queue *lq;
    printf("\nStarting logger worker--->>>\n\n");
    fflush(stdout);

    lq = (struct log_queue *) _log_queue;

    while(1)
    {
        if(_log_queue){
            write_log(_log_queue->info);
            pthread_mutex_lock(&mutex_log_queue);
            lq = _log_queue;
            lq->info = NULL;
            lq->next = NULL;

            _log_queue = _log_queue->next;
            pthread_mutex_unlock(&mutex_log_queue);
        }

        /* Escribir log !!!*/
        /* Borrar actual log !!!*/
    }
}

int logger_add_request(struct log_info *log)
{
    struct log_queue *new, *last, *t;

    pthread_mutex_lock(&mutex_log_queue);

    new = M_malloc(sizeof(struct log_queue));
    new->info = log;
    new->next = NULL;
    
    if(!_log_queue)
    {
        _log_queue = new;
    }
    else
    {
        last = _log_queue;
        while(last->next)
            last = last->next;

        last->next = new;
    }

    pthread_mutex_unlock(&mutex_log_queue);
    
    t = _log_queue;
    printf("\n****ROUND****");
    while(t){
        printf("\nLOG: %s", t->info->uri);
        t = t->next;
    }
    fflush(stdout);
    

    return 0;
}

/* Registra en archivos de logs: accesos
 y errores */
int write_log(struct log_info *log)
{
	FILE *log_file=0;
	
    //printf("\n-->LOGO: %s", log->uri);
    //fflush(stdout);

	if(log->status!=S_LOG_ON){
		return 0;
	}
	pthread_mutex_lock(&mutex_logfile);
	
	/* Register a successfull request */
	if(log->final_response==M_HTTP_OK || log->final_response==M_REDIR_MOVED_T){
		if((log_file=fopen(log->host_conf->access_log_path,"a"))==NULL){
			pthread_mutex_unlock(&mutex_logfile);
			return -1;
		}
			fprintf(log_file,"%s - %s ", log->ip, log->datetime);
			fprintf(log_file,"\"%s %s %s\" %i", mk_http_method_check_str(log->method), 
				log->uri, mk_http_protocol_check_str(log->protocol), log->final_response);
			if(log->size > 0) 
				fprintf(log_file," %i\n", log->size);
			else
				fprintf(log_file,"\n");

	}
	else{ /* Regiter some error */
		if((log_file=fopen(log->host_conf->error_log_path,"a"))==NULL){
			pthread_mutex_unlock(&mutex_logfile);
			return -1;
		}
		fprintf(log_file, "%s - %s  %s\n", log->ip, log->datetime, log->error_msg);
	}
	fclose(log_file);
	pthread_mutex_unlock(&mutex_logfile);
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
