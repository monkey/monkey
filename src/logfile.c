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

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "monkey.h"

/* Registra en archivos de logs: accesos
 y errores */
int log_main(struct request *sr)
{
	FILE *log_file=0;
	
	if(sr->log->status!=S_LOG_ON){
		return 0;
	}

	pthread_mutex_lock(&mutex_logfile);
	
	/* Registramos una peticion exitosa */
	if(sr->log->final_response==M_HTTP_OK || sr->log->final_response==M_REDIR_MOVED_T){
		if((log_file=fopen(config->access_log_path,"a"))==NULL){
			pthread_mutex_unlock(&mutex_logfile);
			return -1;
		}
			fprintf(log_file,"%s - %s ",sr->log->ip,sr->log->datetime);
			fprintf(log_file,"\"%s %s %s\" %i", M_METHOD_get_name(sr->method), 
				sr->uri, get_name_protocol(sr->protocol) , sr->log->final_response);
			if(sr->log->size > 0) 
				fprintf(log_file," %i\n",sr->log->size);
			else
				fprintf(log_file,"\n");

	}
	else{ /* Registramos algun error */
		if((log_file=fopen(config->error_log_path,"a"))==NULL){
			pthread_mutex_unlock(&mutex_logfile);
			return -1;
		}
		fprintf(log_file, "%s - %s  %s\n",sr->log->ip,sr->log->datetime, sr->log->error_msg);
	}
	fclose(log_file);
	pthread_mutex_unlock(&mutex_logfile);
	return 0;	
}

/* Registra PID de monkey */
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
	hora de conexión (Por Daniel R. Ome) */
char *PutTime() {

   time_t      fec_hora;
   static char data[255];

   if ( (fec_hora = time(NULL)) == -1 )
      return 0;

   strftime(data, 255, "[%d/%b/%G %T %z]",
               (struct tm *)localtime((time_t *) &fec_hora));

   return (char *) data;
}

/* Imprime IP de conexion remota */
char *PutIP() {
	int ip_length, max_ip_length=15;
	char *ip_address=0;
	
	ip_address = inet_ntoa(remote.sin_addr);
	ip_length = strlen(ip_address);

	if(ip_length > max_ip_length || ip_length<=0) {
		return NULL;	
	}

	return inet_ntoa(remote.sin_addr);
}

char *BaseName(char *name)
{
   char *base;

   base = rindex (name, '/');
   
   return base ? base : name;
}
