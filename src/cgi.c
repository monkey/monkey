/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2007, Eduardo Silva P.
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

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <string.h>

#include "monkey.h"

/* Main function to normal CGI scripts */
int M_CGI_main(struct client_request *cr, struct request *sr, struct log_info *s_log, char remote_request[MAX_REQUEST_BODY])
{
	int cgi_status=0, checkdir;

	sr->script_filename = (char *) M_CGI_alias(sr->uri_processed, sr->host_conf->scriptalias[0], sr->host_conf->scriptalias[1]);
	checkdir=CheckDir(sr->script_filename);

	if(access(sr->script_filename,F_OK)!=0){
		Request_Error(M_CLIENT_NOT_FOUND, cr, sr, 1, s_log);
		return -1;
	}
	else if(AccessFile(sr->script_filename)!=0 ||  checkdir==0){
		Request_Error(M_CLIENT_FORBIDDEN, cr, sr, 1, s_log);
		return -1;
	}

	if(ExecFile(sr->script_filename)!=0){
		Request_Error(M_CLIENT_FORBIDDEN, cr, sr, 1, s_log);
		return -1;
	}

	if(sr->method==POST_METHOD){
		M_METHOD_Post(cr, sr, remote_request);
	}
	
	cgi_status=M_CGI_run(cr, sr,sr->script_filename, NULL);
	
	switch(cgi_status){
			case M_CGI_TIMEOUT:
					s_log->final_response=M_CLIENT_REQUEST_TIMEOUT;
					break;
			case M_CGI_INTERNAL_SERVER_ERR:  /* Internal server Error */
					s_log->final_response=M_SERVER_INTERNAL_ERROR;
					break;
			case M_CGI_OK:  /* Ok */
					s_log->final_response=M_HTTP_OK;
					break;
	};	

	return cgi_status;
}

/* Return the real path of cgi_path */
char *M_CGI_alias(char *path, char *query, char *newstring )
{
	int slash_offset=0;
	char *aux=0, *buffer=0;
	
	if(!path || !query)
		return NULL;


	if(path[strlen(query) - 1]!='/')
		slash_offset++;
	
	aux=m_build_buffer("%s", path+strlen(query)+slash_offset);
	
	if(newstring[strlen(newstring) - 1]!='/')
		buffer=m_build_buffer("%s/%s", newstring, aux);
	else
		buffer=m_build_buffer("%s%s", newstring, aux);

	M_free(aux);
	return (char *) buffer;
}

/* Running CGI script */
int M_CGI_run(struct client_request *cr, struct request *sr, char *script_filename, char **args)
{
	int return_status=0;
	int pipe_fd[2];
	int pipe_write[2];
	pid_t pid;
	pthread_t pid_thread;
		
	if(socketpair(AF_LOCAL, SOCK_STREAM, 0, pipe_fd )<0)
		return M_CGI_INTERNAL_SERVER_ERR;

	if(args!=NULL)
		M_CGI_change_dir(args[1]);

	pid_thread=pthread_self();
	
	pipe(pipe_write);
	
	M_CGI_register_child(pid_thread, pid=fork());
	
	if(pid==(pid_t) 0){
		
		close(pipe_fd[0]);
		
		if(dup2(pipe_fd[1], STDOUT_FILENO)==-1)
			exit(1);	

	    if(dup2(pipe_write[0], STDIN_FILENO)==-1)
			exit(1);
		
        if(!args) {
          args = (char **) alloca(sizeof(char *) * 1);
          args[0] = NULL;
        }

		if(execve(script_filename, args, M_CGI_env_set_basic((struct request *) sr))==-1){
			perror("execve");
			exit(1);  /* Problemas al ejecutar */
		}
		else
			exit(0);
	}
	else{
		close(pipe_write[0]);
		if(sr->method==POST_METHOD){	
			write(pipe_write[1], sr->post_variables, sr->content_length);
		}
		close(pipe_write[1]);
		
		close(pipe_fd[1]);
		return_status=M_CGI_send(cr->socket, pipe_fd[0], sr->log, 
			config->max_keep_alive_request - cr->counter_connections, sr->protocol);
			
		close(pipe_fd[0]);
		while(waitpid(pid,NULL,0)>0);
	}
		
	M_CGI_free_childs(pid_thread, M_CGI_CHILD_EXIT_OK);

	return return_status;
}

/* Read 'cgi_pipe' pipe data and send it to socket */
int M_CGI_send(int socket, int cgi_pipe, struct log_info *s_log, int persistent_connections_left, int remote_protocol)
{
	int bytes, total_bytes=0, spaces, buffer_empty=VAR_ON;
	long offset;
	char buffer[BUFFER_SOCKET +1], data[BUFFER_SOCKET +1];
	struct header_values hd;
			
	memset(data, '\0', sizeof(data));
	do{
		memset(buffer,'\0',sizeof(buffer));
		bytes=recv(cgi_pipe, buffer, BUFFER_SOCKET, 0);
		if(bytes>0)
			buffer_empty=VAR_OFF;
					
		if(bytes<0){
			return -1;
		}
			
		if(total_bytes+bytes <= BUFFER_SOCKET && bytes>0){
			memcpy(data+total_bytes, buffer, bytes);
			total_bytes+=bytes;
			buffer_empty=VAR_ON;
		}	
		else{
			buffer_empty=VAR_OFF;
			break;
		}
	}while(bytes>0);
	
	offset=str_search(data,"\r\n\r\n",4);
	spaces=4;
	if(offset==-1){
		if((offset=str_search(data,"\n\n",2))!=-1)
			spaces=2;
		else
			return -1;		
	}

	/* Some CGI scrits send a redirect header, we must 
	verify if 'Location' header has been sent from 
	script, i was sent we send an '302 Found' header',
	if not we send '200 OK' header */
	if(strstr2(data, "Location:")!=NULL)
		s_log->final_response=M_REDIR_MOVED_T;
	else
		s_log->final_response=M_HTTP_OK;

	hd.status = s_log->final_response;
	hd.content_length = 0;
	hd.content_type = NULL;
	hd.location = NULL;
	hd.cgi = SH_CGI;
	hd.pconnections_left = persistent_connections_left;	
	hd.last_modified = NULL;
	
	if(M_METHOD_send_headers(socket, &hd, s_log)<0){
		return -1;	
	}
	
	/* HTTP/1.1*/
	if(remote_protocol==HTTP_11){
		
		if(fdprintf(socket, NO_CHUNKED, "Transfer-Encoding: chunked\r\n")<0)
			return -1;			

		if(Socket_Timeout(socket, data, offset, config->timeout, ST_SEND)<0)
			return -1;				

		if(fdprintf(socket, NO_CHUNKED, "\r\n\r\n")<0)
			return -1;			

		if(( total_bytes-offset-spaces ) != 0 ){
			if(fdchunked(socket, data+offset+spaces , total_bytes-offset-spaces)<0)
				return -1;							
		}

		if(buffer_empty==VAR_OFF && bytes>0){
			if(fdchunked(socket, buffer, bytes)<0)
				return -1;				
		}
	}
	else{ /* HTTP/1.0 */
		if(Socket_Timeout(socket, data, total_bytes, config->timeout, ST_SEND)<0){
			return -1;			
		}
		if(buffer_empty==VAR_OFF && bytes>0)
			if(Socket_Timeout(socket, buffer, bytes, config->timeout, ST_SEND)<0){
				return -1;
			}
	}

	do{
		memset(buffer, '\0', sizeof(buffer));
		bytes=recv(cgi_pipe, buffer, BUFFER_SOCKET, 0);		
		if(remote_protocol==HTTP_11 && bytes > 0){
			if(fdchunked(socket, buffer, bytes)<0){
				return -1;							
			}
		}
		else{
			if(bytes>0) {
				if(Socket_Timeout(socket, buffer, bytes, config->timeout, ST_SEND)<0)
					return -1;								
			}
		}
	}while(bytes>0);

	if(remote_protocol==HTTP_11){
		if(fdprintf(socket, NO_CHUNKED, "0\r\n\r\n")<0){
			return -1;																
		}
	}
	else {
		if(fdprintf(socket, NO_CHUNKED, "\r\n")<0){	
			return -1;
		}
	}
	return 0;		
}

/* Here we build an array with basic internal 
vars needs for CGI scripts */
char **M_CGI_env_set_basic(struct request *sr)
{
	char **arg=0, **ptr=0, auxint[10];
	
	ptr = arg = (char **) M_malloc(sizeof(char *) * 30);

	*ptr++ = M_CGI_env_add_var("DOCUMENT_ROOT", sr->host_conf->documentroot);
	
	if(sr->method==POST_METHOD && sr->content_length>0){
		snprintf(auxint,10,"%i",sr->content_length);
		*ptr++ = M_CGI_env_add_var("CONTENT_LENGTH",auxint);
		*ptr++ = M_CGI_env_add_var("CONTENT_TYPE",sr->content_type);
	}
	
	*ptr++ = M_CGI_env_add_var("SERVER_ADDR", config->server_addr);
	
	*ptr++ = M_CGI_env_add_var("SERVER_NAME",sr->host);
	*ptr++ = M_CGI_env_add_var("SERVER_PROTOCOL", get_name_protocol(MONKEY_HTTP_PROTOCOL));
	*ptr++ = M_CGI_env_add_var("SERVER_SOFTWARE", config->server_software);
	*ptr++ = M_CGI_env_add_var("SERVER_SIGNATURE", sr->host_conf->host_signature);
	
	if(sr->user_agent)
		*ptr++ = M_CGI_env_add_var("HTTP_USER_AGENT",sr->user_agent);

	if(sr->accept)
		*ptr++ = M_CGI_env_add_var("HTTP_ACCEPT", sr->accept);
	
	if(sr->accept_charset)
		*ptr++ = M_CGI_env_add_var("HTTP_ACCEPT_CHARSET",sr->accept_charset);
		
	if(sr->accept_encoding)
		*ptr++ = M_CGI_env_add_var("HTTP_ACCEPT_ENCODING",sr->accept_encoding);

	if(sr->accept_language)
		*ptr++ = M_CGI_env_add_var("HTTP_ACCEPT_LANGUAGE",sr->accept_language);

	if(sr->host)
		*ptr++ = M_CGI_env_add_var("HTTP_HOST",sr->host);

	if(sr->cookies)
		*ptr++ = M_CGI_env_add_var("HTTP_COOKIE",sr->cookies);
		
	if(sr->referer)
		*ptr++ = M_CGI_env_add_var("HTTP_REFERER",sr->referer);
		
	snprintf(auxint, 10, "%i", config->serverport);
	*ptr++ = M_CGI_env_add_var("SERVER_PORT",auxint);
	
	snprintf(auxint,10,"CGI/%s",CGI_VERSION);
	*ptr++ = M_CGI_env_add_var("GATEWAY_INTERFACE",auxint);
	*ptr++ = M_CGI_env_add_var("REMOTE_ADDR",PutIP());
	*ptr++ = M_CGI_env_add_var("REQUEST_URI", sr->uri);
	*ptr++ = M_CGI_env_add_var("REQUEST_METHOD", M_METHOD_get_name(sr->method));
	*ptr++ = M_CGI_env_add_var("SCRIPT_NAME",sr->uri);
	*ptr++ = M_CGI_env_add_var("SCRIPT_FILENAME",sr->script_filename);

	snprintf(auxint,10,"%i",remote.sin_port);
	*ptr++ = M_CGI_env_add_var("REMOTE_PORT",auxint);
	*ptr++ = M_CGI_env_add_var("QUERY_STRING",  sr->query_string);
	*ptr++ = M_CGI_env_add_var("POST_VARS", sr->post_variables);
	*ptr++ = '\0';
	
	return arg;
}

/* Add new var to **arg */
char *M_CGI_env_add_var(char *name, const char *value)
{
	char *variable=0;

	variable = m_build_buffer("%s=%s", name, value ? value : "");
	return variable;
}

/* Change dir work */
int M_CGI_change_dir(char *script)
{
	int i, status;
	char *aux=0;

	if(CheckDir(script)==0){
		return chdir(script);
	}	
	
	for(i=strlen(script); i>0 ;i--){
		if(script[i]=='/')
			break;	
	}

	aux = M_malloc(i+2);
	strncpy(aux,script,i+1);
	aux[i+1]='\0';

	if(CheckDir(aux)!=0){
		M_free(aux);
		return -1;
	}

	status = chdir(aux);
	M_free(aux);
	
	return status;
}

/* Register an child of thread */
int M_CGI_register_child(pthread_t thread, pid_t pid)
{
	struct cgi_child *proc=0, *find=0;

	if(pid <= 0){
		return -1;
	}
	
	pthread_mutex_lock(&mutex_cgi_child);
	
	proc = M_malloc(sizeof(struct cgi_child));
	proc->thread_pid = (pthread_t) thread;
	proc->pid = (pid_t) pid;
	proc->next = NULL;
	
	if(cgi_child_index==NULL){	
		cgi_child_index=proc;
		pthread_mutex_unlock(&mutex_cgi_child);
		return 0;
	}
	
	find=cgi_child_index;
	while(find->next!=NULL) 
		find=find->next;

	find->next=proc;
	
	pthread_mutex_unlock(&mutex_cgi_child);
	return 0;
}

/* Killing childs from thread */
int M_CGI_free_childs(pthread_t thread, int exit_type)
{
	struct cgi_child *c_aux, *c_aux2;
	
	pthread_mutex_lock(&mutex_cgi_child);
	
	c_aux=cgi_child_index;
	
	/* We need find all child of thread */
	while(c_aux!=NULL){
		if(pthread_equal(c_aux->thread_pid , thread)!=0){
			if( (c_aux->pid > 0) && (exit_type == M_CGI_CHILD_EXIT_FAIL)){
				/* I need to kill my child, i'm a bad Monkey >:) */
				kill(c_aux->pid, SIGKILL);
			}
			if(c_aux==cgi_child_index){
				cgi_child_index=cgi_child_index->next;
				M_free(c_aux);
				c_aux = cgi_child_index;
				continue;
			}
			else{
				c_aux2=cgi_child_index;
				while(c_aux2->next!=c_aux)
					c_aux2=c_aux2->next;
				c_aux2->next=c_aux->next;
				M_free(c_aux);
			}
		}	
		c_aux=c_aux->next;	
	}	
	while(waitpid(-1,NULL, 0) > 0);
	pthread_mutex_unlock(&mutex_cgi_child);
	return 0;
}
