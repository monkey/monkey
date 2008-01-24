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
 
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "monkey.h"

/* Get & Head Method */
int M_METHOD_Get_and_Head(struct client_request *cr, struct request *sr, 
                                                             int socket)
{
	/* 
        cr = client request
        sr = struct request 
    */

	int method_value=0;
	char *location=0, *real_location=0; /* ruta para redireccion */
	char **mime_info;

	struct stat checkpath, statfile;

	/* Peticion normal, no es a un Virtualhost */
	if((strcmp(sr->uri_processed,"/"))==0)
		sr->real_path = m_build_buffer("%s", sr->temp_path);

	if(sr->user_home==VAR_OFF){
		sr->real_path = m_build_buffer("%s%s", sr->temp_path, sr->uri_processed);
	}
	
	if(sr->method!=HEAD_METHOD)
		method_value=1;

	if(stat(sr->real_path, &checkpath)==-1){
		Request_Error(M_CLIENT_NOT_FOUND, cr, sr, method_value, sr->log);
		return -1;
	}

	// it's an symbolic link
	if(Check_symlink(sr->real_path)==0){
		if(config->symlink==VAR_OFF){
			sr->log->final_response=M_CLIENT_FORBIDDEN;
			Request_Error(M_CLIENT_FORBIDDEN, cr, sr, method_value, sr->log);
			return -1;
		}		
		else{
			char linked_file[MAX_PATH];
			readlink(sr->real_path, linked_file, MAX_PATH);
			if(Deny_Check(linked_file)==-1) {
				sr->log->final_response=M_CLIENT_FORBIDDEN;
				Request_Error(M_CLIENT_FORBIDDEN, cr, sr, method_value, sr->log);
				return -1;
			}
		}			
	}
	/* Checkeando si la ruta es un Directorio */
	if(checkpath.st_mode & S_IFDIR) {
		/* This pointer never must be freed */
		char *index_file = 0; 

		/* 
		  We have to check if exist an slash to the end of
		  this string, if doesn't exist we send a redirection header
		*/
		if(sr->uri_processed[strlen(sr->uri_processed) - 1] != '/') {
			location=m_build_buffer("%s/", sr->uri_processed);
			if(config->serverport == config->standard_port)
				real_location=m_build_buffer("http://%s%s", sr->host, location);
			else
				real_location=m_build_buffer("http://%s:%i%s", sr->host, config->serverport, location);

			sr->headers->status = M_REDIR_MOVED;
			sr->headers->content_length = 0;
			sr->headers->content_type = NULL;
			sr->headers->location = real_location;
			sr->headers->cgi = SH_NOCGI;
			sr->headers->pconnections_left = config->max_keep_alive_request - cr->counter_connections;

			M_METHOD_send_headers(socket, sr->headers, sr->log);

			M_free(location);
			M_free(real_location);
			sr->headers->location=NULL;
			return 0;
		}
	
		/* looking for a index file */
		index_file = (char *) FindIndex(sr->real_path);
		if(!index_file) {
			/* No index file found, show the content directory */
			if(sr->getdir==VAR_ON) {
				int getdir_res = 0;

				getdir_res = GetDir(cr, sr, config->header_file, config->footer_file);
					
				if(getdir_res == -1){
					Request_Error(M_CLIENT_FORBIDDEN, cr, sr, 1, sr->log);
					return -1;
				}
				return 0;
			}
			else {
				Request_Error(M_CLIENT_FORBIDDEN, cr, sr, 1, sr->log);
				return -1;
			}
		}
		else{
			sr->real_path = m_build_buffer_from_buffer(sr->real_path, "%s", index_file);
		}
	}

	/* do exists the file ? */
	if(access(sr->real_path,F_OK)!=0){
		Request_Error(M_CLIENT_NOT_FOUND, cr, sr, 1, sr->log);
		return -1;	
	}

	/* read permission */
	if(AccessFile(sr->real_path)!=0){
		Request_Error(M_CLIENT_FORBIDDEN, cr, sr, 1, sr->log);
		return -1;	
	}
		
	/* Matching MimeType  */
	mime_info=Mimetype_Find(sr->real_path);
	
	if(mime_info[1]){
		/* executable script (e.g PHP) ? */
		if(access(mime_info[1],X_OK)==0){
				int cgi_status=0;
				char *arg_script[3];
			
				/* is it  normal file ? */
				if(CheckFile(mime_info[1])!=0){
					Request_Error(M_SERVER_INTERNAL_ERROR, cr, sr, 1, sr->log);
					Mimetype_free(mime_info);
					return -1;
				}

				sr->log->final_response=M_HTTP_OK;
				sr->script_filename=M_strdup(sr->real_path);

				arg_script[0] = mime_info[1];
				arg_script[1] = sr->script_filename;
				arg_script[2] = NULL;

				if(sr->method==GET_METHOD || sr->method==POST_METHOD)
						cgi_status=M_CGI_run(cr, sr, mime_info[1], arg_script);
			
				switch(cgi_status){
					case -2:	/* Timeout */
							sr->log->final_response=M_CLIENT_REQUEST_TIMEOUT;
							break;
					case -3:  /* Internal server Error */
							sr->log->final_response=M_SERVER_INTERNAL_ERROR;
							break;
						
					case -1:
							sr->make_log=VAR_OFF;
							break;
					case 0:  /* Ok */
							sr->log->final_response=M_HTTP_OK;
							break;
				};	

				if(cgi_status==M_CGI_TIMEOUT || cgi_status==M_CGI_INTERNAL_SERVER_ERR){
					Request_Error(sr->log->final_response, cr, sr, 1, sr->log);	
				}

				Mimetype_free(mime_info);
				return cgi_status;
			}
	}
	/* get file size */
	if(stat(sr->real_path,&statfile) < 0) {
		Request_Error(M_CLIENT_NOT_FOUND, cr, sr, 1, sr->log);
		Mimetype_free(mime_info);
		return -1;
	}
	
	/* was if_modified_since sent by the  client ? */
	sr->headers->pconnections_left = (int) config->max_keep_alive_request - cr->counter_connections;
	if(sr->if_modified_since && sr->method==GET_METHOD){
		time_t date_client; // Date send by client
		time_t date_file_server; // Date server file
		char *gmt_file_unix_time; // gmt time of server file (unix time)
		
		date_client = PutDate_unix(sr->if_modified_since);

		gmt_file_unix_time = PutDate_string((time_t) statfile.st_mtime);
		date_file_server = PutDate_unix(gmt_file_unix_time);
		
		if( (date_file_server <= date_client) && (date_client > 0) ){
			sr->headers->status = M_NOT_MODIFIED;
			M_METHOD_send_headers(socket, sr->headers, sr->log);	
			Mimetype_free(mime_info);
			return 0;
		}
//		M_free(gmt_file_unix_time);
	}
	sr->headers->status = M_HTTP_OK;
	sr->headers->content_length = statfile.st_size;
	sr->headers->cgi = SH_NOCGI;
	sr->headers->last_modified = m_build_buffer("%s", PutDate_string( statfile.st_mtime ));
	sr->headers->location = NULL;

	sr->log->size=(statfile.st_size);
	if(sr->method==GET_METHOD || sr->method==POST_METHOD){
		sr->headers->content_type = mime_info[0];
		/* Range */
		if(sr->range!=NULL && config->resume==VAR_ON){
			M_METHOD_get_range(sr->range, sr->headers->range_values);
			if(sr->headers->range_values[0]>=0 || sr->headers->range_values[1]>=0)
				sr->headers->status = M_HTTP_PARTIAL;
		}
	}
	else{ /* without content-type */
		sr->headers->content_type = NULL;
	}
	M_METHOD_send_headers(socket, sr->headers, sr->log);

	if(sr->headers->content_length==0){
		Mimetype_free(mime_info);
		return -1;
	}
	/* Sending file */
	if((sr->method==GET_METHOD || sr->method==POST_METHOD) && statfile.st_size>0)
		SendFile(socket, sr->real_path, sr->headers->range_values);

	Mimetype_free(mime_info);

	sr->headers->content_type=NULL;

	return 0;
}

/* POST METHOD */
int M_METHOD_Post(struct client_request *cr, 
                                struct request *s_request, char *request_body)
{
	char *tmp;
	char *post_buffer;
	char buffer[MAX_REQUEST_BODY];
	int i=0, content_length_post=0;
	
	if(!(tmp=Request_Find_Variable(request_body, RH_CONTENT_LENGTH))){
		Request_Error(M_CLIENT_LENGHT_REQUIRED, cr, s_request,0,s_request->log);
		return -1;
	}
	
	content_length_post = (int) atoi(tmp);
	M_free(tmp);

	if(content_length_post<=0 || content_length_post >=MAX_REQUEST_BODY){
		Request_Error(M_CLIENT_BAD_REQUEST, cr, s_request, 0, s_request->log);	
		return -1;
	}
	
	if(!(tmp = Request_Find_Variable(request_body, RH_CONTENT_TYPE))){
		Request_Error(M_CLIENT_BAD_REQUEST, cr, s_request, 0, s_request->log);
		return -1;
	}
	
	s_request->content_type = tmp;

	post_buffer = (char *) strstr(request_body,"\r\n\r\n");

	if(post_buffer==NULL || strlen(post_buffer)<=4) {
		s_request->post_variables=NULL;
		return -1;
	}

	memset(buffer,'\0',sizeof(buffer));
	for(i=4;i<strlen(post_buffer);i++){
		buffer[i-4]=post_buffer[i];
	}

	if(strlen(buffer) < content_length_post){
		content_length_post=strlen(buffer);
	}
			
	s_request->post_variables = M_malloc(sizeof(buffer) + 1);
	memset(s_request->post_variables, '\0', sizeof(buffer) + 1);
	strncpy(s_request->post_variables, buffer, content_length_post);
	s_request->post_variables[content_length_post ]='\0';
	s_request->content_length=content_length_post;
	return 0;
}

/* Send_Header , envia las cabeceras principales */
int M_METHOD_send_headers(int fd, struct header_values *sh, struct log_info *s_log)
{
	int fd_status=0;
	char *buffer=0;
	
	/* Status Code */
	switch(sh->status){
		case M_HTTP_OK:	
			buffer = m_build_buffer_from_buffer(buffer,"HTTP/1.1 200 OK\r\n");
			break;
			
		case M_HTTP_PARTIAL:	
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 206 Partial Content\r\n");
			break;
			
		case M_REDIR_MOVED:
			s_log->status=S_LOG_OFF;
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 301 Moved Permanently\r\n");
			break;

		case M_REDIR_MOVED_T:
			s_log->status=S_LOG_ON;
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 302 Found\r\n");
			break;
		
		case M_NOT_MODIFIED:
			s_log->status=S_LOG_OFF;
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 304 Not Modified\r\n");
			break;

		case M_CLIENT_BAD_REQUEST:
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 400 Bad Request\r\n");
			break;

		case M_CLIENT_FORBIDDEN:
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 403 Forbidden\r\n");
			break;

		case M_CLIENT_NOT_FOUND:
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 404 Not Found\r\n");
			break;

		case M_CLIENT_METHOD_NOT_ALLOWED:
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 405 Method Not Allowed\r\n");
			break;

		case M_CLIENT_REQUEST_TIMEOUT:
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 408 Request Timeout\r\n");
			s_log->status=S_LOG_OFF;
			break;

		case M_CLIENT_LENGHT_REQUIRED:
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 411 Length Required\r\n");
			break;
			
		case M_SERVER_INTERNAL_ERROR:
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 500 Internal Server Error\r\n");
			break;
			
		case M_SERVER_HTTP_VERSION_UNSUP:
			buffer = m_build_buffer_from_buffer(buffer, "HTTP/1.1 505 HTTP Version Not Supported\r\n");
			break;
		};

	if(sh->status!=0){
		s_log->final_response = sh->status;
	}
	
	if(fd_status<0){
		return -1;		
	}
	
	/* Informacion del server */
	buffer = m_build_buffer_from_buffer(buffer,"Server: %s\r\n", config->server_software);

	/* Fecha */
	buffer = m_build_buffer_from_buffer(buffer,"Date: %s\r\n", PutDate_string(0));

	/* Location */
	if(sh->location!=NULL)
		buffer = m_build_buffer_from_buffer(buffer, "Location: %s\r\n", sh->location);

	/* Last-Modified */
	if(sh->last_modified!=NULL){
		buffer = m_build_buffer_from_buffer(buffer,"%s %s\r\n", RH_LAST_MODIFIED, sh->last_modified);
	}
	
	/* Conexion */
	if(sh->pconnections_left!=0 && config->keep_alive==VAR_ON){
		buffer = m_build_buffer_from_buffer(buffer, "Keep-Alive: timeout=%i, max=%i\r\n", config->keep_alive_timeout, sh->pconnections_left);
		buffer = m_build_buffer_from_buffer(buffer, "Connection: Keep-Alive\r\n");
	}
	else{
		buffer = m_build_buffer_from_buffer(buffer, "Connection: close\r\n");
	}

	/* Tipo de contenido de la informacion */
	if(sh->content_type!=NULL){
		buffer = m_build_buffer_from_buffer(buffer, "Content-Type: %s\r\n", sh->content_type);
	}
	
	/* Ranges */ 
	buffer = m_build_buffer_from_buffer(buffer, "Accept-Ranges: bytes\r\n", sh->content_type);

	/* Tamaño total de la informacion a enviar */
	if((sh->content_length!=0 && (sh->range_values[0]>=0 || sh->range_values[1]>=0)) && config->resume==VAR_ON){
		long int length;

        /* yyy- */
		if(sh->range_values[0]>=0 && sh->range_values[1]==-1){
			length = (unsigned long int) ( sh->content_length - sh->range_values[0] );
			buffer = m_build_buffer_from_buffer(buffer, "%s %i\r\n", RH_CONTENT_LENGTH, length);
			buffer = m_build_buffer_from_buffer(buffer, "%s bytes %d-%d/%d\r\n", RH_CONTENT_RANGE, sh->range_values[0], 
				(sh->content_length - 1), sh->content_length);
		}
		
		/* yyy-xxx */
		if(sh->range_values[0]>=0 && sh->range_values[1]>=0){
			length = (unsigned long int) (sh->range_values[1] - sh->range_values[0] + 1);
			buffer = m_build_buffer_from_buffer(buffer, "%s %d\r\n", RH_CONTENT_LENGTH, length);	
			buffer = m_build_buffer_from_buffer(buffer, "%s bytes %d-%d/%d\r\n", RH_CONTENT_RANGE, sh->range_values[0], 
				sh->range_values[1], sh->content_length);
		}

		/* -xxx */
		if(sh->range_values[0]==-1 && sh->range_values[1]>=0){
			buffer = m_build_buffer_from_buffer(buffer, "%s %d\r\n", RH_CONTENT_LENGTH, sh->range_values[1]);
			buffer = m_build_buffer_from_buffer(buffer, "%s bytes %d-%d/%d\r\n", RH_CONTENT_RANGE, (sh->content_length - sh->range_values[1]),
				 (sh->content_length - 1) , sh->content_length);
		}
	}
	else if(sh->content_length!=0)
			buffer = m_build_buffer_from_buffer(buffer, "%s %d\r\n", RH_CONTENT_LENGTH, sh->content_length);
		else if(sh->status==M_REDIR_MOVED)
			buffer = m_build_buffer_from_buffer(buffer, "%s %d\r\n", RH_CONTENT_LENGTH, sh->content_length);
		
	if(sh->cgi==SH_NOCGI)
		buffer = m_build_buffer_from_buffer(buffer, "\r\n");

    //printf("\n*** SENDING HEADERS ***\n%s", buffer);
    fflush(stdout);

	fdprintf(fd, NO_CHUNKED, "%s", buffer);
	M_free(buffer);
	return 0;
}

int M_METHOD_get_number(char *method)
{
	if(strcmp(method, GET_METHOD_STR)==0)
		return GET_METHOD;

	if(strcmp(method, POST_METHOD_STR)==0)
		return POST_METHOD;

	if(strcmp(method, HEAD_METHOD_STR)==0)
		return HEAD_METHOD;

	return METHOD_NOT_ALLOWED;
}

char *M_METHOD_get_name(int method)
{
	switch(method){
		case GET_METHOD:
				return (char *) GET_METHOD_STR;
				
		case POST_METHOD:
				return (char *) POST_METHOD_STR;
				
		case HEAD_METHOD:
				return (char *) HEAD_METHOD_STR;
	}
	return (char *) "";
}

int M_METHOD_get_range(char *header, int range_from_to[2])
{
	int eq_pos, sep_pos;
	
	range_from_to[0] = -1;
	range_from_to[1] = -1;
	
	if(!header)
		return -1;	
	
	if((eq_pos = str_search(header, "=", 1))<0)
		return -1;	
	
	if(strncasecmp(header, "Bytes", eq_pos)!=0)
		return -1;	
	
	if((sep_pos = str_search(header, "-", 1))<0)
		return -1;
	
	/* =-xxx */
	if(eq_pos+1 == sep_pos){
		range_from_to[0] = -1;
		range_from_to[1] = (unsigned long) atol(header + sep_pos + 1);
		return 0;
	}

	/* =yyy-xxx */
	if( (eq_pos+1 != sep_pos) && (strlen(header) > sep_pos + 1) ){
		char *buffer_start=0, *buffer=0, *last=0;

		buffer_start = buffer = M_strdup(header+eq_pos+1);
		buffer = strtok_r(buffer, "-", &last);
		range_from_to[0] = (unsigned long) atol(m_build_buffer("%d", atol(buffer)));
		buffer = strtok_r(NULL, "\n", &last);
		range_from_to[1] = (unsigned long) atol(m_build_buffer("%d", atol(buffer)));	
		M_free(buffer_start);
		return 0;
	}
	/* =yyy- */
	if( (eq_pos+1 != sep_pos) && (strlen(header) == sep_pos + 1 ) ){
		char *buffer_start=0, *buffer=0, *last=0;

		buffer = M_strdup(header+eq_pos+1);
		buffer = strtok_r(buffer, "-", &last);

		range_from_to[0] = (unsigned long) atol(m_build_buffer("%d", atol(buffer)));
		range_from_to[1] = -1;
		M_free(buffer_start);
		return 0;
	}
	
	return -1;	
}
