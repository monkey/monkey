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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "monkey.h"

#include "file.h"
#include "http.h"
#include "http_status.h"

/* Get & Head Method */
int M_METHOD_Get_and_Head(struct client_request *cr, struct request *sr, 
                                                             int socket)
{
	int debug_error=0, status=0;
	char *location=0, *real_location=0; /* ruta para redireccion */
	char **mime_info;
	char *gmt_file_unix_time; // gmt time of server file (unix time)
	struct file_info *path_info;

	/* Peticion normal, no es a un Virtualhost */
	if((strcmp(sr->uri_processed,"/"))==0)
		sr->real_path = m_build_buffer("%s", sr->host_conf->documentroot);

	if(sr->user_home==VAR_OFF){
		sr->real_path = m_build_buffer("%s%s", sr->host_conf->documentroot, sr->uri_processed);
	}
	
	if(sr->method!=HTTP_METHOD_HEAD){
		debug_error=1;
	}

	path_info = mk_file_get_info(sr->real_path);
	if(!path_info){
		Request_Error(M_CLIENT_NOT_FOUND, cr, sr, debug_error, sr->log);
		return -1;
	}

	if(path_info->is_link == MK_FILE_TRUE){
		if(config->symlink==VAR_OFF){
			sr->log->final_response=M_CLIENT_FORBIDDEN;
			Request_Error(M_CLIENT_FORBIDDEN, cr, sr, debug_error, sr->log);
			return -1;
		}		
		else{
			char linked_file[MAX_PATH];
			readlink(sr->real_path, linked_file, MAX_PATH);
			/*
			if(Deny_Check(linked_file)==-1) {
				sr->log->final_response=M_CLIENT_FORBIDDEN;
				Request_Error(M_CLIENT_FORBIDDEN, cr, sr, debug_error, sr->log);
				return -1;
			}
			*/
		}			
	}
	/* Checkeando si la ruta es un Directorio */
	if(path_info->is_directory == MK_FILE_TRUE) {
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

			M_METHOD_send_headers(socket, sr, sr->log);

			M_free(location);
			M_free(real_location);
			sr->headers->location=NULL;
			return 0;
		}
	
		/* looking for a index file */
		index_file = (char *) FindIndex(sr->real_path);

		if(!index_file) {
			/* No index file found, show the content directory */
			if(sr->host_conf->getdir==VAR_ON) {
				int getdir_res = 0;

				getdir_res = GetDir(cr, sr);
					
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
			M_free(path_info);
			sr->real_path = m_build_buffer_from_buffer(sr->real_path, "%s", index_file);
			path_info = mk_file_get_info(sr->real_path);
		}
	}

	/* read permission */ 
	if(path_info->read_access == MK_FILE_FALSE){
		Request_Error(M_CLIENT_FORBIDDEN, cr, sr, 1, sr->log);
		return -1;	
	}
		
	/* Matching MimeType  */
	mime_info=Mimetype_Find(sr->real_path);
	
	if(mime_info[1]){
		struct file_info *fcgi, *ftarget;
		fcgi = mk_file_get_info(mime_info[1]);
		
		/* executable script (e.g PHP) ? */
		if(fcgi){
			int cgi_status=0;
			char *arg_script[3];
			
			/* is it  normal file ? */
			if(fcgi->is_directory==MK_FILE_TRUE || fcgi->exec_access==MK_FILE_FALSE){
				Request_Error(M_SERVER_INTERNAL_ERROR, cr, sr, 1, sr->log);
				Mimetype_free(mime_info);
				return -1;
			}
			/*
			 * FIXME: CHECK FOR TARGET PERMISSION AS GCI DOES
			 *			
			 ftarget = mk_file_get_info(sr->script_filename);
			if(!ftarget)
			{
			
			}
			*/
			sr->log->final_response=M_HTTP_OK;
			sr->script_filename=M_strdup(sr->real_path);

			arg_script[0] = mime_info[1];
			arg_script[1] = sr->script_filename;
			arg_script[2] = NULL;

			if(sr->method==HTTP_METHOD_GET || sr->method==HTTP_METHOD_POST)
			{
				cgi_status=M_CGI_run(cr, sr, mime_info[1], arg_script);
			}
			
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
			M_free(fcgi);
			return cgi_status;
		}
	}
	/* get file size */
	if(path_info->size < 0) {
		Request_Error(M_CLIENT_NOT_FOUND, cr, sr, 1, sr->log);
		Mimetype_free(mime_info);
		return -1;
	}
	sr->bytes_to_send = path_info->size;
	sr->bytes_offset = (off_t) 0;

	/* was if_modified_since sent by the  client ? */
	sr->headers->pconnections_left = (int) config->max_keep_alive_request - cr->counter_connections;
	if(sr->if_modified_since && sr->method==HTTP_METHOD_GET){
		time_t date_client; // Date send by client
		time_t date_file_server; // Date server file
		
		date_client = PutDate_unix(sr->if_modified_since);

		gmt_file_unix_time = PutDate_string((time_t) path_info->last_modification);
		date_file_server = PutDate_unix(gmt_file_unix_time);
		M_free(gmt_file_unix_time);

		if( (date_file_server <= date_client) && (date_client > 0) ){
			sr->headers->status = M_NOT_MODIFIED;
			M_METHOD_send_headers(socket, sr, sr->log);	
			Mimetype_free(mime_info);
			M_free(path_info);
			return 0;
		}
	}
	sr->headers->status = M_HTTP_OK;
	sr->headers->content_length = path_info->size;
	sr->headers->cgi = SH_NOCGI;
	sr->headers->last_modified = PutDate_string( path_info->last_modification);
	sr->headers->location = NULL;

	sr->log->size = path_info->size;
	if(sr->method==HTTP_METHOD_GET || sr->method==HTTP_METHOD_POST){
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

	M_METHOD_send_headers(socket, sr, sr->log);

	if(sr->headers->content_length==0){
		Mimetype_free(mime_info);
		return -1;
	}

	/* Sending file */
	if((sr->method==HTTP_METHOD_GET || sr->method==HTTP_METHOD_POST) 
			&& path_info->size>0)
	{
		status = SendFile(socket, sr, sr->range, sr->real_path, 
                                sr->headers->range_values);
	}

	Mimetype_free(mime_info);
	M_free(path_info);
	sr->headers->content_type=NULL;

	return status;
}

/* POST METHOD */
int M_METHOD_Post(struct client_request *cr, struct request *s_request)
{
	char *tmp;
	char buffer[MAX_REQUEST_BODY];
	int content_length_post=0;
	
	if(!(tmp=Request_Find_Variable(s_request->body, RH_CONTENT_LENGTH))){
		Request_Error(M_CLIENT_LENGHT_REQUIRED, cr, s_request,0,s_request->log);
		return -1;
	}

	content_length_post = (int) atoi(tmp);
	M_free(tmp);

	if(content_length_post<=0 || content_length_post >=MAX_REQUEST_BODY){
		Request_Error(M_CLIENT_BAD_REQUEST, cr, s_request, 0, s_request->log);	
		return -1;
	}
	
	if(!(tmp = Request_Find_Variable(s_request->body, RH_CONTENT_TYPE))){
		Request_Error(M_CLIENT_BAD_REQUEST, cr, s_request, 0, s_request->log);
		return -1;
	}
	
	s_request->content_type = tmp;

	if(s_request->post_variables==NULL || strlen(s_request->post_variables)<=4) {
		s_request->post_variables=NULL;
		return -1;
	}

	if(strlen(s_request->post_variables) < content_length_post){
		content_length_post=strlen(buffer);
	}

	s_request->content_length=content_length_post;
	return 0;
}

/* Reuturn the POST variables sent in the request */
char *M_Get_POST_Vars(char *request, int index, char *strend)
{
    int i=index;
    int length, length_string_end;
    int last_byte = 1;

    length = strlen(request);
    length_string_end = strlen(strend);
    if(length_string_end == 2)
    {
        last_byte = 0;
    }

    for(i=index; i<=length; i++)
    {
        if(strncmp(request+i, strend, length_string_end)==0)
        {
            break;
        }
    }
    return m_copy_string(request, index, i-last_byte);
}


/* Send_Header , envia las cabeceras principales */
int M_METHOD_send_headers(int fd, struct request *sr, struct log_info *s_log)
{
	int fd_status=0;
	char *buffer=0;
	struct header_values *sh;
	struct mk_iov *iov;
	char *date=0;

	sh = sr->headers;

	iov = mk_header_iov_create(50);

	/* Status Code */
	switch(sh->status){
		case M_HTTP_OK:	
			mk_header_iov_add_line(iov, RESP_HTTP_OK, LEN_RESP_HTTP_OK, 
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_HTTP_PARTIAL:	
			mk_header_iov_add_line(iov, RESP_HTTP_PARTIAL, 
					LEN_RESP_HTTP_PARTIAL, 
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_REDIR_MOVED:
			s_log->status=S_LOG_OFF;
			mk_header_iov_add_line(iov, RESP_REDIR_MOVED, 
					LEN_RESP_REDIR_MOVED, 
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_REDIR_MOVED_T:
			s_log->status=S_LOG_ON;
			mk_header_iov_add_line(iov, RESP_REDIR_MOVED_T, 
					LEN_RESP_REDIR_MOVED_T,
					MK_IOV_NOT_FREE_BUF);
			break;
		
		case M_NOT_MODIFIED:
			s_log->status=S_LOG_OFF;
			mk_header_iov_add_line(iov, RESP_NOT_MODIFIED, 
					LEN_RESP_NOT_MODIFIED,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_BAD_REQUEST:
			mk_header_iov_add_line(iov, RESP_CLIENT_BAD_REQUEST, 
					LEN_RESP_CLIENT_BAD_REQUEST,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_FORBIDDEN:
			mk_header_iov_add_line(iov, RESP_CLIENT_FORBIDDEN, 
					LEN_RESP_CLIENT_FORBIDDEN,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_NOT_FOUND:
			mk_header_iov_add_line(iov, RESP_CLIENT_NOT_FOUND, 
					LEN_RESP_CLIENT_NOT_FOUND,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_METHOD_NOT_ALLOWED:
			mk_header_iov_add_line(iov, RESP_CLIENT_METHOD_NOT_ALLOWED, 
					LEN_RESP_CLIENT_METHOD_NOT_ALLOWED,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_REQUEST_TIMEOUT:
			mk_header_iov_add_line(iov, RESP_CLIENT_REQUEST_TIMEOUT, 
					LEN_RESP_CLIENT_REQUEST_TIMEOUT,
					MK_IOV_NOT_FREE_BUF);
			s_log->status=S_LOG_OFF;
			break;

		case M_CLIENT_LENGHT_REQUIRED:
			mk_header_iov_add_line(iov, RESP_CLIENT_LENGTH_REQUIRED,
					LEN_RESP_CLIENT_LENGTH_REQUIRED,
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_SERVER_INTERNAL_ERROR:
			mk_header_iov_add_line(iov, RESP_SERVER_INTERNAL_ERROR,
					LEN_RESP_SERVER_INTERNAL_ERROR,
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_SERVER_HTTP_VERSION_UNSUP:
			mk_header_iov_add_line(iov, RESP_SERVER_HTTP_VERSION_UNSUP,
					LEN_RESP_SERVER_HTTP_VERSION_UNSUP,
					MK_IOV_NOT_FREE_BUF);
			break;
	};

	if(sh->status!=0){
		s_log->final_response = sh->status;
	}
	
	if(fd_status<0){
		mk_header_iov_free(iov);
		return -1;		
	}

	/* Informacion del server */
	mk_header_iov_add_line(iov, sr->host_conf->header_host_signature,
			strlen(sr->host_conf->header_host_signature),
			MK_IOV_NOT_FREE_BUF);

	/* Fecha */
	date = PutDate_string(0);
	buffer = m_build_buffer("Date: %s", date);
	mk_header_iov_add_line(iov, buffer, strlen(buffer), MK_IOV_FREE_BUF);
	M_free(date);

	/* Location */
	if(sh->location!=NULL)
	{
		buffer = m_build_buffer( 
			"Location: %s",
			sh->location);
		
		mk_header_iov_add_line(iov, buffer, strlen(buffer), 
				MK_IOV_FREE_BUF);
	}

	/* Last-Modified */
	if(sh->last_modified!=NULL){
		buffer = m_build_buffer(
			"%s %s",
			RH_LAST_MODIFIED,
			sh->last_modified);
		mk_header_iov_add_line(iov, buffer, strlen(buffer),
				MK_IOV_FREE_BUF);
	}
	
	/* Connection */
	if(sh->pconnections_left!=0 && config->keep_alive==VAR_ON){
		buffer = m_build_buffer(
			"Keep-Alive: timeout=%i, max=%i",
			config->keep_alive_timeout, 
			sh->pconnections_left);
		mk_header_iov_add_line(iov, buffer, strlen(buffer),
				MK_IOV_FREE_BUF);

		buffer = m_build_buffer("Connection: Keep-Alive");
		mk_header_iov_add_line(iov, buffer, strlen(buffer),
				MK_IOV_FREE_BUF);
	}
	else{
		buffer = m_build_buffer("Connection: close");
		mk_header_iov_add_line(iov, buffer, strlen(buffer),
				MK_IOV_FREE_BUF);
	}

	/* Tipo de contenido de la informacion */
	if(sh->content_type!=NULL){
		buffer = m_build_buffer( 
			"Content-Type: %s",
			sh->content_type);
		mk_header_iov_add_line(iov, buffer, strlen(buffer),
				MK_IOV_FREE_BUF);
	}
	
	/* Ranges */ 
	buffer = m_build_buffer( 
			"Accept-Ranges: bytes", 
			sh->content_type);
	mk_header_iov_add_line(iov, buffer, strlen(buffer),
			MK_IOV_FREE_BUF);

	/* Tamaño total de la informacion a enviar */
	if((sh->content_length!=0 && 
			(sh->range_values[0]>=0 || sh->range_values[1]>=0)) && 
			config->resume==VAR_ON){
		long int length;

        /* yyy- */
	if(sh->range_values[0]>=0 && sh->range_values[1]==-1){
		length = (unsigned int) ( sh->content_length - sh->range_values[0] );
		buffer = m_build_buffer( 
				"%s %i", 
				RH_CONTENT_LENGTH, 
				length);
		mk_header_iov_add_line(iov, buffer, strlen(buffer), MK_IOV_FREE_BUF);

		buffer = m_build_buffer(
				"%s bytes %d-%d/%d",
				RH_CONTENT_RANGE, 
				sh->range_values[0],
				(sh->content_length - 1), 
				sh->content_length);
		mk_header_iov_add_line(iov, buffer, strlen(buffer), MK_IOV_FREE_BUF);
	}
		
	/* yyy-xxx */
	if(sh->range_values[0]>=0 && sh->range_values[1]>=0){
		length = (unsigned int) abs(sh->range_values[1] - sh->range_values[0]) + 1;
		buffer = m_build_buffer( 
				"%s %d", 
				RH_CONTENT_LENGTH, 
				length);
		mk_header_iov_add_line(iov, buffer, strlen(buffer), MK_IOV_FREE_BUF);

		buffer = m_build_buffer( 
				"%s bytes %d-%d/%d",
				RH_CONTENT_RANGE, 
				sh->range_values[0], 
				sh->range_values[1],
				sh->content_length);
		}
		mk_header_iov_add_line(iov, buffer, strlen(buffer), MK_IOV_FREE_BUF);

		/* -xxx */
		if(sh->range_values[0]==-1 && sh->range_values[1]>=0){
			buffer = m_build_buffer(
					"%s %d", 
					RH_CONTENT_LENGTH,
					sh->range_values[1]);
			mk_header_iov_add_line(iov, buffer, strlen(buffer),
					MK_IOV_FREE_BUF);

			buffer = m_build_buffer(
					"%s bytes %d-%d/%d",
					RH_CONTENT_RANGE, 
					(sh->content_length - sh->range_values[1]),
					(sh->content_length - 1),
					sh->content_length);
			mk_header_iov_add_line(iov, buffer, strlen(buffer),
					MK_IOV_FREE_BUF);
		}
	}
	else if(sh->content_length!=0)
	{
		buffer = m_build_buffer( 
				"%s %d",
				RH_CONTENT_LENGTH,
				sh->content_length);
		mk_header_iov_add_line(iov, buffer, strlen(buffer), 
				MK_IOV_FREE_BUF);
	}
	else if(sh->status==M_REDIR_MOVED)
	{
		buffer = m_build_buffer( 
				"%s %d", 
				RH_CONTENT_LENGTH, 
				sh->content_length);
		mk_header_iov_add_line(iov, buffer, strlen(buffer),
				MK_IOV_FREE_BUF);
	}	
	
	if(sh->cgi==SH_NOCGI)
	{
		mk_header_iov_add_break_line(iov);
	}
	mk_socket_set_cork_flag(fd, TCP_CORK_ON);
	mk_header_iov_send(fd, iov);
	mk_header_iov_free(iov);
	return 0;
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
