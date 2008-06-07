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
