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
#include "str.h"
#include "memory.h"
#include "http.h"
#include "http_status.h"
#include "header.h"
#include "socket.h"
#include "logfile.h"
#include "config.h"
#include "utils.h"

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
	mk_mem_free(tmp);

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
    return mk_string_copy_substr(request, index, i-last_byte);
}


/* Send_Header , envia las cabeceras principales */
int M_METHOD_send_headers(int fd, struct client_request *cr,
		struct request *sr, struct log_info *s_log)
{
	int fd_status=0;
	unsigned long len=0;
	char *buffer=0;
	struct header_values *sh;
	struct mk_iov *iov;
	char *date=0;

	sh = sr->headers;

	iov = mk_iov_create(50);

	/* Status Code */
	switch(sh->status){
		case M_HTTP_OK:	
			mk_iov_add_entry(iov, RESP_HTTP_OK, LEN_RESP_HTTP_OK, 
					BREAK_LINE, MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_HTTP_PARTIAL:	
			mk_iov_add_entry(iov, RESP_HTTP_PARTIAL, 
					LEN_RESP_HTTP_PARTIAL, 
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_REDIR_MOVED:
			s_log->status=S_LOG_OFF;
			mk_iov_add_entry(iov, RESP_REDIR_MOVED, 
					LEN_RESP_REDIR_MOVED, 
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_REDIR_MOVED_T:
			s_log->status=S_LOG_ON;
			mk_iov_add_entry(iov, RESP_REDIR_MOVED_T, 
					LEN_RESP_REDIR_MOVED_T,
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
		
		case M_NOT_MODIFIED:
			s_log->status=S_LOG_OFF;
			mk_iov_add_entry(iov, RESP_NOT_MODIFIED, 
					LEN_RESP_NOT_MODIFIED,
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_BAD_REQUEST:
			mk_iov_add_entry(iov, RESP_CLIENT_BAD_REQUEST, 
					LEN_RESP_CLIENT_BAD_REQUEST,
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_FORBIDDEN:
			mk_iov_add_entry(iov, RESP_CLIENT_FORBIDDEN, 
					LEN_RESP_CLIENT_FORBIDDEN,
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_NOT_FOUND:
			mk_iov_add_entry(iov, RESP_CLIENT_NOT_FOUND, 
					LEN_RESP_CLIENT_NOT_FOUND,
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_METHOD_NOT_ALLOWED:
			mk_iov_add_entry(iov, RESP_CLIENT_METHOD_NOT_ALLOWED, 
					LEN_RESP_CLIENT_METHOD_NOT_ALLOWED,
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_REQUEST_TIMEOUT:
			mk_iov_add_entry(iov, RESP_CLIENT_REQUEST_TIMEOUT, 
					LEN_RESP_CLIENT_REQUEST_TIMEOUT,
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			s_log->status=S_LOG_OFF;
			break;

		case M_CLIENT_LENGHT_REQUIRED:
			mk_iov_add_entry(iov, RESP_CLIENT_LENGTH_REQUIRED,
					LEN_RESP_CLIENT_LENGTH_REQUIRED,
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_SERVER_INTERNAL_ERROR:
			mk_iov_add_entry(iov, RESP_SERVER_INTERNAL_ERROR,
					LEN_RESP_SERVER_INTERNAL_ERROR,
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_SERVER_HTTP_VERSION_UNSUP:
			mk_iov_add_entry(iov, RESP_SERVER_HTTP_VERSION_UNSUP,
					LEN_RESP_SERVER_HTTP_VERSION_UNSUP,
					BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
	};

	if(sh->status!=0){
		s_log->final_response = sh->status;
	}
	
	if(fd_status<0){
		mk_iov_free(iov);
		return -1;		
	}

	/* Informacion del server */
	mk_iov_add_entry(iov, sr->host_conf->header_host_signature,
			strlen(sr->host_conf->header_host_signature),
			BREAK_LINE, MK_IOV_NOT_FREE_BUF);

	/* Fecha */
	date = PutDate_string(0);
	m_build_buffer(&buffer, &len, "Date: %s", date);
	mk_iov_add_entry(iov, buffer, len, 
			BREAK_LINE, MK_IOV_FREE_BUF);
	mk_mem_free(date);

	/* Location */
	if(sh->location!=NULL)
	{
		m_build_buffer(
			&buffer,
			&len,
			"Location: %s",
			sh->location);
		
		mk_iov_add_entry(iov, buffer, len, 
				BREAK_LINE, MK_IOV_FREE_BUF);
	}

	/* Last-Modified */
	if(sh->last_modified!=NULL){
		m_build_buffer(
			&buffer,
			&len,
			"%s %s",
			RH_LAST_MODIFIED,
			sh->last_modified);
		mk_iov_add_entry(iov, buffer, len,
				BREAK_LINE, MK_IOV_FREE_BUF);
	}
	
	/* Connection */

	if(cr->counter_connections<config->max_keep_alive_request && config->keep_alive==VAR_ON){
		m_build_buffer(
			&buffer,
			&len,
			"Keep-Alive: timeout=%i, max=%i",
			config->keep_alive_timeout, 
			config->max_keep_alive_request-cr->counter_connections);
		mk_iov_add_entry(iov, buffer, len,
				BREAK_LINE, MK_IOV_FREE_BUF);

		m_build_buffer(
			&buffer,
			&len,
			"Connection: Keep-Alive");
		mk_iov_add_entry(iov, buffer, len,
				BREAK_LINE, MK_IOV_FREE_BUF);
	}
	else{
		m_build_buffer(
			&buffer,
			&len,
			"Connection: close");
		mk_iov_add_entry(iov, buffer, len,
				BREAK_LINE, MK_IOV_FREE_BUF);
	}

	/* Tipo de contenido de la informacion */
	if(sh->content_type!=NULL){
		m_build_buffer(
			&buffer,
			&len,
			"Content-Type: %s",
			sh->content_type);
		mk_iov_add_entry(iov, buffer, len,
				BREAK_LINE, MK_IOV_FREE_BUF);
	}
	
	/* Ranges */ 
	m_build_buffer(
			&buffer,
			&len,
			"Accept-Ranges: bytes", 
			sh->content_type);
	mk_iov_add_entry(iov, buffer, len,
			BREAK_LINE, MK_IOV_FREE_BUF);

	/* Tamaño total de la informacion a enviar */
	if((sh->content_length!=0 && 
			(sh->ranges[0]>=0 || sh->ranges[1]>=0)) && 
			config->resume==VAR_ON){
		long int length;

        /* yyy- */
	if(sh->ranges[0]>=0 && sh->ranges[1]==-1){
		length = (unsigned int) ( sh->content_length - sh->ranges[0] );
		m_build_buffer( 
				&buffer,
				&len,
				"%s %i", 
				RH_CONTENT_LENGTH, 
				length);
		mk_iov_add_entry(iov, buffer, len,
				BREAK_LINE, MK_IOV_FREE_BUF);

		m_build_buffer(
				&buffer,
				&len,
				"%s bytes %d-%d/%d",
				RH_CONTENT_RANGE, 
				sh->ranges[0],
				(sh->content_length - 1), 
				sh->content_length);
		mk_iov_add_entry(iov, buffer, len,
				BREAK_LINE, MK_IOV_FREE_BUF);
	}
		
	/* yyy-xxx */
	if(sh->ranges[0]>=0 && sh->ranges[1]>=0){
		length = (unsigned int) abs(sh->ranges[1] - sh->ranges[0]) + 1;
		m_build_buffer( 
				&buffer,
				&len,
				"%s %d", 
				RH_CONTENT_LENGTH, 
				length);
		mk_iov_add_entry(iov, buffer, len,
				BREAK_LINE, MK_IOV_FREE_BUF);

		m_build_buffer( 
				&buffer,
				&len,
				"%s bytes %d-%d/%d",
				RH_CONTENT_RANGE, 
				sh->ranges[0], 
				sh->ranges[1],
				sh->content_length);
		}
		mk_iov_add_entry(iov, buffer, len,
				BREAK_LINE, MK_IOV_FREE_BUF);

		/* -xxx */
		if(sh->ranges[0]==-1 && sh->ranges[1]>=0){
			m_build_buffer(
					&buffer,
					&len,
					"%s %d", 
					RH_CONTENT_LENGTH,
					sh->ranges[1]);
			mk_iov_add_entry(iov, buffer, len,
					BREAK_LINE, MK_IOV_FREE_BUF);

			m_build_buffer(
					&buffer,
					&len,
					"%s bytes %d-%d/%d",
					RH_CONTENT_RANGE, 
					(sh->content_length - sh->ranges[1]),
					(sh->content_length - 1),
					sh->content_length);
			mk_iov_add_entry(iov, buffer, len,
					BREAK_LINE, MK_IOV_FREE_BUF);
		}
	}
	else if(sh->content_length!=0)
	{
		m_build_buffer( 
				&buffer,
				&len,
				"%s %d",
				RH_CONTENT_LENGTH,
				sh->content_length);
		mk_iov_add_entry(iov, buffer, len, 
				BREAK_LINE, MK_IOV_FREE_BUF);
	}
	else if(sh->status==M_REDIR_MOVED)
	{
		m_build_buffer( 
				&buffer,
				&len,
				"%s %d", 
				RH_CONTENT_LENGTH, 
				sh->content_length);
		mk_iov_add_entry(iov, buffer, len,
				BREAK_LINE, MK_IOV_FREE_BUF);
	}	
	
	if(sh->cgi==SH_NOCGI)
	{
		mk_iov_add_separator(iov, BREAK_LINE);
	}
	mk_socket_set_cork_flag(fd, TCP_CORK_ON);
	mk_iov_send(fd, iov);
	mk_iov_free(iov);
	return 0;
}

