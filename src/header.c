/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2008, Eduardo Silva P.
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
#include <stdlib.h>
#include <string.h>

#include "monkey.h"
#include "header.h"
#include "memory.h"
#include "request.h"
#include "logfile.h"
#include "iov.h"
#include "http_status.h"
#include "config.h"
#include "socket.h"
#include "utils.h"

/* Send_Header , envia las cabeceras principales */
int mk_header_send(int fd, struct client_request *cr,
		struct request *sr, struct log_info *s_log)
{
	int fd_status=0;
	unsigned long len=0;
	char *buffer=0;
	struct header_values *sh;
	struct mk_iov *iov;
	mk_pointer date;

	sh = sr->headers;

	iov = mk_iov_create(45);

	/* Status Code */
	switch(sh->status){
		case M_HTTP_OK:	
			mk_iov_add_entry(iov, RESP_HTTP_OK, 
					LEN_RESP_HTTP_OK, 
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_HTTP_PARTIAL:	
			mk_iov_add_entry(iov, RESP_HTTP_PARTIAL, 
					LEN_RESP_HTTP_PARTIAL, 
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_REDIR_MOVED:
			s_log->status=S_LOG_OFF;
			mk_iov_add_entry(iov, RESP_REDIR_MOVED, 
					LEN_RESP_REDIR_MOVED, 
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_REDIR_MOVED_T:
			s_log->status=S_LOG_ON;
			mk_iov_add_entry(iov, RESP_REDIR_MOVED_T, 
					LEN_RESP_REDIR_MOVED_T,
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
		
		case M_NOT_MODIFIED:
			s_log->status=S_LOG_OFF;
			mk_iov_add_entry(iov, RESP_NOT_MODIFIED, 
					LEN_RESP_NOT_MODIFIED,
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_BAD_REQUEST:
			mk_iov_add_entry(iov, RESP_CLIENT_BAD_REQUEST, 
					LEN_RESP_CLIENT_BAD_REQUEST,
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_FORBIDDEN:
			mk_iov_add_entry(iov, RESP_CLIENT_FORBIDDEN, 
					LEN_RESP_CLIENT_FORBIDDEN,
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_NOT_FOUND:
			mk_iov_add_entry(iov, RESP_CLIENT_NOT_FOUND, 
					LEN_RESP_CLIENT_NOT_FOUND,
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_METHOD_NOT_ALLOWED:
			mk_iov_add_entry(iov, RESP_CLIENT_METHOD_NOT_ALLOWED, 
					LEN_RESP_CLIENT_METHOD_NOT_ALLOWED,
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_REQUEST_TIMEOUT:
			mk_iov_add_entry(iov, RESP_CLIENT_REQUEST_TIMEOUT, 
					LEN_RESP_CLIENT_REQUEST_TIMEOUT,
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			s_log->status=S_LOG_OFF;
			break;

		case M_CLIENT_LENGHT_REQUIRED:
			mk_iov_add_entry(iov, RESP_CLIENT_LENGTH_REQUIRED,
					LEN_RESP_CLIENT_LENGTH_REQUIRED,
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_SERVER_INTERNAL_ERROR:
			mk_iov_add_entry(iov, RESP_SERVER_INTERNAL_ERROR,
					LEN_RESP_SERVER_INTERNAL_ERROR,
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_SERVER_HTTP_VERSION_UNSUP:
			mk_iov_add_entry(iov, RESP_SERVER_HTTP_VERSION_UNSUP,
					LEN_RESP_SERVER_HTTP_VERSION_UNSUP,
					MK_IOV_BREAK_LINE,
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
			MK_IOV_BREAK_LINE, MK_IOV_NOT_FREE_BUF);

	/* Date */
	date = PutDate_string(0);
	mk_iov_add_entry(iov, 
			mk_header_short_date.data,
			mk_header_short_date.len,
			MK_IOV_HEADER_VALUE, MK_IOV_NOT_FREE_BUF);
	mk_iov_add_entry(iov,
			date.data,
			date.len, 
			MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);
	
	/* Location */
	if(sh->location!=NULL)
	{
		mk_iov_add_entry(iov,
				mk_header_short_location.data,
				mk_header_short_location.len, 
                                MK_IOV_HEADER_VALUE, MK_IOV_NOT_FREE_BUF);
				
                mk_iov_add_entry(iov,
                                 sh->location,
                                 strlen(sh->location),
                                 MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);
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
				MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);
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
				MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);


		mk_iov_add_entry(iov,
				mk_header_conn_ka.data,
				mk_header_conn_ka.len,
				MK_IOV_BREAK_LINE, MK_IOV_NOT_FREE_BUF);
		
	}
	else{
		mk_iov_add_entry(iov,
				mk_header_conn_close.data,
				mk_header_conn_close.len,
				MK_IOV_BREAK_LINE, MK_IOV_NOT_FREE_BUF);
	}

	/* Content type */
	if(sh->content_type)
	{
		mk_iov_add_entry(iov,
				mk_header_short_ct.data,
				mk_header_short_ct.len,
				MK_IOV_HEADER_VALUE, MK_IOV_NOT_FREE_BUF);

		mk_iov_add_entry(iov,
				sh->content_type,
				strlen(sh->content_type),
				MK_IOV_BREAK_LINE, MK_IOV_NOT_FREE_BUF);
	}
	
	/* Transfer Encoding */
	switch(sh->transfer_encoding)
	{
		case MK_HEADER_TE_TYPE_CHUNKED:
			mk_iov_add_entry(iov, 
					mk_header_te_chunked.data, 
					mk_header_te_chunked.len,
					MK_IOV_BREAK_LINE,
					MK_IOV_NOT_FREE_BUF);
			break;
	}

	/* Accept ranges  
	mk_iov_add_entry(iov, 
			mk_header_accept_ranges.data,
			mk_header_accept_ranges.len,
			MK_IOV_BREAK_LINE, MK_IOV_NOT_FREE_BUF);
	*/
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
				MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);

		m_build_buffer(
				&buffer,
				&len,
				"%s bytes %d-%d/%d",
				RH_CONTENT_RANGE, 
				sh->ranges[0],
				(sh->content_length - 1), 
				sh->content_length);
		mk_iov_add_entry(iov, buffer, len,
				MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);
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
				MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);

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
				MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);

		/* -xxx */
		if(sh->ranges[0]==-1 && sh->ranges[1]>=0){
			m_build_buffer(
					&buffer,
					&len,
					"%s %d", 
					RH_CONTENT_LENGTH,
					sh->ranges[1]);
			mk_iov_add_entry(iov, buffer, len,
					MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);

			m_build_buffer(
					&buffer,
					&len,
					"%s bytes %d-%d/%d",
					RH_CONTENT_RANGE, 
					(sh->content_length - sh->ranges[1]),
					(sh->content_length - 1),
					sh->content_length);
			mk_iov_add_entry(iov, buffer, len,
					MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);
		}
	}
	else if(sh->content_length>=0)
	{
		m_build_buffer( 
				&buffer,
				&len,
				"%s %d",
				RH_CONTENT_LENGTH,
				sh->content_length);
		mk_iov_add_entry(iov, buffer, len, 
				MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);
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
				MK_IOV_BREAK_LINE, MK_IOV_FREE_BUF);
	}	
	
	if(sh->cgi==SH_NOCGI || sh->breakline == MK_HEADER_BREAKLINE)
	{
		mk_iov_add_separator(iov, MK_IOV_BREAK_LINE);
	}
	mk_socket_set_cork_flag(fd, TCP_CORK_ON);
	mk_iov_send(fd, iov);
	mk_iov_free(iov);
	
	return 0;
}

//int mk_header_send_chunked(int len)

struct header_values *mk_header_create()
{
	struct header_values *headers;

	headers = (struct header_values *) mk_mem_malloc(sizeof(struct header_values));
	headers->ranges[0]=-1;
	headers->ranges[1]=-1;
	headers->content_length = -1;
	headers->transfer_encoding = -1;
	headers->content_type = NULL;
	headers->last_modified = NULL;
	headers->location = NULL;

	return headers;
}

