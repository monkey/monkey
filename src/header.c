/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

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
#include "clock.h"
#include "cache.h"

int mk_header_iov_add_entry(struct mk_iov *mk_io, mk_pointer data,
                            mk_pointer sep, int free)
{
        return mk_iov_add_entry(mk_io, data.data, data.len, sep, free);
}

struct mk_iov *mk_header_iov_get()
{
        return (struct mk_iov *) pthread_getspecific(mk_cache_iov_header);
}

void mk_header_iov_free(struct mk_iov *iov)
{
        mk_iov_free_marked(iov);
}

/* Send_Header , envia las cabeceras principales */
int mk_header_send(int fd, struct client_request *cr,
		struct request *sr, struct log_info *s_log)
{
	int fd_status=0;
	unsigned long len=0;
	char *buffer=0;
	struct header_values *sh;
	struct mk_iov *iov;

	sh = sr->headers;

	iov = mk_header_iov_get();

	/* Status Code */
	switch(sh->status){
		case M_HTTP_OK:	
			mk_header_iov_add_entry(iov, mk_hr_http_ok,
                                                mk_iov_crlf,
                                                MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_HTTP_PARTIAL:	
			mk_header_iov_add_entry(iov, mk_hr_http_partial,
                                                mk_iov_crlf,
                                                MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_REDIR_MOVED:
			s_log->status=S_LOG_OFF;
			mk_header_iov_add_entry(iov, mk_hr_redir_moved,
                                                mk_iov_crlf,
                                                MK_IOV_NOT_FREE_BUF);
			break;

		case M_REDIR_MOVED_T:
			s_log->status=S_LOG_ON;
			mk_header_iov_add_entry(iov, mk_hr_redir_moved_t,
                                                mk_iov_crlf,
                                                MK_IOV_NOT_FREE_BUF);
			break;
		
		case M_NOT_MODIFIED:
			s_log->status=S_LOG_OFF;
			mk_header_iov_add_entry(iov, mk_hr_not_modified,
                                         mk_iov_crlf,
                                         MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_BAD_REQUEST:
			mk_header_iov_add_entry(iov, mk_hr_client_bad_request, 
                                         mk_iov_crlf,
                                         MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_FORBIDDEN:
			mk_header_iov_add_entry(iov, mk_hr_client_forbidden,
                                         mk_iov_crlf,
                                         MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_NOT_FOUND:
			mk_header_iov_add_entry(iov, mk_hr_client_not_found,
                                                mk_iov_crlf,
                                                MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_METHOD_NOT_ALLOWED:
			mk_header_iov_add_entry(iov, mk_hr_client_method_not_allowed,
                                                mk_iov_crlf,
                                                MK_IOV_NOT_FREE_BUF);
			break;

		case M_CLIENT_REQUEST_TIMEOUT:
			mk_header_iov_add_entry(iov, mk_hr_client_request_timeout,
                                         mk_iov_crlf,
                                         MK_IOV_NOT_FREE_BUF);
			s_log->status=S_LOG_OFF;
			break;

		case M_CLIENT_LENGTH_REQUIRED:
			mk_header_iov_add_entry(iov, mk_hr_client_length_required,
                                                mk_iov_crlf,
                                                MK_IOV_NOT_FREE_BUF);
			break;
			
                case M_SERVER_NOT_IMPLEMENTED:
                        mk_header_iov_add_entry(iov, mk_hr_server_not_implemented,
                                                mk_iov_crlf,
                                                MK_IOV_NOT_FREE_BUF);
                        break;

		case M_SERVER_INTERNAL_ERROR:
			mk_header_iov_add_entry(iov, mk_hr_server_internal_error,
                                                mk_iov_crlf,
                                                MK_IOV_NOT_FREE_BUF);
			break;
			
		case M_SERVER_HTTP_VERSION_UNSUP:
			mk_header_iov_add_entry(iov, 
                                                mk_hr_server_http_version_unsup,
                                                mk_iov_crlf,
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
	mk_iov_add_entry(iov, sr->host_conf->header_host_signature.data,
			sr->host_conf->header_host_signature.len,
			mk_iov_crlf, MK_IOV_NOT_FREE_BUF);

	/* Date */
	mk_iov_add_entry(iov, 
			mk_header_short_date.data,
			mk_header_short_date.len,
			mk_iov_header_value, MK_IOV_NOT_FREE_BUF);
	mk_iov_add_entry(iov,
			header_current_time.data,
			header_current_time.len, 
			mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
	
	/* Location */
	if(sh->location!=NULL)
	{
		mk_iov_add_entry(iov,
				mk_header_short_location.data,
				mk_header_short_location.len, 
                                mk_iov_header_value, MK_IOV_NOT_FREE_BUF);
				
                mk_iov_add_entry(iov,
                                 sh->location,
                                 strlen(sh->location),
                                 mk_iov_crlf, MK_IOV_FREE_BUF);
	}

	/* Last-Modified */
	if(sh->last_modified.len>0)
        {
		mk_iov_add_entry(iov, mk_header_last_modified.data, 
                                 mk_header_last_modified.len,
				mk_iov_header_value, MK_IOV_NOT_FREE_BUF);
                mk_iov_add_entry(iov, sh->last_modified.data, 
                                 sh->last_modified.len,
                                 mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
	}
	
	/* Connection */
	if(cr->counter_connections<config->max_keep_alive_request && 
           config->keep_alive==VAR_ON &&
           cr->request->keep_alive==VAR_ON)
        {
		m_build_buffer(
			&buffer,
			&len,
			"Keep-Alive: timeout=%i, max=%i",
			config->keep_alive_timeout, 
			config->max_keep_alive_request-cr->counter_connections);
		mk_iov_add_entry(iov, buffer, len,
				mk_iov_crlf, MK_IOV_FREE_BUF);


		mk_iov_add_entry(iov,
				mk_header_conn_ka.data,
				mk_header_conn_ka.len,
				mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
		
	}
	else{
		mk_iov_add_entry(iov,
				mk_header_conn_close.data,
				mk_header_conn_close.len,
				mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
	}
        
	/* Content type */
	if(sh->content_type)
	{
		mk_iov_add_entry(iov,
				mk_header_short_ct.data,
				mk_header_short_ct.len,
				mk_iov_header_value, MK_IOV_NOT_FREE_BUF);

		mk_iov_add_entry(iov,
				sh->content_type,
				strlen(sh->content_type),
				mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
	}
	
	/* Transfer Encoding */
	switch(sh->transfer_encoding)
	{
		case MK_HEADER_TE_TYPE_CHUNKED:
			mk_iov_add_entry(iov, 
					mk_header_te_chunked.data, 
					mk_header_te_chunked.len,
					mk_iov_crlf,
					MK_IOV_NOT_FREE_BUF);
			break;
	}

	/* Accept ranges  
	mk_iov_add_entry(iov, 
			mk_header_accept_ranges.data,
			mk_header_accept_ranges.len,
			mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
	*/
	/* Tamaño total de la informacion a enviar */
	if((sh->content_length!=0 && 
			(sh->ranges[0]>=0 || sh->ranges[1]>=0)) && 
			config->resume==VAR_ON)
        {
		long int length;

                /* yyy- */
                if(sh->ranges[0]>=0 && sh->ranges[1]==-1){
                        length = (unsigned int) 
                                ( sh->content_length - sh->ranges[0] );
                        m_build_buffer( 
                                       &buffer,
                                       &len,
                                       "%s %i", 
                                       RH_CONTENT_LENGTH, 
                                       length);
                        mk_iov_add_entry(iov, buffer, len,
                                         mk_iov_crlf, MK_IOV_FREE_BUF);

                        m_build_buffer(
                                       &buffer,
                                       &len,
                                       "%s bytes %d-%d/%d",
                                       RH_CONTENT_RANGE, 
                                       sh->ranges[0],
                                       (sh->content_length - 1), 
                                       sh->content_length);
                        mk_iov_add_entry(iov, buffer, len,
                                         mk_iov_crlf, MK_IOV_FREE_BUF);
                }
		
                /* yyy-xxx */
                if(sh->ranges[0]>=0 && sh->ranges[1]>=0){
                        length = (unsigned int) 
                                abs(sh->ranges[1] - sh->ranges[0]) + 1;
                        m_build_buffer( 
                                       &buffer,
                                       &len,
                                       "%s %d", 
                                       RH_CONTENT_LENGTH, 
                                       length);
                        mk_iov_add_entry(iov, buffer, len,
                                         mk_iov_crlf, MK_IOV_FREE_BUF);

                        m_build_buffer( 
                                       &buffer,
                                       &len,
                                       "%s bytes %d-%d/%d",
                                       RH_CONTENT_RANGE, 
                                       sh->ranges[0], 
                                       sh->ranges[1],
                                       sh->content_length);

                        mk_iov_add_entry(iov, buffer, len,
                                         mk_iov_crlf, MK_IOV_FREE_BUF);
                }

		/* -xxx */
                if(sh->ranges[0]==-1 && sh->ranges[1]>0){
                        length = (unsigned int)sh->ranges[1];

                        if(length > sh->content_length){
                                length        = sh->content_length;
                                sh->ranges[1] = sh->content_length;
                        }

			m_build_buffer(
					&buffer,
					&len,
					"%s %d", 
					RH_CONTENT_LENGTH,
					length);
			mk_iov_add_entry(iov, buffer, len,
					mk_iov_crlf, MK_IOV_FREE_BUF);

			m_build_buffer(
					&buffer,
					&len,
					"%s bytes %d-%d/%d",
					RH_CONTENT_RANGE, 
					(sh->content_length - sh->ranges[1]),
					(sh->content_length - 1),
					sh->content_length);
			mk_iov_add_entry(iov, buffer, len,
					mk_iov_crlf, MK_IOV_FREE_BUF);
		}
	}
	else if(sh->content_length>=0)
	{
		mk_iov_add_entry(iov, mk_rh_content_length.data,
                                 mk_rh_content_length.len, 
                                 mk_iov_space, MK_IOV_NOT_FREE_BUF);
        
                mk_iov_add_entry(iov, sh->content_length_p.data,
                                 sh->content_length_p.len,
                                 mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
	}
        	
	if(sh->cgi==SH_NOCGI || sh->breakline == MK_HEADER_BREAKLINE)
	{
		mk_iov_add_entry(iov, mk_iov_crlf.data, mk_iov_crlf.len,
                           mk_iov_none, MK_IOV_NOT_FREE_BUF);
	}

	mk_socket_set_cork_flag(fd, TCP_CORK_ON);
	mk_iov_send(fd, iov, MK_IOV_SEND_TO_SOCKET);

#ifdef DEBUG_HEADERS_OUT
        mk_iov_send(0, iov, MK_IOV_SEND_TO_SOCKET);
#endif

        mk_header_iov_free(iov);
	
	return 0;
}

char *mk_header_chunked_line(int len)
{
        char *buf;

        buf = mk_mem_malloc_z(10);
        snprintf(buf, 9, "%x%s", len, MK_CRLF);

        return (char *) buf;
}

struct header_values *mk_header_create()
{
	struct header_values *headers;

	headers = (struct header_values *) mk_mem_malloc(sizeof(struct header_values));
	headers->ranges[0]=-1;
	headers->ranges[1]=-1;
	headers->content_length = -1;
	headers->transfer_encoding = -1;
	headers->content_type = NULL;
	mk_pointer_reset(&headers->last_modified);
	headers->location = NULL;

	return headers;
}

