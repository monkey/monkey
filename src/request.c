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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include <string.h>

#include <arpa/inet.h> 
#include <netinet/in.h>
#include <sys/types.h>

#include "request.h"
#include "monkey.h"
#include "http.h"
#include "http_status.h"
#include "string.h"
#include "cgi.h"
#include "str.h"
#include "config.h"
#include "scheduler.h"
#include "epoll.h"
#include "socket.h"
#include "logfile.h"
#include "utils.h"
#include "header.h"
#include "deny.h"
#include "user.h"
#include "method.h"
#include "memory.h"
#include "socket.h"
#include "cache.h"
#include "clock.h"

struct request *mk_request_parse(struct client_request *cr)
{
	int i, n, init_block=0, n_blocks=0;
	int pipelined=FALSE;
	struct request *cr_buf=0, *cr_search=0;

	init_block = 0;

	for(i=cr->first_block_end; i<=cr->body_length-mk_endblock.len; i++)
	{
                /* Allocating request block */
		cr_buf = mk_request_alloc();
	
		/* mk_pointer */
		cr_buf->body.data = cr->body+init_block;
		cr_buf->body.len = i-init_block;

                if(i==cr->first_block_end){
                        cr_buf->method = cr->first_method;
                }
                else{
                        cr_buf->method = mk_http_method_get(cr_buf->body.data);
                }

                cr_buf->log->ip = cr->ip;
		cr_buf->next = NULL;

		i = init_block = i + mk_endblock.len;
	
		/* Looking for POST data */
		if(cr_buf->method == HTTP_METHOD_POST)
		{
			cr_buf->post_variables =
                                mk_method_post_get_vars(cr->body, i);

			if(cr_buf->post_variables.len >= 0)
			{
				i = init_block = i+cr_buf->post_variables.len;
			}
		}

		if(!cr->request)
		{	
			cr->request = cr_buf;
		}
		else{
			cr_search = cr->request;
			while(cr_search)
			{
				if(cr_search->next==NULL)
				{
					cr_search->next = cr_buf;
                       			break;
				}
				else
				{
					cr_search = cr_search->next;
				}
			}
		}
		n_blocks++;
                n = mk_string_search(cr->body+i, mk_endblock.data);
                if(n<=0)
                {
                        break;
                }
                else{
                        i = i + n;
                }
	}

	/* Checking pipelining connection */
	cr_search = cr->request;
	if(n_blocks>1)
	{
		pipelined = TRUE;

		while(cr_search){
			if(cr_search->method!=HTTP_METHOD_GET && 
					cr_search->method!=HTTP_METHOD_HEAD)
			{
				pipelined = FALSE;
				break;
			}
			cr_search = cr_search->next;
		}

		if(pipelined == FALSE){
			/* All pipelined requests must use GET method */
			return NULL;
		}
		else{
			cr->pipelined = TRUE;
		}
	}

	/* DEBUG BLOCKS 
        printf("*****************************************");
	fflush(stdout);	
	cr_search = cr->request;
	while(cr_search){
		printf("\n---BLOCK---:\n%s---END BLOCK---\n\n", cr_search->body);
		fflush(stdout);
		cr_search = cr_search->next;
	}
	*/

	return cr->request;
}

int mk_handler_read(int socket)
{
	int bytes, efd;
        struct client_request *cr;

	cr = mk_request_client_get(socket);
	if(!cr)
	{
                /* Note: Linux don't set TCP_NODELAY socket flag by default, 
                 * also we set the client socket on non-blocking mode
                 */
                mk_socket_set_tcp_nodelay(socket);
                mk_socket_set_nonblocking(socket);

		cr = mk_request_client_create(socket);

                /* Update requests counter */
                mk_sched_update_thread_status(MK_SCHEDULER_ACTIVE_UP,
                                              MK_SCHEDULER_CLOSED_DOWN);
        }
        else{
                /* If cr struct already exists, that could means that we 
                 * are facing a keepalive connection, need to verify, if it 
                 * applies we increase the thread status for active connections
                 */
                if(cr->counter_connections > 1 && cr->body_length == 0){
                        mk_sched_update_thread_status(MK_SCHEDULER_ACTIVE_UP,
                                                      MK_SCHEDULER_CLOSED_NONE);
                }
        }

        bytes = read(socket, cr->body+cr->body_length,
                     MAX_REQUEST_BODY-cr->body_length);

	if (bytes < 0) {
		if (errno == EAGAIN) {
			return 1;
		} 
		else{
                        mk_request_client_remove(socket);
                        return -1;
                }
	}
	if (bytes == 0){
                mk_request_client_remove(socket);
                return -1;
	}

	if(bytes > 0)
	{
		cr->body_length+=bytes;
                cr->body[cr->body_length] = '\0';

                if(mk_http_pending_request(cr)==0){
                        efd = mk_sched_get_thread_poll();
                        mk_epoll_socket_change_mode(efd, socket, MK_EPOLL_WRITE);
                }
                else if(cr->body_length+1 >= MAX_REQUEST_BODY)
                {
                        /* Request is incomplete and our buffer is full, 
                         * close connection 
                         */
                        mk_request_client_remove(socket);
                        return -1;
                }
	}

	return 0;
}

int mk_handler_write(int socket, struct client_request *cr)
{
	int bytes, final_status=0;
	struct request *p_request;

	/* 
	 * Get node from schedule list node which contains
	 * the information regarding to the current thread
	 */
	cr = mk_request_client_get(socket);
	
	if(!cr)
	{
		return -1;
	}
	
	if(!cr->request)
	{
		if(!mk_request_parse(cr))
		{
			return -1;	
		}
	}

	p_request = cr->request;

	while(p_request)
	{
		/* Request not processed */
		if(p_request->bytes_to_send < 0)
		{
                        final_status = mk_request_process(cr, p_request);
		}
		/* Request with data to send */
		else if(p_request->bytes_to_send>0)
		{
                        bytes = SendFile(socket, p_request);
			final_status = bytes;
		}
		/*
		 * If we got an error, we don't want to parse
		 * and send information for another pipelined request
		 */
		if(final_status > 0)
		{
                        return final_status;
		}
		else if(final_status <= 0)
		{
                        mk_logger_write_log(p_request->log, p_request->host_conf);
		}
		p_request = p_request->next;
	}

	/* If we are here, is because all pipelined request were
	 * processed successfully, let's return 0;
	 */
	return 0;
}

int mk_request_process(struct client_request *cr, struct request *s_request)
{
	int status=0;
	struct host *host;

	status = mk_request_header_process(s_request);

	if(status<0)
	{
		return EXIT_NORMAL;
	}

        switch(s_request->method)
        {
                case METHOD_NOT_ALLOWED:
                        mk_request_error(M_CLIENT_METHOD_NOT_ALLOWED, cr, 
                                         s_request, 1, s_request->log);
                        return EXIT_NORMAL;
                case METHOD_NOT_FOUND:
                        mk_request_error(M_SERVER_NOT_IMPLEMENTED, cr,
                                         s_request, 1, s_request->log);
                        return EXIT_NORMAL;
        }

	s_request->user_home=VAR_OFF;
        s_request->log->method = s_request->method;

	/* Valid request URI? */
	if(s_request->uri_processed==NULL){
		mk_request_error(M_CLIENT_BAD_REQUEST, cr, s_request, 1, 
                                 s_request->log);
		return EXIT_NORMAL;
	}	
	
	/*  URL it's Allowed ? */ 
	if(Deny_Check(s_request, cr->ip.data)==-1) {
		s_request->log->final_response=M_CLIENT_FORBIDDEN;
		mk_request_error(M_CLIENT_FORBIDDEN, cr, s_request, 1,
                                 s_request->log);
		return EXIT_NORMAL;
	}
	

	/* HTTP/1.1 needs Host header */
	if(!s_request->host.data && s_request->protocol==HTTP_PROTOCOL_11){
		s_request->log->final_response=M_CLIENT_BAD_REQUEST;
		mk_request_error(M_CLIENT_BAD_REQUEST, cr, s_request,1,
                                 s_request->log);
		return EXIT_NORMAL;
	}

	/* Method not allowed ? */
	if(s_request->method==METHOD_NOT_ALLOWED){
		s_request->log->final_response=M_CLIENT_METHOD_NOT_ALLOWED;
		mk_request_error(M_CLIENT_METHOD_NOT_ALLOWED, cr, s_request, 1,
                                 s_request->log);
		return EXIT_NORMAL;
	}

	/* Validating protocol version */
	if(s_request->protocol == HTTP_PROTOCOL_UNKNOWN)
	{

		s_request->log->final_response=M_SERVER_HTTP_VERSION_UNSUP;
		mk_request_error(M_SERVER_HTTP_VERSION_UNSUP, cr, s_request, 1,
                                 s_request->log);
		return EXIT_NORMAL;
	}
	
	if(s_request->host.data)
	{
		host=mk_config_host_find(s_request->host);
		if(host)
		{
			s_request->host_conf = host;
		}
		else{
			s_request->host_conf = config->hosts;
		}
    	}
	else{
		s_request->host_conf = config->hosts;
	}
	s_request->log->host_conf = s_request->host_conf;

	/* is requesting an user home directory ? */
        if(config->user_dir){
                if(strncmp(s_request->uri_processed, 
                           mk_user_home.data,
                           mk_user_home.len)==0){
                        if(mk_user_init(cr, s_request)!=0){
                                return EXIT_NORMAL;
                        }
                }
        }
 
	/* Handling method requested */
	if(s_request->method==HTTP_METHOD_POST)
	{
		if((status=mk_method_post(cr, s_request))==-1){
			return status;
		}
	}

	status = mk_http_init(cr, s_request);

	return status;
}

/* Return a struct with method, URI , protocol version 
and all static headers defined here sent in request */
int mk_request_header_process(struct request *sr)
{
	int uri_init=0, uri_end=0;
        char *query_init=0;
	int prot_init=0, prot_end=0, pos_sep=0;
        int fh_limit;
	char *str_prot=0, *port=0;
	char *headers;
	mk_pointer host;

        /* If verification fails it will return always
         * a bad request status
         */
        sr->log->final_response = M_CLIENT_BAD_REQUEST;

	/* Method */
	sr->method_p = mk_http_method_check_str(sr->method);

	/* Request URI */
        uri_init = (index(sr->body.data, ' ') - sr->body.data) + 1;
        fh_limit = (index(sr->body.data, '\n') - sr->body.data);

        uri_end = mk_string_search_r(sr->body.data, ' ', 
                                                fh_limit) - 1;

        if(uri_end <= 0)
        {
                return -1;
        }

        prot_init = uri_end + 2;

	if(uri_end < uri_init)
	{
		return -1;
	}
	
	/* Query String */
	query_init = index(sr->body.data+uri_init, '?');
        if(query_init)
	{
                int init, end;

                init = (int) (query_init-(sr->body.data+uri_init)) + uri_init;
                if(init <= uri_end)
                {
                        end = uri_end;
                        uri_end = init - 1;
                 
                        sr->query_string = mk_pointer_create(sr->body.data, 
                                                             init+1, end+1);
                }
	}
        
	/* Request URI Part 2 */
	sr->uri = sr->log->uri = mk_pointer_create(sr->body.data, 
                                                   uri_init, uri_end+1);

	if(sr->uri.len<1)
	{
		return -1;
	}


	/* HTTP Version */
        prot_end = fh_limit-1;
	if(prot_end!=prot_init && prot_end>0){
		str_prot = mk_string_copy_substr(sr->body.data, 
                                                 prot_init, prot_end);
		sr->protocol = sr->log->protocol = 
                        mk_http_protocol_check(str_prot);

        	mk_mem_free(str_prot);
	}

	headers = sr->body.data+prot_end+mk_crlf.len;

	/* URI processed */
	sr->uri_processed = get_real_string(sr->uri);

        if(!sr->uri_processed)
	{
		sr->uri_processed = mk_pointer_to_buf(sr->uri);
		sr->uri_twin = VAR_ON;
	}

        /* Creating table of content (index) for request headers */
        int toc_len = MK_KNOWN_HEADERS;
        struct header_toc *toc = mk_request_header_toc_create(toc_len);
        mk_request_header_toc_parse(toc, headers, toc_len);

        /* Host */
	host = mk_request_header_find(toc, toc_len, headers, mk_rh_host);

	if(host.data)
	{
		if((pos_sep = mk_string_char_search(host.data, ':', host.len))>=0)
		{
			sr->host.data = host.data;
			sr->host.len = pos_sep;

			port = mk_string_copy_substr(host.data, pos_sep+1, host.len);
			sr->port = atoi(port);
			mk_mem_free(port);
		}
		else{
			sr->host=host;  /* maybe null */ 
			sr->port=config->standard_port;
		}
	}
	else{
		sr->host.data=NULL;
	}
	
        /* Looking for headers */
	sr->accept = mk_request_header_find(toc, toc_len, headers, mk_rh_accept);
	sr->accept_charset = mk_request_header_find(toc, toc_len, headers, 
                                                    mk_rh_accept_charset);
	sr->accept_encoding = mk_request_header_find(toc, toc_len, headers, 
                                                           mk_rh_accept_encoding);


	sr->accept_language = mk_request_header_find(toc, toc_len, headers, 
                                                     mk_rh_accept_language);
	sr->cookies = mk_request_header_find(toc, toc_len, headers, mk_rh_cookie);
	sr->connection = mk_request_header_find(toc, toc_len, headers, 
                                                mk_rh_connection);
	sr->referer = mk_request_header_find(toc, toc_len, headers, 
                                             mk_rh_referer);
	sr->user_agent = mk_request_header_find(toc, toc_len, headers, 
                                                mk_rh_user_agent);
	sr->range = mk_request_header_find(toc, toc_len, headers, mk_rh_range);
	sr->if_modified_since = mk_request_header_find(toc, toc_len, headers, 
                                                     mk_rh_if_modified_since);

	/* Default Keepalive is off */
	sr->keep_alive = VAR_OFF;
        if(sr->connection.data){
                if(mk_string_casestr(sr->connection.data, "Keep-Alive")){
                        sr->keep_alive = VAR_ON;
                }
        }
        else{
                /* Default value for HTTP/1.1 */
                if(sr->protocol==HTTP_PROTOCOL_11){
                        /* Assume keep-alive connection */
                        sr->keep_alive = VAR_ON;
                }
        }
        sr->log->final_response = M_HTTP_OK;

        /*
        mk_pointer_print(sr->method_p);
        mk_pointer_print(sr->uri);
        mk_pointer_print(sr->query_string);
        */

	return 0;
}

/* Return value of some variable sent in request */
mk_pointer mk_request_header_find(struct header_toc *toc, int toc_len, 
                                  char *request_body,  mk_pointer header)
{
        int i;
	mk_pointer var;

	var.data = NULL;
	var.len = 0;

        /* new code */
        if(toc)
        {
                for(i=0; i<toc_len; i++)
                {
                        /* status = 1 means that the toc entry was already
                         * checked by monkey 
                         */
                        if(toc[i].status == 1)
                        {
                                continue;
                        }

                        if(!toc[i].init)
                                break;

                        if(strncasecmp(toc[i].init, header.data, header.len)==0)
                        {
                                var.data = toc[i].init + header.len + 1;
                                var.len = toc[i].end - var.data;
                                toc[i].status = 1;
                                return var;
                        }
                }
        }

        return var;
}

/* FIXME: IMPROVE access */
/* Look for some  index.xxx in pathfile */
mk_pointer mk_request_index(char *pathfile)
{
	unsigned long len;
	char *file_aux=0;
        mk_pointer f;
	struct indexfile *aux_index;

        mk_pointer_reset(&f);

	aux_index=first_index;

	while(aux_index) {
		m_build_buffer(&file_aux, &len, "%s%s", 
                               pathfile, aux_index->indexname);
	
		if(access(file_aux,F_OK)==0)
		{
                        f.data = file_aux;
                        f.len = len;
			return f;
		}
		mk_mem_free(file_aux);
		aux_index=aux_index->next;
	}

	return f;
}

/* Send error responses */
void mk_request_error(int num_error, struct client_request *cr, 
                   struct request *s_request, int debug, struct log_info *s_log)
{
	char *aux_message=0;
	mk_pointer message, page;
        long n;

	if(!s_log) {
		s_log=mk_mem_malloc(sizeof(struct log_info));
	}
	
	mk_pointer_reset(&page);

	switch(num_error) {
		case M_CLIENT_BAD_REQUEST:
			mk_request_set_default_page(&page, "Bad Request", 
					s_request->uri, 
					s_request->host_conf->host_signature);
			s_log->error_msg = request_error_msg_400; 
			break;

		case M_CLIENT_FORBIDDEN:
			mk_request_set_default_page(&page, "Forbidden", 
					s_request->uri, 
					s_request->host_conf->host_signature);
			s_log->error_msg = request_error_msg_403;
			// req s_request->uri;
			break;

		case M_CLIENT_NOT_FOUND:
			m_build_buffer(&message.data, &message.len,
					"The requested URL was not found on this server.");
			mk_request_set_default_page(&page, "Not Found", 
					message, 
					s_request->host_conf->host_signature);
			s_log->error_msg = request_error_msg_404;
			// req uri;
			mk_pointer_free(&message);
			break;

		case M_CLIENT_METHOD_NOT_ALLOWED:
			mk_request_set_default_page(&page, "Method Not Allowed",
					s_request->uri, 
					s_request->host_conf->host_signature);

			s_log->final_response=M_CLIENT_METHOD_NOT_ALLOWED;
			s_log->error_msg = request_error_msg_405;
			break;

		case M_CLIENT_REQUEST_TIMEOUT:
			s_log->status=S_LOG_OFF;
			s_log->error_msg = request_error_msg_408;
			break;

		case M_CLIENT_LENGTH_REQUIRED:
			s_log->error_msg = request_error_msg_411;
			break;
			
                case M_SERVER_NOT_IMPLEMENTED:
                        mk_request_set_default_page(&page, 
                                                    "Method Not Implemented",
                                                    s_request->uri,
                                                    s_request->host_conf->host_signature);
                        s_log->final_response=M_SERVER_NOT_IMPLEMENTED;
                        s_log->error_msg = request_error_msg_501;
                        break;

		case M_SERVER_INTERNAL_ERROR:
			m_build_buffer(&message.data, &message.len, 
					"Problems found running %s ",
					s_request->uri);
			mk_request_set_default_page(&page, "Internal Server Error",
					message, s_request->host_conf->host_signature);
			s_log->error_msg = request_error_msg_500;

			mk_pointer_free(&message);
			break;
			
		case M_SERVER_HTTP_VERSION_UNSUP:
			mk_pointer_reset(&message);
			mk_request_set_default_page(&page, 
                                                    "HTTP Version Not Supported",
                                                    message,
				       s_request->host_conf->host_signature);
			s_log->error_msg = request_error_msg_505;
			break;
	}

	s_log->final_response=num_error;

	s_request->headers->status = num_error;
	s_request->headers->content_length = page.len;
        s_request->headers->content_length_p = mk_utils_int2mkp(page.len);
	s_request->headers->location = NULL;
	s_request->headers->cgi = SH_NOCGI;
	s_request->headers->pconnections_left = 0;
	mk_pointer_reset(&s_request->headers->last_modified);
	
	if(aux_message) mk_mem_free(aux_message);
	
	if(!page.data)
	{
          mk_pointer_reset(&s_request->headers->content_type);
	}
	else
	{
          mk_pointer_set(&s_request->headers->content_type, "text/html");
	}

	mk_header_send(cr->socket, cr, s_request, s_log);
        
	if(debug==1){
                n = write(cr->socket, page.data, page.len);
		mk_pointer_free(&page);
	}
}

/* Build error page */
void mk_request_set_default_page(mk_pointer *page, char *title, 
		mk_pointer message, char *signature)
{
	char *temp;
	
	temp = mk_pointer_to_buf(message);
	m_build_buffer(&page->data, &page->len, 
                       MK_REQUEST_DEFAULT_PAGE,
                       title, temp, signature);
	mk_mem_free(temp);
}

/* Create a memory allocation in order to handle the request data */
struct request *mk_request_alloc()
{
	struct request *request=0;

	request = (struct request *) mk_mem_malloc(sizeof(struct request));
	request->log = (struct log_info *) mk_mem_malloc(sizeof(struct log_info));

	request->status=VAR_OFF; /* Request not processed yet */
	request->make_log=VAR_ON; /* build log file of this request ? */

        mk_pointer_reset(&request->body);

	request->log->final_response=M_HTTP_OK;
	request->log->status=S_LOG_ON;

        mk_pointer_reset(&request->log->size_p);
	mk_pointer_reset(&request->log->error_msg);

	request->status=VAR_ON;
	request->method=METHOD_NOT_FOUND;

	mk_pointer_reset(&request->uri);
	request->uri_processed = NULL;
	request->uri_twin = VAR_OFF;

 	request->accept.data = NULL;
	request->accept_language.data = NULL;
	request->accept_encoding.data = NULL;
	request->accept_charset.data = NULL;
	request->content_type.data = NULL;
	request->connection.data = NULL;	
	request->cookies.data = NULL; 
	request->host.data = NULL;
	request->if_modified_since.data = NULL;
	request->last_modified_since.data = NULL;
	request->range.data = NULL;
	request->referer.data = NULL;
	request->resume.data = NULL;
	request->user_agent.data = NULL;

	request->post_variables.data = NULL;

	request->user_uri = NULL;
	mk_pointer_reset(&request->query_string);

	request->virtual_user = NULL;
	request->script_filename = NULL;
	mk_pointer_reset(&request->real_path);
	request->host_conf = config->hosts; 

	request->bytes_to_send = -1;
	request->bytes_offset = 0;
	request->fd_file = -1;

	/* Response Headers */
	request->headers = mk_header_create();

	return (struct request *) request;
}

void mk_request_free_list(struct client_request *cr)
{
    struct request *sr=0, *before=0;
    
    /* sr = last node */

    while(cr->request)
    {
        sr = before = cr->request;

	while(sr->next)
        {
            sr = sr->next;
        }

        if(sr!=cr->request){
            while(before->next!=sr){
                before = before->next;
            }
            before->next = NULL;
        }
        else{
            cr->request = NULL;
        }
        mk_request_free(sr);
    }
    cr->request = NULL;
}

void mk_request_free(struct request *sr)
{
        /* I hate it, but I don't know another light way :( */
	if(sr->fd_file>0)
	{
		close(sr->fd_file);
	}
	if(sr->headers){
            mk_mem_free(sr->headers->location);
            mk_pointer_free(&sr->headers->last_modified);
            /*
                mk_mem_free(sr->headers->content_type);
                 headers->content_type never it's allocated 
		 with malloc or something, so we don't need 
		 to free it, the value has been freed before 
		 in M_METHOD_Get_and_Head(struct request *sr)
                
		 this BUG was reported by gentoo team.. thanks guys XD
            */

            mk_mem_free(sr->headers);
        }

        
        if(sr->log){
        	//mk_mem_free(sr->log->error_msg); 
		mk_mem_free(sr->log);
        }

        mk_pointer_reset(&sr->body);
        mk_pointer_reset(&sr->uri);

	if(sr->uri_twin==VAR_ON)
	{
		mk_mem_free(sr->uri_processed);
        }

        mk_pointer_free(&sr->post_variables);
        mk_mem_free(sr->user_uri);
 	mk_pointer_reset(&sr->query_string);

        mk_mem_free(sr->virtual_user);
        mk_mem_free(sr->script_filename);
        mk_pointer_free(&sr->real_path);
	mk_mem_free(sr);
}

/* Create a client request struct and put it on the
 * main list
 */
struct client_request *mk_request_client_create(int socket)
{
        struct request_idx *request_index;
	struct client_request *cr;

	cr = mk_mem_malloc(sizeof(struct client_request));

	cr->pipelined = FALSE;
	cr->counter_connections = 0;
	cr->socket = socket;
	cr->request = NULL;

        mk_pointer_set(&cr->ip, mk_socket_get_ip(socket));

        /* creation time in unix time */
        cr->init_time = log_current_utime;

	cr->next = NULL;
	cr->body = mk_mem_malloc(MAX_REQUEST_BODY);
	cr->body_length = 0;
        cr->first_block_end = -1;
        cr->first_method = HTTP_METHOD_UNKNOWN;

        request_index = mk_sched_get_request_index();
	if(!request_index->first)
	{
		request_index->first = request_index->last = cr;
	}
	else{
                request_index->last->next = cr;
                request_index->last = cr;
	}
        mk_sched_set_request_index(request_index);


        mk_sched_update_thread_status(MK_SCHEDULER_ACTIVE_UP,
                                      MK_SCHEDULER_CLOSED_NONE);
        
        return (struct client_request *) cr;
}

struct client_request *mk_request_client_get(int socket)
{
	struct request_idx *request_index;
        struct client_request *cr=NULL;

	request_index = mk_sched_get_request_index();
	cr = request_index->first;
	while(cr!=NULL)
	{
		if(cr->socket == socket)
		{
                        break;
		}
		cr = cr->next;
	}

	return (struct client_request *) cr;
}

/*
 * From thread sched_list_node "list", remove the client_request
 * struct information 
 */
struct client_request *mk_request_client_remove(int socket)
{
	struct request_idx *request_index;
        struct client_request *cr, *aux;

	request_index = mk_sched_get_request_index();
	cr = request_index->first;

	while(cr)
	{
		if(cr->socket == socket)
		{
			if(cr==request_index->first)
			{
				request_index->first = cr->next;
			}
			else
			{
				aux = request_index->first;
				while(aux->next!=cr)
				{
					aux = aux->next;
				}
				aux->next = cr->next;
                                if(!aux->next)
                                {
                                        request_index->last = aux;
                                }
			}
			break;
		}
		cr = cr->next;
	}
        
        /* No keep alive connection */
        if(cr->counter_connections == 0){
                mk_sched_update_thread_status(MK_SCHEDULER_ACTIVE_DOWN,
                                              MK_SCHEDULER_CLOSED_UP);
        }

        mk_pointer_free(&cr->ip);
	mk_mem_free(cr->body);
	mk_mem_free(cr);

	return NULL;
}

struct header_toc *mk_request_header_toc_create(int len)
{
        int i;
        struct header_toc *p;

        p = (struct header_toc *) pthread_getspecific(mk_cache_header_toc);

        for(i=0; i<len; i++)
        {
                p[i].init = NULL;
                p[i].end = NULL;
                p[i].status = 0;
        }
        return p;
}

void mk_request_header_toc_parse(struct header_toc *toc, char *data, int len)
{
        char *p, *l;
        int i;

        p = data;
        for(i=0; i<len && p; i++)
        {
                l = strstr(p, MK_CRLF);

                if(l)
                {
                        toc[i].init = p;
                        toc[i].end = l;
                        p = l + mk_crlf.len;
                }
                else
                {
                        break;
                }
        }
}

void mk_request_ka_next(struct client_request *cr)
{
        bzero(cr->body, sizeof(cr->body));
        cr->first_method = -1;
        cr->first_block_end = -1;
        cr->body_length = 0;
        cr->counter_connections++;
}
