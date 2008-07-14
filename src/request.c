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
#include "vhost.h"
#include "socket.h"
#include "logfile.h"
#include "utils.h"
#include "header.h"
#include "deny.h"
#include "user.h"
#include "method.h"
#include "memory.h"

struct request *mk_request_parse(struct client_request *cr)
{
	int i, init_block=0, n_blocks=0, offset=0;
	int length_buf=0, length_end=0;
	int pipelined=FALSE;
	char *string_end=0, *check_normal_string=0, *check_old_string=0;
	struct request *cr_buf=0, *cr_search=0;

	check_normal_string = strstr(cr->body, NORMAL_STRING_END);
	if(check_normal_string)
	{
		if(check_old_string)
		{
			return FALSE;
		}
		else
		{
			string_end = NORMAL_STRING_END;
			length_end = LEN_NORMAL_STRING_END;
			offset = 0;
		}
	}
	else if(check_old_string)
	{
		check_old_string = strstr(cr->body, OLD_STRING_END);
		if(check_old_string)
		{
			string_end = OLD_STRING_END;
			length_end = LEN_OLD_STRING_END;
			offset = 1;
		}
		else{
			return FALSE;
		}
	}

	length_buf = cr->body_length;

	init_block = 0;
	for(i=0; i<= length_buf-length_end; i++)
	{
		if(strncmp(cr->body+i, string_end, length_end)==0)
		{
			/* Allocating request block */
			//block = mk_string_copy_substr(cr->body, init_block, i);
				
			cr_buf = mk_request_alloc();
	
			/* mk_pointer */
			cr_buf->body.data = cr->body+init_block;
			cr_buf->body.len = i-init_block;

			cr_buf->method = mk_http_method_get(cr_buf->body);
			cr_buf->log->ip = cr->client_ip;
			cr_buf->next = NULL;

			i = init_block = (i+offset) + length_end;
	
			/* Looking for POST data */
			if(cr_buf->method == HTTP_METHOD_POST)
			{
				cr_buf->post_variables = M_Get_POST_Vars(cr->body, i, string_end);
				if(cr_buf->post_variables)
				{
					i += strlen(cr_buf->post_variables) + length_end;
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
			/* All pipelined requests must been GET method */
			return NULL;
		}
		else{
			cr->pipelined = TRUE;
		}
	}

	/* DEBUG BLOCKS 
        // printf("*****************************************");
	//fflush(stdout);	
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
		cr = mk_request_client_create(socket);
	}

	bytes = read(socket, cr->body+cr->body_length,
			MAX_REQUEST_BODY-cr->body_length-1);

	if (bytes == -1) {
		if (errno == EAGAIN) {
			return 1;
		} 
		else{
			perror("read");
			return -1;
		}
	}
	if (bytes == 0){
		return -1;
	}

	if(bytes > 0)
	{
		cr->body_length+=bytes;
		efd = mk_sched_get_thread_poll();

		if(strncmp(cr->body+(cr->body_length-LEN_NORMAL_STRING_END),
					NORMAL_STRING_END, 
					LEN_NORMAL_STRING_END) == 0)
		{
			mk_epoll_socket_change_mode(efd, socket, 
					MK_EPOLL_WRITE);
		}
		else if(strncmp(cr->body+(cr->body_length-LEN_OLD_STRING_END),
					OLD_STRING_END,
					LEN_OLD_STRING_END) == 0)
		{
			mk_epoll_socket_change_mode(efd, socket, 
					MK_EPOLL_WRITE);
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
		if(final_status<0 || final_status > 0)
		{
			return final_status;
		}
		write_log(p_request->log, p_request->host_conf->logpipe[1]);
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

	s_request->user_home=VAR_OFF;

	/* Valid request URI? */
	if(s_request->uri_processed==NULL){
		mk_request_error(M_CLIENT_BAD_REQUEST, cr, s_request, 1, s_request->log);
		return EXIT_NORMAL;
	}	
	
	/*  URL it's Allowed ? */ 
	if(Deny_Check(s_request, cr->client_ip)==-1) {
		s_request->log->final_response=M_CLIENT_FORBIDDEN;
		mk_request_error(M_CLIENT_FORBIDDEN, cr, s_request,1,s_request->log);
		return EXIT_NORMAL;
	}
	

	/* HTTP/1.1 needs Host header */
	if(!s_request->host.data && s_request->protocol==HTTP_PROTOCOL_11){
		s_request->log->final_response=M_CLIENT_BAD_REQUEST;
		mk_request_error(M_CLIENT_BAD_REQUEST, cr, s_request,1,s_request->log);
		return EXIT_NORMAL;
	}

	/* Method not allowed ? */
	if(s_request->method==METHOD_NOT_ALLOWED){
		s_request->log->final_response=M_CLIENT_METHOD_NOT_ALLOWED;
		mk_request_error(M_CLIENT_METHOD_NOT_ALLOWED, cr, s_request,1,s_request->log);
		return EXIT_NORMAL;
	}

	/* Validating protocol version */
	if(s_request->protocol == HTTP_PROTOCOL_UNKNOWN)
	{
		s_request->log->final_response=M_SERVER_HTTP_VERSION_UNSUP;
		mk_request_error(M_SERVER_HTTP_VERSION_UNSUP, cr, s_request,1,s_request->log);
		return EXIT_NORMAL;
	}
	
	if(s_request->host.data)
	{
		host=VHOST_Find(s_request->host);
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

	/* CGI Request ? */
	if(s_request->host_conf->scriptalias!=NULL){
		int len=0;

		len = strlen(s_request->host_conf->scriptalias[0]);
		if((strncmp(s_request->host_conf->scriptalias[0], s_request->uri_processed, len))==0){
			int cgi_status;
			cgi_status=M_CGI_main(cr, s_request, s_request->log, s_request->body);
			/* Codes:
				-1 : Fallo de permisos
				-2 : Timeout
				-3 : Internal Server Error
			*/
			if(cgi_status==M_CGI_TIMEOUT || cgi_status==M_CGI_INTERNAL_SERVER_ERR){
				mk_request_error(s_request->log->final_response, 
						cr, s_request, 1, s_request->log);	
			}
			return cgi_status;
		}
	}

	/* is requesting an user home directory ? */
	if(strncmp(s_request->uri_processed, USER_HOME_STRING, 
        strlen(USER_HOME_STRING))==0 && config->user_dir){
		if(User_main(cr, s_request)!=0)
			return EXIT_NORMAL;
	}

	/* 
	 * Handling method requested */
	if(s_request->method==HTTP_METHOD_POST)
	{
		if((status=M_METHOD_Post(cr, s_request))==-1){
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
	int query_init=0, query_end=0;
	int prot_init=0, prot_end=0, pos_sep=0;
	int break_line;
	char *str_prot=0, *port=0;
	char *headers;
	mk_pointer host;

	/* Method */
	sr->method_str = (char *) mk_http_method_check_str(sr->method);

	/* Request URI */
	uri_init = mk_string_search(sr->body.data, " ") + 1;
	uri_end = mk_string_search(sr->body.data+uri_init, " ") + uri_init;

	if(uri_end < uri_init)
	{
		return -1;
	}
	
	/* Query String */
	query_init = mk_string_search(sr->body.data+uri_init, "?");
	if(query_init > 0 && query_init <= uri_end)
	{
		query_init+=uri_init+1;
		query_end = uri_end;
		uri_end = query_init - 1;
		sr->query_string = mk_pointer_create(sr->body.data, query_init, query_end);
	}
	
	/* Request URI Part 2 */
	sr->uri = sr->log->uri = mk_pointer_create(sr->body.data, uri_init, uri_end);
	
	if(sr->uri.len<1)
	{
		return -1;
	}
	
	/* HTTP Version */
	prot_init=mk_string_search(sr->body.data+uri_init+1," ")+uri_init+2;

	if(mk_string_search(sr->body.data, "\r\n")>0){
		prot_end = mk_string_search(sr->body.data, "\r\n");
		break_line = 2;
	}
	else{
		prot_end = mk_string_search(sr->body.data, "\n");
		break_line = 1;
	}

	if(prot_end!=prot_init && prot_end>0){
		str_prot = mk_string_copy_substr(sr->body.data, prot_init, prot_end);
		sr->protocol = sr->log->protocol = mk_http_protocol_check(str_prot);
        	mk_mem_free(str_prot);
	}
	headers = sr->body.data+prot_end+break_line;

	/* URI processed */
	sr->uri_processed = get_real_string(sr->uri);
	if(!sr->uri_processed)
	{
		sr->uri_processed = mk_pointer_to_buf(sr->uri);
		sr->uri_twin = VAR_ON;
	}

	/* Host */
	host = mk_request_header_find(headers, RH_HOST);

	if(host.data)
	{
		if((pos_sep = mk_string_search_n(host.data, ":", host.len))>=0)
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
	sr->accept = mk_request_header_find(headers, RH_ACCEPT);
	sr->accept_charset = mk_request_header_find(headers, RH_ACCEPT_CHARSET);
	sr->accept_encoding = mk_request_header_find(headers, RH_ACCEPT_ENCODING);
	sr->accept_language = mk_request_header_find(headers, RH_ACCEPT_LANGUAGE);
	sr->cookies = mk_request_header_find(headers, RH_COOKIE);
	sr->connection = mk_request_header_find(headers, RH_CONNECTION);
	sr->referer = mk_request_header_find(headers, RH_REFERER);
	sr->user_agent = mk_request_header_find(headers, RH_USER_AGENT);
	sr->range = mk_request_header_find(headers, RH_RANGE);
	sr->if_modified_since = mk_request_header_find(headers, RH_IF_MODIFIED_SINCE);

	/* Checking keepalive */
	sr->keep_alive=VAR_OFF;
	if(sr->connection.data)
	{
		if(sr->protocol==HTTP_PROTOCOL_11 || 
				sr->protocol==HTTP_PROTOCOL_10)
		{
			if(mk_string_casestr(sr->connection.data,"Keep-Alive"))
			{
				sr->keep_alive=VAR_ON;
			}
		}
	}
	return 0;
}

/* Return value of some variable sent in request */
mk_pointer mk_request_header_find(char *request_body,  char *string)
{
	mk_pointer var;
	int pos_init_var=0, pos_end_var=0;
	char *t;

	var.data = NULL;
	var.len = 0;

	/* looking for string on request_body ??? */	
	if(!(t=(char *)mk_string_casestr(request_body, string)))
	{
		return var;
	}

	pos_init_var = strlen(string);
	if((t+pos_init_var)[0]==' ')
	{
		pos_init_var++;
	}

	pos_end_var = mk_string_search((char *)t, "\n") - 1;
	if(pos_end_var<0)
	{
		pos_end_var = strlen(t);
	}
	if(pos_init_var<=0 || pos_end_var<=0){
		return  var;	
	}

	var.data = t+pos_init_var;
	var.len = pos_end_var - pos_init_var;
	return (mk_pointer) var;
}

/* Look for some  index.xxx in pathfile */
char *mk_request_index(char *pathfile)
{
	unsigned long len;
	char *file_aux=0;
	struct indexfile *aux_index;

	aux_index=first_index;
	
	while(aux_index!=NULL) {
		if(pathfile[strlen(pathfile)-1]=='/')
		{
			m_build_buffer(&file_aux, &len,
					"%s/%s",pathfile,aux_index->indexname);
		}
		else
		{
			m_build_buffer(&file_aux, &len,
					"%s%s",pathfile,aux_index->indexname);
		}
	
		if(access(file_aux,F_OK)==0) {
			mk_mem_free(file_aux);
			return (char *) aux_index->indexname;
		}
		mk_mem_free(file_aux);
		aux_index=aux_index->next;
	}

	return NULL;
}

/* Send error responses */
void mk_request_error(int num_error, struct client_request *cr, 
                   struct request *s_request, int debug, struct log_info *s_log)
{
	unsigned long len;
	char *page_default=0, *aux_message=0;
	mk_pointer message;

	if(!s_log) {
		s_log=mk_mem_malloc(sizeof(struct log_info));
	}
		
	switch(num_error) {
		case M_CLIENT_BAD_REQUEST:
			page_default=mk_request_set_default_page("Bad Request", 
					s_request->uri, 
					s_request->host_conf->host_signature);
			m_build_buffer(&s_log->error_msg, &len,
					"[error 400] Bad request");
			break;

		case M_CLIENT_FORBIDDEN:
			page_default=mk_request_set_default_page("Forbidden", 
					s_request->uri, 
					s_request->host_conf->host_signature);
			m_build_buffer(&s_log->error_msg, &len,
					"[error 403] Forbidden %s",s_request->uri);
			break;

		case M_CLIENT_NOT_FOUND:
			m_build_buffer(&message.data, &message.len,
					"The requested URL was not found on this server.");
			page_default=mk_request_set_default_page("Not Found", 
					message, 
					s_request->host_conf->host_signature);
			m_build_buffer(&s_log->error_msg, &len, 
					"[error 404] Not Found %s",
					s_request->uri);
			mk_pointer_free(message);
			break;

		case M_CLIENT_METHOD_NOT_ALLOWED:
			page_default=mk_request_set_default_page("Method Not Allowed",
					s_request->uri, 
					s_request->host_conf->host_signature);

			s_log->final_response=M_CLIENT_METHOD_NOT_ALLOWED;
			m_build_buffer(&s_log->error_msg, &len, 
					"[error 405] Method Not Allowed");
			break;

		case M_CLIENT_REQUEST_TIMEOUT:
			s_log->status=S_LOG_OFF;
			m_build_buffer(&s_log->error_msg, &len,
					"[error 408] Request Timeout");
			break;

		case M_CLIENT_LENGHT_REQUIRED:
			m_build_buffer(&s_log->error_msg, &len,
					"[error 411] Length Required");
			break;
			
		case M_SERVER_INTERNAL_ERROR:
			m_build_buffer(&message.data, &message.len, 
					"Problems found running %s ",
					s_request->uri);
			page_default=mk_request_set_default_page("Internal Server Error",
					message, s_request->host_conf->host_signature);
			m_build_buffer(&s_log->error_msg, &len,
					"[error 411] Internal Server Error %s",s_request->uri);
			mk_pointer_free(message);
			break;
			
		case M_SERVER_HTTP_VERSION_UNSUP:
			mk_pointer_reset(message);
			page_default=mk_request_set_default_page("HTTP Version Not Supported",message,
				       s_request->host_conf->host_signature);
			m_build_buffer(&s_log->error_msg, &len, 
					"[error 505] HTTP Version Not Supported");
			break;
	}

	s_log->final_response=num_error;
	
	s_request->headers->status = num_error;
	s_request->headers->content_length = 0;
	s_request->headers->location = NULL ;
	s_request->headers->cgi = SH_NOCGI;
	s_request->headers->pconnections_left = 0;
	s_request->headers->last_modified = NULL;
	
	if(aux_message) mk_mem_free(aux_message);
	
	if(!page_default)
	{
		s_request->headers->content_type = NULL;
	}
	else
	{
		m_build_buffer(&s_request->headers->content_type,
				&len,
				"text/html");
	}

	M_METHOD_send_headers(cr->socket, cr, s_request, s_log);

	if(debug==1){
		fdprintf(cr->socket, NO_CHUNKED, "%s", page_default);
		mk_mem_free(page_default);
	}
}

/* Build error page */
char *mk_request_set_default_page(char *title, 
		mk_pointer message, char *signature)
{
	unsigned long len;
	char *page=0;
	char *temp;
	
	temp = mk_pointer_to_buf(message);
	m_build_buffer(&page, &len, "<HTML><BODY><H1>%s</H1>%s<BR><HR> \
		<ADDRESS>%s</ADDRESS></BODY></HTML>", title, temp, signature);

	mk_mem_free(temp);
	return (char *) page;
}

/* Create a memory allocation in order to handle the request data */
struct request *mk_request_alloc()
{
	struct request *request=0;

	request = (struct request *) mk_mem_malloc_z(sizeof(struct request));
	request->log = (struct log_info *) mk_mem_malloc_z(sizeof(struct log_info));

	request->status=VAR_OFF; /* Request not processed yet */
	request->make_log=VAR_ON; /* build log file of this request ? */
	mk_pointer_reset(request->query_string);
	
	//request->log->datetime=PutTime();
	request->log->final_response=M_HTTP_OK;
	request->log->status=S_LOG_ON;
	request->log->error_msg = NULL;
	request->status=VAR_ON;
	request->method=METHOD_NOT_FOUND;

	mk_pointer_reset(request->uri);
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

	request->post_variables = NULL;

	request->user_uri = NULL;
	mk_pointer_reset(request->query_string);

	request->virtual_user = NULL;
	request->script_filename = NULL;
	request->real_path = NULL;
	request->host_conf = config->hosts; 

	request->bytes_to_send = -1;
	request->bytes_offset = 0;
	request->fd_file = -1;

	request->headers = (struct header_values *) mk_mem_malloc(sizeof(struct header_values));

	request->headers->content_type = NULL;
	request->headers->last_modified = NULL;
	request->headers->location = NULL;
	request->headers->ranges[0]=-1;
	request->headers->ranges[1]=-1;

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
            mk_mem_free(sr->headers->last_modified);
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
            mk_mem_free(sr->log->error_msg); 
            mk_mem_free(sr->log);
        }

        mk_pointer_reset(sr->body);
        mk_pointer_reset(sr->uri);

	if(sr->uri_twin==VAR_OFF)
	{
		mk_mem_free(sr->uri_processed);
	}

	mk_mem_free(sr->post_variables);
        mk_mem_free(sr->user_uri);
 	mk_pointer_reset(sr->query_string);

        mk_mem_free(sr->virtual_user);
        mk_mem_free(sr->script_filename);
        mk_mem_free(sr->real_path);
	mk_mem_free(sr);
}

/* Create a client request struct and put it on the
 * main list
 */
struct client_request *mk_request_client_create(int socket)
{
	struct client_request *request_handler, *cr, *aux;

	cr = mk_mem_malloc_z(sizeof(struct client_request));

	cr->pipelined = FALSE;
	cr->counter_connections = 0;
	cr->socket = socket;
	cr->request = NULL;
	cr->client_ip = mk_socket_get_ip(socket);
	cr->next = NULL;
	cr->body = mk_mem_malloc_z(MAX_REQUEST_BODY);
	request_handler = mk_sched_get_request_handler();
	cr->body_length = 0;

	if(!request_handler)
	{
		request_handler = cr;
	}
	else{
		aux = request_handler;
		while(aux->next!=NULL)
		{
			aux = aux->next;
		}

		aux->next = cr;
	}

	mk_sched_set_request_handler(request_handler);
	request_handler = mk_sched_get_request_handler();
	return (struct client_request *) cr;
}

struct client_request *mk_request_client_get(int socket)
{
	struct client_request *request_handler, *cr;

	request_handler = mk_sched_get_request_handler();
	cr = request_handler;
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
	struct client_request *request_handler, *cr, *aux;

	request_handler = mk_sched_get_request_handler();
	cr = request_handler;
	
	while(cr)
	{
		if(cr->socket == socket)
		{
			if(cr==request_handler)
			{
				request_handler = cr->next;
			}
			else
			{
				aux = request_handler;
				while(aux->next!=cr)
				{
					aux = aux->next;
				}
				aux->next = cr->next;
			}
			break;
		}
		cr = cr->next;
	}
	mk_mem_free(cr->body);
	mk_mem_free(cr);
	mk_sched_set_request_handler(request_handler);
	return NULL;
}

