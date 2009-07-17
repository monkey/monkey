 /* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2009, Eduardo Silva P.
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
#include "http.h"
#include "http_status.h"
#include "cgi.h"
#include "method.h"
#include "str.h"
#include "memory.h"
#include "utils.h"
#include "config.h"
#include "support.h"
#include "logfile.h"
#include "socket.h"
#include "header.h"
#include "iov.h"

struct palm *mk_palm_get_handler(mk_pointer *file)
{
        struct palm *p;
	int j, len;

	j = len = file->len;
	
	/* looking for extension */
	while(file->data[j]!='.' && j>=0) 
		j--;

        if(j==0){
                return NULL;
        }

        p = palms;
        while(p)
        {
                if(strcasecmp(file->data+j+1, p->ext)==0)
                {
                        return p;
                }
                p = p->next;
        }

        return NULL;
}

char *mk_palm_check_request(struct client_request *cr, struct request *sr)
{
        int sock, ret, n=0, total=0;
        char *buf;
        int len = 50024;
        struct palm *p;
        struct mk_iov *iov;

        p = mk_palm_get_handler(&sr->real_path);
        if(!p)
        {
                return NULL;
        }

        sock = mk_socket_create();
        ret = mk_socket_connect(sock, p->host, p->port);

        iov = mk_palm_create_env(cr, sr);

        mk_socket_set_tcp_nodelay(sock);
        mk_socket_set_cork_flag(sock, TCP_CORK_ON);
        mk_iov_send(sock, iov, MK_IOV_SEND_TO_SOCKET);

        n = write(sock, "\r\n\r\n", 2);
        fflush(stdout);

        mk_socket_set_cork_flag(sock, TCP_CORK_OFF);
        
        buf = mk_mem_malloc_z(len);
        do {
                n=read(sock, buf+total, len);
                total+=n;
        }while(n>0);

        return (char *)buf;
}

struct mk_iov *mk_palm_create_env(struct client_request *cr, 
                                  struct request *sr)
{
        struct mk_iov *iov;

        iov = mk_iov_create(100, 0);

        mk_iov_add_entry(iov, sr->real_path.data,
                         sr->real_path.len,
                         mk_crlf,
                         MK_IOV_NOT_FREE_BUF);

        mk_iov_add_entry(iov, mk_cgi_document_root.data, 
                         mk_cgi_document_root.len, 
                         mk_iov_equal,
                         MK_IOV_NOT_FREE_BUF);
        

        mk_iov_add_entry(iov, sr->host_conf->documentroot.data,
                         sr->host_conf->documentroot.len, mk_iov_crlf,
                         MK_IOV_NOT_FREE_BUF);


        if(sr->method == HTTP_METHOD_POST && sr->content_length>0){
                /* FIX Content length: 
                mk_palm_iov_add_header(iov, mk_cgi_content_length,
                                       sr->content_length);
                */
                mk_palm_iov_add_header(iov, mk_cgi_content_type,
                                       sr->content_type);
        }


        //mk_palm_iov_add_header(iov, mk_cgi_server_addr, config->server_addr);
        mk_palm_iov_add_header(iov, mk_cgi_server_name, sr->host);
        mk_palm_iov_add_header(iov, mk_cgi_server_protocol, mk_monkey_protocol);
        mk_palm_iov_add_header(iov, mk_cgi_server_software, 
                               config->server_software);
        //        mk_palm_iov_add_header(iov, mk_cgi_server_signature, 
        //                       sr->host_conf->host_signature);

        if(sr->user_agent.data)
                mk_palm_iov_add_header(iov, mk_cgi_http_user_agent, 
                                       sr->user_agent);

        if(sr->accept.data)
                mk_palm_iov_add_header(iov, mk_cgi_http_accept, sr->accept);
        
        if(sr->accept_charset.data)
                mk_palm_iov_add_header(iov, mk_cgi_http_accept_charset, 
                                       sr->accept_charset);

        if(sr->accept_encoding.data)
                mk_palm_iov_add_header(iov, mk_cgi_http_accept_encoding,
                                       sr->accept_encoding);

        if(sr->accept_language.data)
                mk_palm_iov_add_header(iov, mk_cgi_http_accept_language, 
                                       sr->accept_language);

        if(sr->host.data)
                mk_palm_iov_add_header(iov, mk_cgi_http_host, sr->host);

        if(sr->cookies.data)
                mk_palm_iov_add_header(iov, mk_cgi_http_cookie, sr->cookies);

        if(sr->referer.data)
                mk_palm_iov_add_header(iov, mk_cgi_http_referer, sr->referer);
        
        //        mk_palm_iov_add_header(iov, mk_cgi_server_port, mk_monkey_port);
        mk_palm_iov_add_header(iov, mk_cgi_gateway_interface, mk_cgi_version);
        mk_palm_iov_add_header(iov, mk_cgi_remote_addr, cr->ip);
        mk_palm_iov_add_header(iov, mk_cgi_request_uri, sr->uri);
        //mk_palm_iov_add_header(iov, mk_cgi_request_method, sr->method);
        mk_palm_iov_add_header(iov, mk_cgi_script_name, sr->uri);


        /* real path is not an mk_pointer */
        mk_palm_iov_add_header(iov, mk_cgi_script_filename, sr->real_path);
        //mk_palm_iov_add_header(iov, mk_cgi_remote_port, cr->port);
        mk_palm_iov_add_header(iov, mk_cgi_query_string, sr->query_string);
        //mk_palm_iov_add_header(iov, mk_cgi_post_vars, sr->post_variables);

        /* CRLF */
        mk_iov_add_entry(iov, mk_crlf.data, mk_crlf.len, 
                         mk_iov_none, MK_IOV_NOT_FREE_BUF);
        return iov;
}

void mk_palm_iov_add_header(struct mk_iov *iov, 
                            mk_pointer header, mk_pointer value)
{
        mk_iov_add_entry(iov, header.data, header.len, 
                         mk_iov_equal, MK_IOV_NOT_FREE_BUF);
        mk_iov_add_entry(iov, value.data, value.len, 
                         mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
}

int mk_palm_send_response(struct client_request *cr, struct request *sr,
                          char *buf)
{
        int len;
        int i;
        long n;
        char *s;
        char *status_msg = "Status: ";

        len = 8;
        if(strncasecmp(buf, status_msg, len)==0)
        {
                i = mk_string_search(buf+len, " ");
                s = mk_string_copy_substr(buf, len, len+i);
                sr->headers->status = atoi(s); 
                i = mk_string_search(buf, mk_crlf.data) + mk_crlf.len;
        }
        else{
                i = 0;
                sr->headers->status = M_HTTP_OK;
        }

        sr->headers->cgi = SH_CGI;
        sr->headers->content_length = 0;

        mk_socket_set_cork_flag(cr->socket, TCP_CORK_ON);
        mk_header_send(cr->socket, cr, sr, sr->log);
        n = write(cr->socket, buf+i, strlen(buf+i));
        return 0;
}

void mk_palm_set_env()
{
        mk_pointer_set(&mk_cgi_document_root, MK_CGI_DOCUMENT_ROOT);
        mk_pointer_set(&mk_cgi_content_length, MK_CGI_CONTENT_LENGTH);
        mk_pointer_set(&mk_cgi_content_type, MK_CGI_CONTENT_TYPE);
        mk_pointer_set(&mk_cgi_server_addr, MK_CGI_SERVER_ADDR);
        mk_pointer_set(&mk_cgi_server_name, MK_CGI_SERVER_NAME);
        mk_pointer_set(&mk_cgi_server_protocol, MK_CGI_SERVER_PROTOCOL);
        mk_pointer_set(&mk_cgi_server_software, MK_CGI_SERVER_SOFTWARE);
        mk_pointer_set(&mk_cgi_server_signature, MK_CGI_SERVER_SIGNATURE);
        mk_pointer_set(&mk_cgi_http_user_agent, MK_CGI_HTTP_USER_AGENT);
        mk_pointer_set(&mk_cgi_http_accept, MK_CGI_HTTP_ACCEPT);
        mk_pointer_set(&mk_cgi_http_accept_charset, MK_CGI_HTTP_ACCEPT_CHARSET);
        mk_pointer_set(&mk_cgi_http_accept_encoding, MK_CGI_HTTP_ACCEPT_ENCODING);
        mk_pointer_set(&mk_cgi_http_accept_language, MK_CGI_HTTP_ACCEPT_LANGUAGE);
        mk_pointer_set(&mk_cgi_http_host, MK_CGI_HTTP_HOST);
        mk_pointer_set(&mk_cgi_http_cookie, MK_CGI_HTTP_COOKIE);
        mk_pointer_set(&mk_cgi_http_referer, MK_CGI_HTTP_REFERER);
        mk_pointer_set(&mk_cgi_server_port, MK_CGI_SERVER_PORT);
        mk_pointer_set(&mk_cgi_cgi_version, MK_CGI_CGI_VERSION);
        mk_pointer_set(&mk_cgi_gateway_interface, MK_CGI_GATEWAY_INTERFACE);
        mk_pointer_set(&mk_cgi_remote_addr, MK_CGI_REMOTE_ADDR);
        mk_pointer_set(&mk_cgi_request_uri, MK_CGI_REQUEST_URI);
        mk_pointer_set(&mk_cgi_request_method, MK_CGI_REQUEST_METHOD);
        mk_pointer_set(&mk_cgi_script_name, MK_CGI_SCRIPT_NAME);
        mk_pointer_set(&mk_cgi_script_filename, MK_CGI_SCRIPT_FILENAME);
        mk_pointer_set(&mk_cgi_remote_port, MK_CGI_REMOTE_PORT);
        mk_pointer_set(&mk_cgi_query_string, MK_CGI_QUERY_STRING);
        mk_pointer_set(&mk_cgi_post_vars, MK_CGI_POST_VARS);
}
