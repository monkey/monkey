/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P. <edsiper@gmail.com>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/* request.c */

#include "memory.h"
#include "scheduler.h"

#ifndef MK_REQUEST_H
#define MK_REQUEST_H


/* Request buffer chunks = 4KB */
#define MK_REQUEST_CHUNK (int) 4096
#define MK_REQUEST_DEFAULT_PAGE  "<HTML><HEAD><STYLE type=\"text/css\"> body {font-size: 12px;} </STYLE></HEAD><BODY><H1>%s</H1>%s<BR><HR><ADDRESS>Powered by %s</ADDRESS></BODY></HTML>"

#define MK_CRLF "\r\n"
#define MK_ENDBLOCK "\r\n\r\n"

mk_pointer mk_crlf;
mk_pointer mk_endblock;

/* Headers */
#define RH_ACCEPT "Accept:"
#define RH_ACCEPT_CHARSET "Accept-Charset:"
#define RH_ACCEPT_ENCODING "Accept-Encoding:"
#define RH_ACCEPT_LANGUAGE "Accept-Language:"
#define RH_CONNECTION "Connection:"
#define RH_COOKIE "Cookie:"
#define RH_CONTENT_LENGTH "Content-Length:"
#define RH_CONTENT_RANGE "Content-Range:"
#define RH_CONTENT_TYPE	"Content-type:"
#define RH_IF_MODIFIED_SINCE "If-Modified-Since:"
#define RH_HOST	"Host:"
#define RH_LAST_MODIFIED "Last-Modified:"
#define RH_LAST_MODIFIED_SINCE "Last-Modified-Since:"
#define RH_REFERER "Referer:"
#define RH_RANGE "Range:"
#define RH_USER_AGENT "User-Agent:"

mk_pointer mk_rh_accept;
mk_pointer mk_rh_accept_charset;
mk_pointer mk_rh_accept_encoding;
mk_pointer mk_rh_accept_language;
mk_pointer mk_rh_connection;
mk_pointer mk_rh_cookie;
mk_pointer mk_rh_content_length;
mk_pointer mk_rh_content_range;
mk_pointer mk_rh_content_type;
mk_pointer mk_rh_if_modified_since;
mk_pointer mk_rh_host;
mk_pointer mk_rh_last_modified;
mk_pointer mk_rh_last_modified_since;
mk_pointer mk_rh_referer;
mk_pointer mk_rh_range;
mk_pointer mk_rh_user_agent;

/* Aqui se registran temporalmente los 
parametros de una peticion */
#define MAX_REQUEST_METHOD 10
#define MAX_REQUEST_URI 1025
#define MAX_REQUEST_PROTOCOL 10
#define MAX_SCRIPTALIAS 3

#define MK_REQUEST_STATUS_INCOMPLETE -1
#define MK_REQUEST_STATUS_COMPLETED 0

#define EXIT_NORMAL 0
#define EXIT_ERROR -1
#define EXIT_ABORT -2
#define EXIT_PCONNECTION 24

#define MK_HEADERS_TOC_LEN 32

struct client_session
{
    int pipelined;              /* Pipelined request */
    int socket;
    int counter_connections;    /* Count persistent connections */
    int status;                 /* Request status */
    char *body;                 /* Original request sent */

    mk_pointer *ipv4;

    int body_size;
    int body_length;

    int body_pos_end;
    int first_method;

    time_t init_time;

    struct mk_list request_list;
    struct mk_list _head;
};

pthread_key_t request_list;

struct header_toc
{
    char *init;
    char *end;
    int status;                 /* 0: not found, 1: found = skip! */
    struct header_toc *next;
};

/* Request plugin Handler, each request can be handled by 
 * several plugins, we handle list in a simple list */
struct handler
{
    struct plugin *p;
    struct handler *next;
};

struct session_request
{
    int status;

    int pipelined;              /* Pipelined request */
    mk_pointer body;

    /* HTTP Headers Table of Content */ 
    struct header_toc headers_toc[MK_HEADERS_TOC_LEN];
    int headers_len;
    

    /*----First header of client request--*/
    int method;
    mk_pointer method_p;
    mk_pointer uri;             /* original request */
    char *uri_processed;        /* processed request */
    int uri_twin;

    int protocol;
    mk_pointer protocol_p;

    /* If request specify Connection: close, Monkey will
     * close the connection after send the response, by
     * default this var is set to VAR_OFF;
     */
    int close_now;

    /*---Request headers--*/
    int content_length;

    mk_pointer accept;
    mk_pointer accept_language;
    mk_pointer accept_encoding;
    mk_pointer accept_charset;

    mk_pointer content_type;
    mk_pointer connection;
    mk_pointer cookies;

    mk_pointer host;
    mk_pointer host_port;
    mk_pointer if_modified_since;
    mk_pointer last_modified_since;
    mk_pointer range;
    mk_pointer referer;
    mk_pointer resume;
    mk_pointer user_agent;

    /*---------------------*/
    
    /* POST */
    mk_pointer post_variables;
    /*-----------------*/

    /*-Internal-*/
    mk_pointer real_path;       /* Absolute real path */
    char *user_uri;             /* ~user/...path */
    mk_pointer query_string;    /* ?... */

    char *virtual_user;         /* Virtualhost user */

    int keep_alive;
    int user_home;              /* user_home request(VAR_ON/VAR_OFF) */
    
    /*-Connection-*/
    long port;
    /*------------*/
    
    /* file descriptors */
    int fd_file;

    struct file_info *file_info;
    struct host *host_conf;
    struct response_headers *headers;      /* headers response */

    long loop;
    long bytes_to_send;
    off_t bytes_offset;

    /* Plugin handlers */
    struct plugin *handled_by;

    struct mk_list _head;
};

struct response_headers
{
    int status;

    /* Length of the content to send */
    long content_length;

    /* Private value, real length of the file requested */
    long real_length;

    int cgi;
    int pconnections_left;
    int ranges[2];
    int transfer_encoding;
    int breakline;

    time_t last_modified;
    mk_pointer content_type;
    mk_pointer content_encoding;
    char *location;

    /* 
     * This field allow plugins to add their own response
     * headers
     */
    struct mk_iov *_extra_rows;
};

mk_pointer mk_request_index(char *pathfile);


/* Custom HTML Page for errors */
mk_pointer mk_request_header_find(struct header_toc *toc, const char *request_body, 
                                  mk_pointer header);

void mk_request_error(int http_status, struct client_session *cs, 
                      struct session_request *sr);

void mk_request_free_list(struct client_session *cs);

struct client_session *mk_session_create(int socket);
struct client_session *mk_session_get(int socket);
void mk_session_remove(int socket);

void mk_request_init_error_msgs(void);

int mk_handler_read(int socket, struct client_session *cs);
int mk_handler_write(int socket, struct client_session *cs);

void mk_request_header_toc_init(struct header_toc *toc);

void mk_request_ka_next(struct client_session *cs);
#endif
