/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P. <edsiper@gmail.com>
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

#define MK_REQUEST_DEFAULT_PAGE  "<HTML><BODY><H1>%s</H1>%s<BR><HR><ADDRESS>%s</ADDRESS></BODY></HTML>"

/* Handle index file names: index.* */
#define MAX_INDEX_NOMBRE 50
struct indexfile
{
    char indexname[MAX_INDEX_NOMBRE];
    struct indexfile *next;
}        *first_index;

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

struct request_idx
{
    struct client_request *first;
    struct client_request *last;
};

struct client_request
{
    int pipelined;              /* Pipelined request */
    int socket;
    int counter_connections;    /* Count persistent connections */
    int status;                 /* Request status */
    char *body;                 /* Original request sent */

    mk_pointer *ipv4;

    int body_length;

    int body_pos_end;
    int first_method;

    time_t init_time;
    struct request *request;    /* Parsed request */
    struct client_request *next;
};

pthread_key_t request_index;

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

struct request
{
    int status;

    int pipelined;              /* Pipelined request */
    mk_pointer body;

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
    char *script_filename;
    int keep_alive;
    int user_home;              /* user_home request(VAR_ON/VAR_OFF) */
    
    /*-Connection-*/
    int port;
    /*------------*/
    
    /* file descriptors */
    int fd_file;

    struct file_info *file_info;
    struct host *host_conf;
    struct header_values *headers;      /* headers response */
    struct request *next;

    long loop;
    long bytes_to_send;
    off_t bytes_offset;

    /* Plugin handlers */
    struct plugin *handled_by;
};

struct header_values
{
    int status;
    mk_pointer *status_p;

    long content_length;
    mk_pointer content_length_p;

    int cgi;
    int pconnections_left;
    int ranges[2];
    int transfer_encoding;
    int breakline;

    mk_pointer content_type;
    mk_pointer last_modified;
    char *location;
};

struct request *mk_request_parse(struct client_request *cr);
int mk_request_process(struct client_request *cr, struct request *s_request);
mk_pointer mk_request_index(char *pathfile);


/* Custom HTML Page for errors */
mk_pointer *mk_request_set_default_page(char *title, mk_pointer message,
                                        char *signature);

int mk_request_header_process(struct request *sr);
mk_pointer mk_request_header_find(struct header_toc *toc, int toc_len,
                                  char *request_body, mk_pointer header);

void mk_request_error(int http_status, struct client_request *cr,
                      struct request *sr, int debug);

struct request *mk_request_alloc();
void mk_request_free_list(struct client_request *cr);
void mk_request_free(struct request *sr);

struct client_request *mk_request_client_create(int socket);
struct client_request *mk_request_client_get(int socket);
void mk_request_client_remove(int socket);

void mk_request_init_error_msgs();

int mk_handler_read(int socket, struct client_request *cr);
int mk_handler_write(int socket, struct client_request *cr);


struct header_toc *mk_request_header_toc_create(int len);
void mk_request_header_toc_parse(struct header_toc *toc, int toc_len,
                                 char *data, int len);

void mk_request_ka_next(struct client_request *cr);
#endif
