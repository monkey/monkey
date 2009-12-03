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

/* request.c */

#include "memory.h"
#include "scheduler.h"

#ifndef MK_REQUEST_H
#define MK_REQUEST_H

#define MK_REQUEST_DEFAULT_PAGE  "<HTML><BODY><H1>%s</H1>%s<BR><HR><ADDRESS>%s</ADDRESS></BODY></HTML>"

/* Handle index file names: index.* */
#define MAX_INDEX_NOMBRE 50
struct indexfile {
	char indexname[MAX_INDEX_NOMBRE];		
	struct indexfile *next;	
} *first_index;

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

#define EXIT_NORMAL -1
#define EXIT_PCONNECTION 24

/* Request error messages for log file */
#define ERROR_MSG_400 "[error 400] Bad Request" 
#define ERROR_MSG_403 "[error 403] Forbidden"
#define ERROR_MSG_404 "[error 404] Not Found"
#define ERROR_MSG_405 "[error 405] Method Not Allowed"
#define ERROR_MSG_408 "[error 408] Request Timeout"
#define ERROR_MSG_411 "[error 411] Length Required"
#define ERROR_MSG_500 "[error 500] Internal Server Error"
#define ERROR_MSG_501 "[error 501] Not Implemented"
#define ERROR_MSG_505 "[error 505] HTTP Version Not Supported"

/* mk pointers with error messages */
mk_pointer request_error_msg_400;
mk_pointer request_error_msg_403;
mk_pointer request_error_msg_404;
mk_pointer request_error_msg_405;
mk_pointer request_error_msg_408;
mk_pointer request_error_msg_411;
mk_pointer request_error_msg_500;
mk_pointer request_error_msg_501;
mk_pointer request_error_msg_505;

struct request_idx
{
        struct client_request *first;
        struct client_request *last;
};

struct client_request
{
        int pipelined; /* Pipelined request */
        int socket;
        int counter_connections; /* Count persistent connections */
        int status; /* Request status */
        char *body; /* Original request sent */

        mk_pointer ip;
        mk_pointer port;

        int body_length;
        
        int first_block_end;
        int first_method;

        time_t init_time;
        struct request *request; /* Parsed request */
        struct client_request *next;
};

pthread_key_t request_index;

struct header_toc {
        char *init;
        char *end;
        int status; /* 0: not found, 1: found = skip! */
        struct header_toc *next;
};

struct request {
	int status;
	int pipelined; /* Pipelined request */
	mk_pointer body;

	/*----First header of client request--*/
	int method;
	mk_pointer method_p;
	mk_pointer uri;  /* original request */
	char *uri_processed; /* processed request */
	int uri_twin;

	int protocol;
        /*------------------*/

	/*---Request headers--*/
	int  content_length;
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
	mk_pointer real_path; /* Absolute real path */
	char *user_uri; /* ~user/...path */
	mk_pointer query_string; /* ?... */

	char *virtual_user; /* Virtualhost user */
	char *script_filename;
	int  keep_alive;	
	int  user_home; /* user_home request(VAR_ON/VAR_OFF) */

	/*-Connection-*/
	int  port;
	/*------------*/
	
	int make_log;
	int cgi_pipe[2];

	/* file descriptors */
	int fd_file;

        struct file_info *file_info;
	struct host *host_conf;
	struct log_info *log; /* Request Log */
	struct header_values *headers; /* headers response */
	struct request *next;

        long loop;
	long bytes_to_send;
        off_t bytes_offset;
};

struct header_values {
	int status;

	int content_length;	
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
mk_pointer *mk_request_set_default_page(char *title, mk_pointer message, char *signature);

int mk_request_header_process(struct request *sr);
mk_pointer mk_request_header_find(struct header_toc *toc, int toc_len,
                                  char *request_body, mk_pointer header);

void mk_request_error(int num_error, struct client_request *cr, 
                   struct request *s_request, int debug, 
		   struct log_info *s_log);

struct request *mk_request_alloc();
void mk_request_free_list(struct client_request *cr);
void mk_request_free(struct request *sr);

struct client_request *mk_request_client_create(int socket);
struct client_request *mk_request_client_get(int socket);
struct client_request *mk_request_client_remove(int socket);

void mk_request_init_error_msgs();

int mk_handler_read(int socket, struct client_request *cr);
int mk_handler_write(int socket, struct client_request *cr);


struct header_toc *mk_request_header_toc_create(int len);
void mk_request_header_toc_parse(struct header_toc *toc, char *data, int len);

void mk_request_ka_next(struct client_request *cr);
#endif
