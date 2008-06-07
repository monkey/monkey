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

/* Handle index file names: index.* */
#define MAX_INDEX_NOMBRE 50
struct indexfile {
	char indexname[MAX_INDEX_NOMBRE];		
	struct indexfile *next;	
} *first_index;

#define NORMAL_STRING_END "\r\n\r\n"
#define LEN_NORMAL_STRING_END 4

#define OLD_STRING_END "\n\n"
#define LEN_OLD_STRING_END 2

#define CRLF "\r\n"
#define CRLF_LEN 2

/* Headers */
#define RH_ACCEPT "Accept:"
#define RH_ACCEPT_CHARSET	"Accept-Charset:"
#define RH_ACCEPT_ENCODING	"Accept-Encoding:"
#define RH_ACCEPT_LANGUAGE	"Accept-Language:"
#define RH_CONNECTION	"Connection:"
#define RH_COOKIE	"Cookie:"
#define RH_CONTENT_LENGTH	"Content-Length:"
#define RH_CONTENT_RANGE	"Content-Range:"
#define RH_CONTENT_TYPE	"Content-type:"
#define RH_IF_MODIFIED_SINCE "If-Modified-Since:"
#define RH_HOST	"Host:"
#define RH_LAST_MODIFIED "Last-Modified:"
#define RH_LAST_MODIFIED_SINCE "Last-Modified-Since:"
#define RH_REFERER	"Referer:"
#define RH_RANGE	"Range:"
#define RH_USER_AGENT	"User-Agent:"

/* Aqui se registran temporalmente los 
parametros de una peticion */
#define MAX_REQUEST_METHOD 10
#define MAX_REQUEST_URI 1025
#define MAX_REQUEST_PROTOCOL 10
#define MAX_SCRIPTALIAS 3

#define EXIT_NORMAL -1
#define EXIT_PCONNECTION 24

/* 
 * Every client request has the status of the process, 
 * we handle it with different values.
 */
#define MK_REQ_STAT_WAITING 0 // Not attended
#define MK_REQ_STAT_READING 1 // Reading client request 
#define MK_REQ_STAT_READING_DONE 2 // Reading request has done
#define MK_REQ_STAT_PROCESSING 3 // Processing readed data
#define MK_REQ_STAT_PROCESSING_DONE 4 // Processing data has done
#define MK_REQ_STAT_WRITING 5 // Writing response to client
#define MK_REQ_STAT_WRITING_DONE 6 // Writing process has done

struct client_request
{
    int pipelined; /* Pipelined request */
    int socket;
    int  counter_connections; /* Count persistent connections */
    int status; /* Request status */
   
    char *body; /* Original request sent */
    char *client_ip;
    int body_length;
    struct request *request; /* Parsed request */
    struct client_request *next;
};

pthread_key_t request_handler;

struct request {

	int status;
	int pipelined; /* Pipelined request */
	char *body;

	/*----First header of client request--*/
	int method;
	char *method_str;
	char *uri;  /* original request */
	char *uri_processed; /* processed request */
	int protocol;
	/*------------------*/

	/*---Request headers--*/
	int  content_length;
	char *accept;
	char *accept_language;
	char *accept_encoding;
	char *accept_charset;
	char *content_type;
	char *connection;	
	char *cookies; 
	char *host;
	char *if_modified_since;
	char *last_modified_since;
	char *range;
	char *referer;
	char *resume;
	char *user_agent;	
	char *post_variables;
	/*-----------------*/

	/*-Internal-*/
	char *real_path; /* Absolute real path */
	char *user_uri; /* ~user/...path */
	char *query_string; /* ?... */

	char *virtual_user; /* Virtualhost user */
	char *script_filename;
	int  keep_alive;	
	int  user_home; /* user_home request(VAR_ON/VAR_OFF) */

	/*-Connection-*/
	int  port;
	/*------------*/
	
	int make_log;
	int cgi_pipe[2];

	struct host *host_conf;
	struct log_info *log; /* Request Log */
	struct header_values *headers; /* headers response */
	struct request *next;

	size_t bytes_to_send;
	size_t bytes_offset;
};

struct header_values {
	int status;
	int content_length;	
	int cgi;
	int pconnections_left;
	int range_values[2];
		
	char *content_type;
	char *last_modified;
	char *location;
};

int Get_Request(struct client_request *s_request);
int Process_Request(struct client_request *cr, struct request *s_request);
int Process_Request_Header(struct request *sr);

int	Socket_Timeout(int s, char *buf, int len, int timeout, int recv_send);
int	Get_method_from_request(char *request);
char	*FindIndex(char *pathfile);
char	*Set_Page_Default(char *title,  char *message, char *signature);
char	*Request_Find_Variable(char *request_body, char *string);
void Request_Error(int num_error, struct client_request *cr, 
                   struct request *s_request, int debug, struct log_info *s_log);
int Validate_Request_Header(char *buf);

struct request *alloc_request();
void free_list_requests(struct client_request *cr);
void free_request(struct request *sr);

struct client_request *mk_create_client_request(int socket);
struct client_request *mk_get_client_request_from_fd(int socket);
struct client_request *mk_remove_client_request(int socket);

int mk_handler_read(int socket);
int mk_handler_write(int socket);

