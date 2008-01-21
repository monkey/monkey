/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2007, Eduardo Silva P.
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

struct client_request
{
    int pipelined; /* Pipelined request */
    int socket;
    int  counter_connections; /* Count persistent connections */
    char *body; /* Original request sent */
    struct request *request; /* Parsed request */
};

struct request {

	int status;	/* Request Status, ON, OFF */
    int pipelined; /* Pipelined request */
    char *body;

	/*----First header of client request--*/
	int method;
	char *uri;  /* Request original */
	char *uri_processed; /* Request procesado */
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

	char *real_path; /* Path real al que se realiza la petici�n */
	char *temp_path; /* Variable temporal para trabajar con 
						Virtualhost en request. */

	char *user_uri; /* Lo que queda despues del /~user/.... */
	char *query_string; /* ?... */

	char *virtual_user; /* Usuario del proceso para un Virtualhost */
	char *scriptalias[MAX_SCRIPTALIAS]; /* Arreglo que mantiene info de peticion a un Virtualhost */
	char *script_filename;

	char *server_signature;
	
	int  getdir; 
	
	int  keep_alive;	
	int  user_home; /* � Peticion a un home de usuario ? (VAR_ON/VAR_OFF) */

	/*-Connection-*/
	int  port;
	/*------------*/
	
	int make_log;
	int cgi_pipe[2];
		
	struct log_info *log; /* Request Log */
	struct header_values *headers; /* headers response */
    struct request *next;
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

int Request_Main(struct client_request *s_request);
int	Socket_Timeout(int s, char *buf, int len, int timeout, int recv_send);
int	Get_method_from_request(char *request);
char	*FindIndex(char *pathfile);
char	*Set_Page_Default(char *title,  char *message, char *signature);
char	*Request_Find_Variable(char *request_body, char *string);
void	Request_Error(int num_error, struct request *s_request, int debug, struct log_info *s_log);
struct request	*Request_Strip_Header(struct request *sr, char *request_body);
struct request *alloc_request();

