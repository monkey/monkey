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

#define M_CGI_OK 0
#define M_CGI_TIMEOUT -2
#define M_CGI_INTERNAL_SERVER_ERR -3
#define M_CGI_PIPE_ERR -4

#define M_CGI_CHILD_EXIT_OK	0
#define M_CGI_CHILD_EXIT_FAIL	-1

/* Struct to keep PID childs */
struct cgi_child {
	pthread_t	thread_pid;
	pid_t	pid;
	struct cgi_child *next;
} *cgi_child_index;

/* cgi.c */
int M_CGI_main(struct client_request *cr, struct request *sr, 
                        struct log_info *s_log, char *remote_request);
int M_CGI_run(struct client_request *cr, struct request *sr, 
                        char *script_filename, char **args);
int M_CGI_send(int socket, int cgi_pipe, struct request *sr, 
                        int persistent_connections_left, int remote_protocol);

int M_CGI_change_dir(char *script);
char *M_CGI_env_add_var(char *name, const char *value);
char *M_CGI_alias(char *path, char *query, char *newstring );
char **M_CGI_env_set_basic(struct request *s_request);

/* Childs managment */
int	M_CGI_register_child(pthread_t thread, pid_t pid);
int	M_CGI_free_childs(pthread_t thread, int exit_type);
