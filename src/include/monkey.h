/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2003, Eduardo Silva P.
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

#ifndef _MONKEY_H
#define _MONKEY_H

#include <pthread.h>
#include <netinet/in.h>

/* Sockets*/
struct sockaddr_in remote;

int local_fd;

/* CONSTANTES DEL SERVIDOR */
#define MAX_REQUEST_BODY 10240 /* Maximo buffer del request */
#define BUFFER_SOCKET 4096 /* Maximo buffer de envio */

#define MAX_PATH 1024 /* Largo máximo para rutas (archivos) */

/* METODOS */
#define GET_METHOD 	 (0)
#define POST_METHOD	(1)
#define HEAD_METHOD   (2)
#define METHOD_NOT_ALLOWED  (-1)
#define METHOD_NOT_FOUND	(-2)
#define METHOD_EMPTY	(-3)

/* String que define la llamada a 
un home de un usuario */
#define USER_HOME_STRING "/~"

/* Socket_Timeout() */
#define ST_RECV 0
#define ST_SEND 1

/* Send_Header(...,int cgi) */
#define SH_NOCGI 0
#define SH_CGI 1

/* Status para struct s_log */
#define S_LOG_ON 0
#define S_LOG_OFF 1

/* Valores para distintas variables */
#define VAR_NOTSET -1
#define VAR_ON 0
#define VAR_OFF 1

/* Cantidad maxima de ciclos del 
loop recibiendo una peticion en request.c */
#define RECV_MAX_TIMES 10000

/* Contador de requests en proceso */
int thread_counter;

/* Thread mutexes */
pthread_mutex_t  mutex_thread_list;
pthread_mutex_t  mutex_thread_counter;
pthread_mutex_t  mutex_cgi_child;
pthread_mutex_t  mutex_logfile;

/* Usuario real que que ejecuto
 el servidor */
gid_t EGID;
gid_t EUID;

/* Functions and data types */
#include "http_status.h"

#include "request.h"
#include "method.h"
#include "cgi.h"
#include "process.h"
#include "user.h"
#include "info.h"
#include "support.h"
#include "utils.h"
#include "mimetype.h"
#include "logfile.h"
#include "dir_html.h"
#include "deny.h"
#include "signals.h"
#include "vhost.h"
#include "config.h"
#include "chars.h"

#include "modules.h"

void free_request(struct request *sr);

#endif

