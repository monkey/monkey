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

#ifndef MK_MONKEY_H
#define MK_MONKEY_H

#include <pthread.h>
#include <netinet/in.h>
#include "memory.h"

int server_fd;

/* Max buf length sent by client */
#define MAX_REQUEST_BODY 1024
/* Max Path lenth */
#define MAX_PATH 1024

/* Send_Header(...,int cgi) */
#define SH_NOCGI 0
#define SH_CGI 1

#define VAR_ERR -2
#define VAR_NOTSET -1
#define VAR_ON 0
#define VAR_OFF 1


/* Thread mutexes */
pthread_mutex_t mutex_thread_list;
pthread_mutex_t mutex_thread_counter;
pthread_mutex_t mutex_cgi_child;
pthread_mutex_t mutex_logfile;
pthread_mutex_t mutex_wait_register;

mk_pointer mk_monkey_protocol;
mk_pointer mk_monkey_port;

/* Process UID/GID */
gid_t EGID;
gid_t EUID;

#endif
