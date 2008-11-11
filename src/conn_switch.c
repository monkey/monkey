/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2008, Eduardo Silva P.
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

#include "monkey.h"
#include "http.h"
#include "conn_switch.h"
#include "scheduler.h"
#include "epoll.h"
#include "request.h"

#include <string.h>
#include <stdio.h>

int mk_conn_switch_read(int socket)
{
	int ret;

	ret = mk_handler_read(socket);
	return ret;
}

int mk_conn_switch_write(int socket)
{
	int ret=-1, ka, efd;
	struct client_request *cr;

	/* Get node from schedule list node which contains
	 * the information regarding to the current client/socket
	 */
	cr = mk_request_client_get(socket);
	
	if(!cr)
	{
		return -1;
	}

	ret = mk_handler_write(socket, cr);
	ka = mk_http_keepalive_check(socket, cr);

	/* if ret < 0, means that some error
	 * happened in the writer call, in the
	 * other hand, 0 means a successful request
	 * processed, if ret > 0 means that some data
	 * still need to be send.
	 */

	if(ret <= 0)
	{
		mk_request_free_list(cr);
	
		/* We need to ask to http_keepalive if this 
		 * connection can continue working or we must 
		 * close it.
		 */

		if(ka<0 || ret<0)
		{
			mk_request_client_remove(socket);
			return -1;
		}
		else{
			memset(cr->body, '\0', sizeof(cr->body));
			cr->body_length = 0;
			cr->counter_connections++;
			efd = mk_sched_get_thread_poll();
			mk_epoll_socket_change_mode(efd, socket, MK_EPOLL_READ);
			return 0;
		}
	}
	else if(ret > 0)
	{
		return 0;
	}

	/* avoid to make gcc cry :_( */
	return -1;
}

int mk_conn_switch(int action, int socket)
{
	int status=-1; 
	
	switch(action)
	{
		case MK_CONN_SWITCH_READ:
			status = mk_conn_switch_read(socket);
			break;
		case MK_CONN_SWITCH_WRITE:
			status = mk_conn_switch_write(socket);
			break;
	}

	return status;
}


