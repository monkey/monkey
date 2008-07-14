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

#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include "socket.h"

/* 
 * Example from:
 * http://www.baus.net/on-tcp_cork
 */
int mk_socket_set_cork_flag(int fd, int state)
{
	return setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
}

int mk_socket_set_nonblocking(int sockfd)
{
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0)|O_NONBLOCK) == -1) {
        perror("fcntl");
	return -1;
    }
    return 0;
}

char *mk_socket_get_ip(int socket)
{
	struct sockaddr_in m_addr;
	socklen_t len;

	len = sizeof(m_addr);
	getpeername(socket, (struct sockaddr*)&m_addr, &len);

	return inet_ntoa(m_addr.sin_addr);
}

int mk_socket_close(int socket)
{
	return close(socket);
}

int mk_socket_timeout(int s, char *buf, int len, 
		int timeout, int recv_send)
{
	fd_set fds;
	time_t init_time, max_time;
	int n=0, status;
	struct timeval tv;

	init_time=time(NULL);
	max_time = init_time + timeout;

	FD_ZERO(&fds);
	FD_SET(s,&fds);
	
	tv.tv_sec=timeout;
	tv.tv_usec=0;

	if(recv_send==ST_RECV)
		n=select(s+1,&fds,NULL,NULL,&tv);  // recv 
	else{
		n=select(s+1,NULL,&fds,NULL,&tv);  // send 
	}

	switch(n){
		case 0:
				return -2;
				break;
		case -1:
				//pthread_kill(pthread_self(), SIGPIPE);
				return -1;
	}
	
	if(recv_send==ST_RECV){
		status=recv(s,buf,len, 0);
	}
	else{
		status=send(s,buf,len, 0);
	}

	if( status < 0 ){
		if(time(NULL) >= max_time){
			//pthread_kill(pthread_self(), SIGPIPE);
		}
	}
	
	return status;
}

