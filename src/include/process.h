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

/* process.c */

#define P_NORMAL_EXIT	0
#define P_BROKEN_PIPE	1

/* Struct to register info about thread childs (clients) */
struct process {
	pthread_t	thread_pid;
	int 	socket;
	char *ip_client;
	struct request *sr;
	struct process *next;
} *first_process;

struct process *RegProc(pthread_t thread, int socket);
int	FreeThread(pthread_t thread);

