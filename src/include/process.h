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

/* process.c */

#define P_NORMAL_EXIT	0
#define P_BROKEN_PIPE	1

/* Struct to register info about the thread childs (clients) */
struct process
{
    pthread_t thread_pid;
    int socket;
    char *ip_client;
    struct client_request *cr;
    struct process *next;
}      *first_process;

struct process *RegProc(pthread_t thread, int socket);
int FreeThread(pthread_t thread);
