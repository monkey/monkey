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
 
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include "monkey.h"


/* Close socket and delete thread info from register */
int FreeThread(pthread_t thread)
{
	struct process *aux=0, *aux2=0;
	
	pthread_mutex_lock(&mutex_thread_list);
	
	aux=first_process;
	while(aux!=NULL){
		if(pthread_equal(aux->thread_pid, thread)!=0){
			close(aux->socket);
			free_list_requests(aux->cr);
			if(first_process==aux){
				first_process=first_process->next;
				M_free(aux);
				aux = first_process;
				continue;
			}
			else{
				aux2=first_process;
				while(aux2->next!=aux)
					aux2=aux2->next;
				aux2->next=aux->next;
				M_free(aux);
				aux=NULL;
				break;
			}
		}	
		aux=aux->next;	
	}	

	/* Searching for childrens */
	M_CGI_free_childs(thread, M_CGI_CHILD_EXIT_FAIL);
	
	/* Mutex thread_counter */
	pthread_mutex_lock(&mutex_thread_counter);
	thread_counter--;
	pthread_mutex_unlock(&mutex_thread_counter);
	/* End thread_counter -- */
	
	pthread_mutex_unlock(&mutex_thread_list);
	return 0;
}
