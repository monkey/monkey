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
 
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "monkey.h"

#include "str.h"
#include "memory.h"
#include "http.h"
#include "http_status.h"
//#include "header.h"
#include "socket.h"
#include "logfile.h"
#include "config.h"
#include "utils.h"
#include "file.h"

/* POST METHOD */
int M_METHOD_Post(struct client_request *cr, struct request *s_request)
{
	/*
	char *tmp;
	char buffer[MAX_REQUEST_BODY];
	int content_length_post=0;
	
	if(!(tmp=Request_Find_Variable(s_request->body, RH_CONTENT_LENGTH))){
		Request_Error(M_CLIENT_LENGHT_REQUIRED, cr, s_request,0,s_request->log);
		return -1;
	}

	content_length_post = (int) atoi(tmp);
	mk_mem_free(tmp);

	if(content_length_post<=0 || content_length_post >=MAX_REQUEST_BODY){
		Request_Error(M_CLIENT_BAD_REQUEST, cr, s_request, 0, s_request->log);	
		return -1;
	}
	
	if(!(tmp = Request_Find_Variable(s_request->body, RH_CONTENT_TYPE))){
		Request_Error(M_CLIENT_BAD_REQUEST, cr, s_request, 0, s_request->log);
		return -1;
	}
	
	s_request->content_type = tmp;

	if(s_request->post_variables==NULL || strlen(s_request->post_variables)<=4) {
		s_request->post_variables=NULL;
		return -1;
	}

	if(strlen(s_request->post_variables) < content_length_post){
		content_length_post=strlen(buffer);
	}

	s_request->content_length=content_length_post;
	*/
	return 0;
	
}

/* Reuturn the POST variables sent in the request */
char *M_Get_POST_Vars(char *request, int index, char *strend)
{
    int i=index;
    int length, length_string_end;
    int last_byte = 1;

    length = strlen(request);
    length_string_end = strlen(strend);
    if(length_string_end == 2)
    {
        last_byte = 0;
    }

    for(i=index; i<=length; i++)
    {
        if(strncmp(request+i, strend, length_string_end)==0)
        {
            break;
        }
    }
    return mk_string_copy_substr(request, index, i-last_byte);
}



