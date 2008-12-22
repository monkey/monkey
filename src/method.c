/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

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
#include "socket.h"
#include "logfile.h"
#include "config.h"
#include "utils.h"
#include "file.h"

long int mk_method_post_content_length(char *body)
{
        long int len;
        mk_pointer tmp;

        tmp = mk_request_header_find(body, mk_rh_content_length);
        if(!tmp.data)
        {
                return -2;
        }
	
        len = atoi(tmp.data);
        
        return len;
}


/* POST METHOD */
int M_METHOD_Post(struct client_request *cr, struct request *sr)
{
	mk_pointer tmp;
	char buffer[MAX_REQUEST_BODY];
	long content_length_post=0;
	
        content_length_post = mk_method_post_content_length(cr->body);
	if(content_length_post == -2)
        {
		mk_request_error(M_CLIENT_LENGHT_REQUIRED, 
                              cr, sr, 0, sr->log);
		return -1;
	}

	if(content_length_post<=0 || content_length_post >=MAX_REQUEST_BODY){
		mk_request_error(M_CLIENT_BAD_REQUEST, 
                              cr, sr, 0, sr->log);	
		return -1;
	}
	
        tmp = mk_request_header_find(sr->body.data, mk_rh_content_type);
        if(!tmp.data){
		mk_request_error(M_CLIENT_BAD_REQUEST, 
                              cr, sr, 0, sr->log);
		return -1;
	}
	sr->content_type = tmp;

	if(sr->post_variables.len < content_length_post){
		content_length_post=strlen(buffer);
	}

	sr->content_length=content_length_post;
	
	return 0;
	
}

/* Return POST variables sent in request */
mk_pointer mk_method_post_get_vars(char *body, int index)
{
        long len=1;
        char *str=0;
        mk_pointer p;

        str = mk_string_copy_substr(body, index, strlen(body));
        if(str)
        {
                len = strlen(str);
        }

        p.data = str;
        p.len = len;

        return p;
}
