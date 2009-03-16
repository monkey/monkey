/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2002, Eduardo Silva P.
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
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/resource.h>

#include "monkey.h"
#include "http.h"
#include "http_status.h"
#include "memory.h"
#include "str.h"
#include "utils.h"
#include "config.h"

int User_main(struct client_request *cr, struct request *sr)
{
        int limit, offset;
        char *user=0, *user_server_root=0;
	struct passwd *s_user;
	unsigned long len;

	sr->user_home=VAR_ON;

	user = mk_mem_malloc(strlen(sr->uri_processed) + 1);
	offset=strlen(USER_HOME_STRING);	
	limit=mk_string_search(sr->uri_processed+offset, "/");

	if(limit==-1)
		limit=strlen(sr->uri_processed) - offset ;

	strncpy(user, sr->uri_processed+offset, limit);	
	user[limit]='\0';
	
	if(sr->uri.data[offset+limit]=='/')
	{
                m_build_buffer(&sr->uri.data, &sr->uri.len,
                               "%s", sr->uri_processed+offset+limit);

                /* Extract URI portion after /~user */
                sr->user_uri = (char*)mk_mem_malloc_z(sr->uri.len + 1);
                char* src = sr->uri.data;
                char* dst = sr->user_uri;

                while (*src != ' ' && src < (sr->uri.data + sr->uri.len)){
                        *dst++ = *src++;
                }
	}

	if((s_user=getpwnam(user))==NULL){
		mk_mem_free(user);
		mk_request_error(M_CLIENT_NOT_FOUND, cr, sr,1,sr->log);
		return -1;
	}
	mk_mem_free(user);
	
	m_build_buffer(&user_server_root, &len, "%s/%s",s_user->pw_dir, config->user_dir);

	if(sr->user_uri!=NULL)
	{
		m_build_buffer(&sr->real_path.data, &sr->real_path.len, "%s%s",
                               user_server_root, sr->user_uri);
	}
	else
	{
		m_build_buffer(&sr->real_path.data, &sr->real_path.len, "%s",
                               user_server_root);
	}
	mk_mem_free(user_server_root);
	return 0;
}

/* Cambia el usuario del proceso */
int mk_user_set_uidgid()
{
   struct passwd   *usr;

   EGID=(gid_t) getegid();
   EUID=(gid_t) geteuid();
   
   if(geteuid()==0 && config->user) {            /* Lanzado por root ?? */
		struct rlimit rl;
		
		/* Just if i'm superuser */
		rl.rlim_max= (256 * config->maxclients);
		rl.rlim_cur = rl.rlim_max;
	    setrlimit( RLIMIT_NOFILE, &rl );
    
      /* Chequear si existe el usuario USER ... */
      if ((usr = getpwnam( config->user )) == NULL) {
         printf("Error: Invalid user '%s'\n", config->user);
         exit(1);
      }
      /* Cambiar el UID y el GID del proceso */
      if(setegid(usr->pw_gid)==-1) {
         printf("I can't change the GID to %u\n", usr->pw_gid);
         exit(1);
      }

      if(seteuid(usr->pw_uid)==-1) {
         printf("I can't change the UID to %u\n", usr->pw_uid);
         exit(1);
      }

   }
   return 0;
}

/* Vuelve el proceso a su usuario original */
int mk_user_undo_uidgid()
{
	if(EUID==0){
		setegid(EGID);
		seteuid(EUID);
	}
	return 0;
}
