/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2007, Eduardo Silva P.
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "monkey.h"
 
int VHOST_Config_Add(char *vhost_servername, char  *vhost_documentroot,
									char *vhost_cgi_alias, char  *vhost_cgi_path, int getdir)
{

	struct host *new_vhost, *aux_vhost;
	
	new_vhost=M_malloc(sizeof(struct host));

	new_vhost->servername = M_strdup(vhost_servername);
	new_vhost->documentroot = M_strdup(vhost_documentroot);

	if(vhost_cgi_alias && vhost_cgi_path){
		new_vhost->cgi_alias = M_strdup(vhost_cgi_alias);
		new_vhost->cgi_path = M_strdup(vhost_cgi_path);
	}
	else{
		new_vhost->cgi_alias=NULL;
		new_vhost->cgi_path=NULL;
	}
	
	new_vhost->getdir=getdir;
	
    if(!config->hosts)
    {
        config->hosts=new_vhost;
	}
	else
    {
        aux_vhost=config->hosts;
        while(aux_vhost->next!=NULL)
            aux_vhost=aux_vhost->next;
        
        aux_vhost->next=new_vhost;
	}

	return 0;
}

void VHOST_Config_Error(char *path)
{
	printf("Error: %s -> Virtualhost section.\n", path);
	exit(1);	
}

struct host *VHOST_Find(char *host)
{
	struct host *aux_host;
	
    aux_host = config->hosts;

	while(aux_host){
		if(strcasecmp(aux_host->servername, host)==0)
			break;
		else
			aux_host=aux_host->next;
	}

	return (struct host *) aux_host;
}
