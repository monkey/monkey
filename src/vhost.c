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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "monkey.h"
 
 
void VHOST_Read_Config(char *path_conf, char *file_conf)
{
	int i, flag=0; /* Flag: ¿esta abierta alguna sentencia Virtualhost?(0=No , 1=Si) */
	int forcegetdir=VAR_NOTSET;
	char *path=0, buffer[255];
	char *variable=0, *value=0, *auxarg=0, *last=0;
	char *vhost_servername=0, *vhost_documentroot=0, *vhost_cgi_alias=0, *vhost_cgi_path=0;
	FILE *configfile;

	path=m_build_buffer("%s/%s", config->serverconf, file_conf);
	
	if( (configfile=fopen(path,"r"))==NULL ) {
		printf("Error: I can't open %s file.", path);
		exit(1);
	}
	
	while(!feof(configfile)) {
		fgets(buffer,255,configfile);

		if(buffer[0] == '#' || buffer[0] == '\n' || buffer[0] == '\r') 
			continue;
        
		for(i=0; i<255 && buffer[i]!='\0'; i++)
		  if(buffer[i] == '\n' || buffer[i] == '\r')
	 	   buffer[i]='\0';

		variable   = strtok_r(buffer, "\"\t ", &last);
		value	  = strtok_r(NULL, "\"\t ", &last);

		if(!variable || (!value && (strcasecmp(variable,"<Virtualhost>")!=0) &&
			(strcasecmp(variable,"</Virtualhost>")!=0)))  {
			continue;
		}
		
		/* Virtual Host */
		if(strcasecmp(variable,"<Virtualhost>")==0 && flag==0) {
			flag=1;
		}
		else {
			if(strcasecmp(variable,"<Virtualhost>")==0 && flag==1) {
				VHOST_Config_Error(path);
			}
		}
		
		if(strcasecmp(variable,"VirtualServerName")==0 && flag==1) {
			vhost_servername = M_strdup(value);
		}

		if(strcasecmp(variable,"VirtualDocumentRoot")==0 && flag==1) {
			vhost_documentroot = M_strdup(value);
		}

		if(strcasecmp(variable,"VirtualScriptAlias")==0 && flag==1) {
			if(!value) VHOST_Config_Error(path);
			vhost_cgi_alias = M_strdup(value);
			auxarg=strtok_r(NULL,"\"\t ", &last);

			if(!auxarg) VHOST_Config_Error(path);
			vhost_cgi_path = M_strdup(auxarg);
		}

		if(strcasecmp(variable,"VirtualForceGetDir")==0 && flag==1) {
			forcegetdir=VAR_OFF;
			if(strcasecmp(value,"on") && strcasecmp(value,"off"))
				VHOST_Config_Error(path);
			else
				if(strcasecmp(value,"on")==0)
					forcegetdir=VAR_ON;
		}
		
		if(strcasecmp(variable,"</Virtualhost>")==0 && flag==1) {
			if(vhost_servername && vhost_documentroot) {
				VHOST_Config_Add(vhost_servername, vhost_documentroot, vhost_cgi_alias, vhost_cgi_path, forcegetdir);
				M_free(vhost_servername);
				M_free(vhost_documentroot);;
				M_free(vhost_cgi_alias);
				M_free(vhost_cgi_path);
				vhost_servername = 0;
				vhost_documentroot = 0;
				flag=0;
			}
			else{
				VHOST_Config_Error(path);
			}
		}
		else
			if(strcasecmp(variable,"</Virtualhost>")==0 && flag==0 && vhost_servername){
				VHOST_Config_Error(path);
			}
	}	
	if(flag!=0) {
		VHOST_Config_Error(path);
	}
	fclose(configfile);
	M_free(path);
}

int VHOST_Config_Add(char *vhost_servername, char  *vhost_documentroot,
									char *vhost_cgi_alias, char  *vhost_cgi_path, int forcegetdir)
{

	struct vhost *new_vhost, *aux_vhost;
	
	new_vhost=M_malloc(sizeof(struct vhost));

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
	
	new_vhost->forcegetdir=forcegetdir;
	
	if(first_vhost==NULL) {
			first_vhost=new_vhost;
	}
	else {
			aux_vhost=first_vhost;
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

struct vhost *VHOST_Find(char *host)
{

	struct vhost *aux_vhost;
	
	if(first_vhost==NULL || host==NULL)
		return NULL;

	aux_vhost=first_vhost;
	while(aux_vhost!=NULL){
		if(strcasecmp(aux_vhost->servername,host)==0)
			break;
		else
			aux_vhost=aux_vhost->next;
	}
	
	return (struct vhost *) aux_vhost;
}
