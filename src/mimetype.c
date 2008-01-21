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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "monkey.h"

/* Carga en estructura los mimetypes */
void Mimetype_Read_Config()
{
	char buffer[255], path[MAX_PATH];
	char *name=0,*type=0, *last=0;
	FILE *mime_file;
		
	snprintf(path,MAX_PATH,"%s/monkey.mime", config->serverconf);

	if((mime_file=fopen(path,"r"))==NULL ) {
		puts("Error: I can't open monkey.mime file");
		exit(1);
	}
	
	/* Rutina que carga en memoria los mime types */
	while( fgets(buffer,255,mime_file) ) {
		int len;
		len = strlen(buffer);
		if(buffer[len-1] == '\n') {
			buffer[--len] = 0;
			if(len && buffer[len-1] == '\r')
				buffer[--len] = 0;
		}

		name  = strtok_r(buffer, "\"\t ", &last);
		type  = strtok_r(NULL, "\"\t ", &last);

		if (!name || !type) continue;
		if (buffer[0] == '#') continue;

		if(Mimetype_Add(name,type,NULL)!=0)
			puts("Error loading Mime Types");
	}
	fclose(mime_file);
}

int Mimetype_Add(char *name, char *type, char *bin_path)
{
	
	struct mimetypes *new_mime, *aux_mime;
	
	new_mime = M_malloc(sizeof(struct mimetypes));
	
	new_mime->name = M_strdup(name);
	new_mime->type = M_strdup(type);
	new_mime->script_bin_path = M_strdup(bin_path);

	new_mime->next=NULL;
	
	if(first_mime==NULL)
		first_mime=new_mime;
	else {
		aux_mime=first_mime;
		while(aux_mime->next!=NULL)
			aux_mime=aux_mime->next;
		aux_mime->next=new_mime;
	}
	return 0;	
}

char **Mimetype_Find(char *filename)
{
	int i,j;
	char name[MAX_PATH];
	
	j=strlen(filename)-1;
	
	/* Tipo de archivo */
	while(filename[j]!='.' && j>=0) 
		j--;

	for(i=0; i<=strlen(filename) ;i++) {
		name[i]=filename[j+1];
		j++;
	}
	name[strlen(name)]='\0';

	return (char **) Mimetype_CMP(name);
}

/* Busca mime type segun Request */
char **Mimetype_CMP(char *name)
{
	char **info;
	struct mimetypes *aux_mime;
		
	aux_mime=first_mime;
	while(aux_mime!=NULL) {
		if(strcasecmp(aux_mime->name,name)==0) {
			break;		 		  
		}
		else 
			aux_mime=aux_mime->next;
	}

	info=(char **) M_malloc(sizeof(char *) * 3);
	if(aux_mime==NULL){
		info[0]=M_strdup("text/plain");
		info[1]=NULL;
	}
	else{
		info[0]=M_strdup(aux_mime->type);
		info[1]=M_strdup(aux_mime->script_bin_path);
	}
	info[2]='\0';
	return info;
}

int Mimetype_free(char **arr)
{
	M_free(arr[0]);
	M_free(arr[1]);
	M_free(arr);
	return 0;
}

