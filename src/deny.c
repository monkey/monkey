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

/* Carga en memoria los mimes registrados en mime.types */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>

#include "monkey.h"

void Deny_Read_Config()
{
	char buffer[255];
	char *path=0;
	char *type=0,*value=0, *last=0;
	FILE *deny_file;
		
	path = m_build_buffer("%s/%s", config->serverconf, DENY_CONF_FILENAME);

	if((deny_file=fopen(path,"r"))==NULL ) {
		puts("Error: I can't open monkey deny file");
		exit(1);
	}
	
	/* Rutina que carga en memoria los mime types */
	while(fgets(buffer,255,deny_file)) {
		int len;
		len = strlen(buffer);
		if(buffer[len-1] == '\n') {
			buffer[--len] = 0;
			if(len && buffer[len-1] == '\r')
				buffer[--len] = 0;
		}

		type  = strtok_r(buffer, "\"\t ", &last);
		value = strtok_r(NULL, "\"\t ", &last);

		if (!type || !value) continue;
		if (buffer[0] == '#') continue;

		if(strcasecmp(type, DENY_CONF_URL)==0 || strcasecmp(type, DENY_CONF_IP)==0) {
			if(strcasecmp(type, DENY_CONF_URL)==0)
				Deny_Add(DENY_URL, value);
			else if(strcasecmp(type, DENY_CONF_IP)==0)
				Deny_Add(DENY_IP, value);
		}
	}
	fclose(deny_file);
	M_free(path);
}

/* Agrega una denegacion de IP o URL */
void Deny_Add(const short int type, char *value)
{
	struct deny *new_deny, *aux_deny;
		
	new_deny=M_malloc(sizeof(struct deny));
	
	new_deny->type = type;
	strncpy(new_deny->value,value,MAX_DENY_VALUE - 1);
	new_deny->value[MAX_DENY_VALUE - 1]='\0';
	new_deny->next=NULL;
	
	if(first_deny==NULL) {
			first_deny=new_deny;
	}
	else {
		aux_deny=first_deny;
		while(aux_deny->next!=NULL)
			aux_deny=aux_deny->next;
		aux_deny->next=new_deny;
	}
}

/* Compara la IP a denegar con la IP solicitante del servicio */
/* Devuelve 0 cuando hay coincidencia, 1 cuando no la hay	  */
int Check_IP(char *client_ip, char *aux_deny_value)
{
	int	 i;

	/* Comparar el valor a denegar con el IP 		*/
	/* El * indica coincidencia completa	 		*/
	/* El ? indica coincidencia con un solo numero 	*/
	for ( i=0; aux_deny_value[i]; i ++) {	
	
		if (aux_deny_value[i]=='?') {
			if (client_ip[i]=='.' || client_ip[i]=='\0')	
				return 1;
			else
				continue;
		}
																			
		if (aux_deny_value[i]=='*') /* Coincidencia, salir */
			return 0;
		
		if (aux_deny_value[i]!=client_ip[i]) /* Las IPs no coinciden, salir */
			return 1;	
	}
	
	if (client_ip[i]=='\0')
		return 0;
	else
		return 1;
}

int Deny_Check(struct request *req, char *client_ip)
{
	struct deny *aux_deny;

	aux_deny=first_deny;
	while(aux_deny!=NULL){
		/* Validando que la IP sea distinta */
		if(aux_deny->type==DENY_IP)
		{
			if(Check_IP(client_ip, aux_deny->value)==0) 
			{
				return -1;
			}
		}

		/* Validando strings a denegar en el request */
		if(req->uri){
			if(aux_deny->type && DENY_URL && strstr(req->uri,aux_deny->value)){
				return -1;
			}			
		}
		aux_deny=aux_deny->next;
	}
	return 0;	
}
