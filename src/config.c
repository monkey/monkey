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

#include <dirent.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "monkey.h"

/* Read configuration files */
void M_Config_read_files(char *path_conf, char *file_conf)
{
    int bool;
	char *path=0, buffer[255];
	char *variable=0, *value=0, *last=0, *auxarg=0;
	FILE *configfile;
	struct stat checkdir;

	config->serverconf = M_strdup(path_conf);
	
	if(stat(config->serverconf, &checkdir)==-1){
		fprintf(stderr, "ERROR: Invalid path to configuration files.");
		exit(1);
	}
	
	path = m_build_buffer("%s/%s", path_conf, file_conf);

	if( (configfile=fopen(path,"r"))==NULL ) {
		fprintf(stderr, "Error: I can't open %s file.\n", path);
		exit(1);
	}

	while(fgets(buffer,255,configfile)) {
		int len;
		len = strlen(buffer);
		if(buffer[len-1] == '\n') {
			buffer[--len] = 0;
			if(len && buffer[len-1] == '\r')
				buffer[--len] = 0;
		}
		
		if(!buffer[0] || buffer[0] == '#')
			continue;
			
		variable   = strtok_r(buffer, "\"\t ", &last);
		value	  = strtok_r(NULL, "\"\t ", &last);

		if (!variable || !value) continue;

		/* Puerto de conexion */
		if(strcasecmp(variable, "Port")==0) {
			config->serverport=atoi(value);
			if(!config->serverport>=1 && !config->serverport<=65535)
				M_Config_print_error_msg("Port", path);
		}

		/* Timeout */
		if(strcasecmp(variable,"Timeout")==0) {
			config->timeout=atoi(value);
			if(config->timeout<1 || !value)
				M_Config_print_error_msg("Timeout", path);
		}
				
		/* KeepAlive */
		if(strcasecmp(variable,"KeepAlive")==0) {
            bool = M_Config_Get_Bool(value);
            if(bool == VAR_ERR)
            {
                M_Config_print_error_msg("KeepAlive", path);
            }
            else{
                config->keep_alive=bool;
            }
        }

    	/* MaxKeepAliveRequest */
		if(strcasecmp(variable,"MaxKeepAliveRequest")==0){
			config->max_keep_alive_request=atoi(value);
			if(config->max_keep_alive_request==0)
			    M_Config_print_error_msg("MaxKeepAliveRequest", path);
		}
		
		/* KeepAliveTimeout */
		if(strcasecmp(variable,"KeepAliveTimeout")==0){
			config->keep_alive_timeout=atoi(value);
			if(config->keep_alive_timeout==0)
			    M_Config_print_error_msg("KeepAliveTimeout", path);
		}
		
		/* MaxClients */
		if(strcasecmp(variable,"MaxClients")==0) { 
			config->maxclients=atoi(value);
			if(config->maxclients < 1)
			    M_Config_print_error_msg("MaxClients", path);
		}
		
		/* Pid File */
		if(strcasecmp(variable,"PidFile")==0)
			config->pid_file_path=m_build_buffer("%s", value);

		/* Directorio para /~ */
		if(strcasecmp(variable,"UserDir")==0){
			config->user_dir = m_build_buffer("%s", value);
		}
		
		/* Variable INDEX */
		if(strcasecmp(variable,"Indexfile")==0) {
			auxarg=value;
			while(auxarg!=NULL) {
					M_Config_add_index(auxarg);
					auxarg=strtok_r(NULL,"\"\t ", &last);
			}
		}

		/* HideVersion Variable */
		if(strcasecmp(variable,"HideVersion")==0) {
            bool = M_Config_Get_Bool(value);
            if(bool == VAR_ERR)
            {
                M_Config_print_error_msg("HideVersion", path);
            }
            else{
                config->hideversion=bool;
            }
		}
		
		/* Scripts */
		if(strcasecmp(variable,"AddScript")==0){
			char *mimescript[4];

			mimescript[0]=value; /* Mime Type */
			mimescript[1]=strtok_r(NULL,"\"\t ", &last); /* Bin Path */
			mimescript[2]=strtok_r(NULL,"\"\t ", &last); /* Ext */
			mimescript[3]='\0';
			
			if(strlen(mimescript[0])<1){
				printf("Error: AddScript variable in %s -> mime type not found.\n", path);
				exit(1);
			}	

			if(access(mimescript[1],X_OK)!=0 || CheckFile(mimescript[1])!=0){
				printf("Error: AddScript variable in %s -> binary file not valid.\n", path);
				exit(1);
			}
			if(strlen(mimescript[2])<1){
				printf("Error: AddScript variable in %s -> extension not found.\n", path);
				exit(1);
			}	
			Mimetype_Add(mimescript[2],mimescript[0],mimescript[1]);
		}

		/* User Variable */
		if(strcasecmp(variable,"User")==0) {
			config->user = m_build_buffer("%s", value);
		}

		/* Resume */
		if(strcasecmp(variable, "Resume")==0)
        {
            bool = M_Config_Get_Bool(value);
            if(bool == VAR_ERR)
            {
                M_Config_print_error_msg("Resume", path);
            }
            else{
                config->resume=bool;
            }
		}
		
		/* Symbolic Links */
		if(strcasecmp(variable, "SymLink")==0) {
            bool = M_Config_Get_Bool(value);
            if(bool == VAR_ERR)
            {
                M_Config_print_error_msg("SymLink", path);
            }
            else{
                config->symlink=bool;
            }
		}
		/* Max connection per IP */
		if(strcasecmp(variable, "Max_IP")==0) {
			config->max_ip = atoi(value);
			if(config->max_ip < 0)
			    M_Config_print_error_msg("Max_IP", path);
		} 		

		/* Including files */
		if(strcasecmp(variable,"Include")==0) {
			M_Config_read_files(path_conf, value);
		}
	}
	fclose(configfile);
	M_free(path);
    M_Config_Read_Hosts(path_conf);
}

void M_Config_Read_Hosts(char *path)
{
    DIR *dir;
    char *buf;
    char *file;
    struct host *p_host, *new_host; /* debug */
    struct dirent *ent;

    buf = m_build_buffer("%s/sites/default", path);
    config->hosts = M_Config_Get_Host(buf);
    M_free(buf);

    if(!config->hosts)
    {
        printf("\nError parsing main configuration file 'default'\n");
        exit(1);
    }

    buf = m_build_buffer("%s/sites/", path);
    if (!(dir = opendir(buf)))
        exit(1);


    p_host = config->hosts;

    /* Reading content */
    while ((ent = readdir(dir)) != NULL)
    {
        if (strcmp((char *) ent->d_name, "." )  == 0) continue;
        if (strcmp((char *) ent->d_name, ".." ) == 0) continue;
        if (strcasecmp((char *) ent->d_name, "default" ) == 0) continue;

        file = m_build_buffer("%s/sites/%s", path, ent->d_name);

        new_host = (struct host *) M_Config_Get_Host(file);
        M_free(file);
        if(!new_host)
        {
            continue;
        }
        else{
            p_host->next = new_host;
            p_host = new_host;
        }
    }
    /*
    h = config->hosts;
    while(h)
    {
        printf("*** HOST ***\n");
        printf(" [servername]\t\t%s\n", h->servername);
        printf(" [documentroot]\t\t%s\n", h->documentroot);
        printf(" [conf file]\t\t%s\n", h->file);
        printf(" [access log]\t\t%s\n", h->access_log_path);
        printf(" [error log]\t\t%s\n", h->error_log_path);
        printf(" [script alias]\t\t%s %s\n", h->scriptalias[0], h->scriptalias[1]);
        printf(" [get dir]\t\t%i\n", h->getdir);
        printf(" [header file]\t\t%s\n", h->header_file);
        printf(" [footer file]\t\t%s\n\n", h->footer_file);

        h = h->next;
    }
    fflush(stdout);
    */
}

int M_Config_Get_Bool(char *value)
{
    int on, off;

    on = strcasecmp(value, VALUE_ON);
    off = strcasecmp(value,VALUE_OFF);

    if(on!=0 && off!=0)
    {
        return -1;
    }
    else if(on>=0)
    {
        return VAR_ON;
    }
    else{
        return VAR_OFF;
    }
}

struct host *M_Config_Get_Host(char *path)
{
    char buffer[255];
    char *variable=0, *value=0, *last=0, *auxarg=0;
    FILE *configfile;
    struct stat checkdir;
    struct host *host;

    printf("[PARSING HOST FILE]: %s\n", path);
    fflush(stdout);

    if( (configfile=fopen(path,"r"))==NULL ) {
        fprintf(stderr, "Error: I can't open %s file.\n", path);
        return NULL;
    }

    host = M_malloc(sizeof(struct host));
    host->file = M_strdup(path);

    while(fgets(buffer,255,configfile)) {
        int len;
        len = strlen(buffer);
        if(buffer[len-1] == '\n') {
            buffer[--len] = 0;
            if(len && buffer[len-1] == '\r')
                buffer[--len] = 0;
        }
        
        if(!buffer[0] || buffer[0] == '#')
            continue;
            
        variable   = strtok_r(buffer, "\"\t ", &last);
        value     = strtok_r(NULL, "\"\t ", &last);

        if (!variable || !value) continue;


        /* Server Name */
        if(strcasecmp(variable,"Servername")==0)
            host->servername = m_build_buffer("%s", value);

        /* Ubicacion directorio servidor */
        if(strcasecmp(variable,"DocumentRoot")==0) {
            host->documentroot=M_strdup(value);
            if(stat(host->documentroot, &checkdir)==-1) {
                fprintf(stderr, "ERROR: Invalid path to Server_root in %s.", path); 
                exit(1);
            }
            else if(!(checkdir.st_mode & S_IFDIR)) {
                fprintf(stderr, "ERROR: DocumentRoot variable in %s has an invalid directory path.", path);
                exit(1);
            }
        }

        /* Access log */
        if(strcasecmp(variable,"AccessLog")==0) 
            host->access_log_path=m_build_buffer("%s", value);
        
        /* Error log */
        if(strcasecmp(variable,"ErrorLog")==0)
            host->error_log_path = m_build_buffer("%s", value);

        /* GetDir Variable */
        if(strcasecmp(variable,"GetDir")==0)
        {
            if(strcasecmp(value,VALUE_ON) && strcasecmp(value,VALUE_OFF))
                M_Config_print_error_msg("GetDir", path);
            else if(strcasecmp(value,VALUE_OFF)==0)
                     host->getdir=VAR_OFF;
        }

        /* Script_Alias del server */
        if(strcasecmp(variable,"ScriptAlias")==0)
        {
            if(!value) M_Config_print_error_msg("ScriptAlias", path);
            host->scriptalias = (char **) M_malloc(sizeof(char *) * 3);
            host->scriptalias[0]=M_strdup(value);
            auxarg=strtok_r(NULL,"\"\t ", &last);

            if(!auxarg) M_Config_print_error_msg("ScriptAlias", path);
            host->scriptalias[1]=M_strdup(auxarg);
            host->scriptalias[2]='\0';
        }

        if(strcasecmp(variable, "Header_file")==0)
            host->header_file = m_build_buffer("%s", value);

        if(strcasecmp(variable, "Footer_file")==0)
            host->footer_file = m_build_buffer("%s", value);

    }
    fclose(configfile);
    if(!host->servername)
    {
        return NULL;
    }

	/* Server Signature */
	if(config->hideversion==VAR_OFF){
		host->host_signature = m_build_buffer("Monkey/%s Server (Host: %s, Port: %i)",
				VERSION, host->servername, config->serverport);
	}
	else{
		host->host_signature = m_build_buffer("Monkey Server (Host: %s, Port: %i)",
				host->servername, config->serverport);
	}
	host->header_host_signature = m_build_buffer("Server: %s", host->host_signature);
	host->header_len_host_signature = strlen(host->header_host_signature);

	host->next = NULL;
	return host;
}

/* Imprime error de configuracion y cierra */
void M_Config_print_error_msg(char *variable, char *path)
{
	fprintf(stderr, "\nError: %s variable in %s has an invalid value.\n", variable, path);
	fflush(stderr);
	exit(1);
}

/* Agrega distintos index.xxx */
void M_Config_add_index(char *indexname)
{
	struct indexfile *new_index=0, *aux_index;

	new_index = (struct indexfile *) malloc(sizeof(struct indexfile));
	strncpy(new_index->indexname,indexname,MAX_INDEX_NOMBRE - 1);
	new_index->indexname[MAX_INDEX_NOMBRE - 1]='\0';
	new_index->next=NULL; 
	
	if(first_index==NULL) {
			first_index=new_index;
	}
	else {
		aux_index=first_index;
		while(aux_index->next!=NULL)
			aux_index=aux_index->next;
		aux_index->next=new_index;
	}
}

void M_Config_set_init_values(void)
{
	/* Valores iniciales */
	config->timeout=15;
	config->hideversion=VAR_OFF;
	config->keep_alive=VAR_ON;
	config->keep_alive_timeout=15;
	config->max_keep_alive_request=50;
	config->maxclients=150;
	config->max_ip = 15; 
	config->resume=VAR_ON;
	config->standard_port=80;
	config->serverport=2001;
	config->server_addr=NULL;
	config->symlink=VAR_OFF;
}

/* Lee la configuraci�n principal desde monkey.conf */
void M_Config_start_configure(void)
{

    M_Config_set_init_values();

    M_Config_read_files(config->file_config, M_DEFAULT_CONFIG_FILE);

    /* Si no fueron definidas variables 
    INDEX, se asume index.html por omisi�n */
    if(first_index==NULL) 
    	M_Config_add_index("index.html");			

	/* Almacenar en estructura los mimetypes definidos */
    Mimetype_Read_Config();
     
	/* Carga directorios e IP's a denegar */
    Deny_Read_Config(); 

    /* Informaci�n b�sica del server */
    if(config->hideversion==VAR_OFF)
		config->server_software = m_build_buffer("Monkey/%s (%s)",VERSION,OS);
    else
		config->server_software = m_build_buffer("Monkey Server");
}
