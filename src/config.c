/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

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
#include <fcntl.h>

#include "monkey.h"
#include "config.h"
#include "str.h"
#include "utils.h"
#include "mimetype.h"
#include "info.h"
#include "logfile.h"
#include "deny.h"
#include "memory.h"
#include "dir_html.h"
#include "cgi.h"

/* Read configuration files */
void mk_config_read_files(char *path_conf, char *file_conf)
{
	int bool;
	unsigned long len;
	char *path=0, buffer[255];
	char *variable=0, *value=0, *last=0, *auxarg=0;
	FILE *configfile;
	struct stat checkdir;

	config->serverconf = mk_string_dup(path_conf);
	
	if(stat(config->serverconf, &checkdir)==-1){
		fprintf(stderr, "ERROR: Invalid path to configuration files.");
		exit(1);
	}
	
	m_build_buffer(&path, &len, "%s/%s", path_conf, file_conf);

	if( (configfile=fopen(path,"r"))==NULL ) {
		fprintf(stderr, "Error: I can't open %s file.\n", path);
		exit(1);
	}

	while(fgets(buffer,255,configfile)) {
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

		/* Connection port */
		if(strcasecmp(variable, "Port")==0) {
			config->serverport=atoi(value);
			if(!config->serverport>=1 && !config->serverport<=65535)
				mk_config_print_error_msg("Port", path);
		}


      		/* MaxClients */
		if(strcasecmp(variable,"Workers")==0) { 
			config->workers=atoi(value);
			if(config->maxclients < 1)
			    mk_config_print_error_msg("Workers", path);
		}


		/* Timeout */
		if(strcasecmp(variable,"Timeout")==0) {
			config->timeout=atoi(value);
			if(config->timeout<1 || !value)
				mk_config_print_error_msg("Timeout", path);
		}
				
		/* KeepAlive */
		if(strcasecmp(variable,"KeepAlive")==0) {
                        bool = mk_config_get_bool(value);
                        if(bool == VAR_ERR)
                        {
                                        mk_config_print_error_msg("KeepAlive", 
                                                                  path);
                        }
                        else{
                                config->keep_alive=bool;
                        }
                }

                /* MaxKeepAliveRequest */
		if(strcasecmp(variable,"MaxKeepAliveRequest")==0){
			config->max_keep_alive_request=atoi(value);
			if(config->max_keep_alive_request==0)
			    mk_config_print_error_msg("MaxKeepAliveRequest", path);
		}
		
		/* KeepAliveTimeout */
		if(strcasecmp(variable,"KeepAliveTimeout")==0){
			config->keep_alive_timeout=atoi(value);
			if(config->keep_alive_timeout==0)
			    mk_config_print_error_msg("KeepAliveTimeout", path);
		}
		
		/* MaxClients */
		if(strcasecmp(variable,"MaxClients")==0) { 
			config->maxclients=atoi(value);
			if(config->maxclients < 1)
			    mk_config_print_error_msg("MaxClients", path);
		}
		
		/* Pid File */
		if(strcasecmp(variable,"PidFile")==0)
			m_build_buffer(&config->pid_file_path, &len, "%s", value);

		/* Directorio para /~ */
		if(strcasecmp(variable,"UserDir")==0){
			m_build_buffer(&config->user_dir, &len, "%s", value);
		}
		
		/* Variable INDEX */
		if(strcasecmp(variable,"Indexfile")==0) {
			auxarg=value;
			while(auxarg!=NULL) {
					mk_config_add_index(auxarg);
					auxarg=strtok_r(NULL,"\"\t ", &last);
			}
		}

		/* HideVersion Variable */
		if(strcasecmp(variable,"HideVersion")==0)
		{
			bool = mk_config_get_bool(value);
			if(bool == VAR_ERR)
			{
				mk_config_print_error_msg("HideVersion", path);
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
			mk_mimetype_add(mimescript[2],mimescript[0],mimescript[1]);
		}

		/* User Variable */
		if(strcasecmp(variable,"User")==0) {
			m_build_buffer(&config->user, &len,
					"%s", value);
		}
		
		/* Resume */
		if(strcasecmp(variable, "Resume")==0)
		{
			bool = mk_config_get_bool(value);
			if(bool == VAR_ERR)
			{
				mk_config_print_error_msg("Resume", path);
			}
			else{
				config->resume=bool;
			}
		}
		
		/* Symbolic Links */
		if(strcasecmp(variable, "SymLink")==0)
		{
			bool = mk_config_get_bool(value);
			if(bool == VAR_ERR)
 			{
				mk_config_print_error_msg("SymLink", path);
			}
			else{
				config->symlink=bool;
			}
		}


                /* Monkey Palm Servers */
                if(strcasecmp(variable, "Palm")==0){
                        struct palm *new, *p;
                        
                        new = mk_mem_malloc(sizeof(struct palm));
                        new->ext = strdup(value);
                        new->mimetype = strdup(strtok_r(NULL,"\"\t ", &last));
			new->host = strdup(strtok_r(NULL,"\"\t ", &last));
                        new->port = atoi(strtok_r(NULL, "\"\t ", &last));
                        new->next = NULL;

                        if(!palms)
                        {
                                palms = new;
                        }
                        else{
                                p = palms;
                                while(p->next)
                                        p = p->next;

                                p->next = palms;
                        }
                }

		/* Max connection per IP */
		if(strcasecmp(variable, "Max_IP")==0) {
			config->max_ip = atoi(value);
			if(config->max_ip < 0)
			    mk_config_print_error_msg("Max_IP", path);
		} 		

		/* Including files */
		if(strcasecmp(variable,"Include")==0) {
			mk_config_read_files(path_conf, value);
		}
	}
	fclose(configfile);
	mk_mem_free(path);
	mk_config_read_hosts(path_conf);
}

void mk_config_read_hosts(char *path)
{
    DIR *dir;
    unsigned long len;
    char *buf=0;
    char *file;
    struct host *p_host, *new_host; /* debug */
    struct dirent *ent;

    m_build_buffer(&buf, &len, "%s/sites/default", path);
    config->hosts = mk_config_get_host(buf);
    config->nhosts++;
    mk_mem_free(buf);

    if(!config->hosts)
    {
        printf("\nError parsing main configuration file 'default'\n");
        exit(1);
    }

    m_build_buffer(&buf, &len, "%s/sites/", path);
    if (!(dir = opendir(buf)))
        exit(1);


    p_host = config->hosts;

    /* Reading content */
    while ((ent = readdir(dir)) != NULL)
    {
        if (strcmp((char *) ent->d_name, "." )  == 0) continue;
        if (strcmp((char *) ent->d_name, ".." ) == 0) continue;
        if (strcasecmp((char *) ent->d_name, "default" ) == 0) continue;

        m_build_buffer(&file, &len, "%s/sites/%s", path, ent->d_name);

        new_host = (struct host *) mk_config_get_host(file);
        mk_mem_free(file);
        if(!new_host)
        {
            continue;
        }
        else{
            p_host->next = new_host;
            p_host = new_host;
	    config->nhosts++;
        }
    }
    closedir(dir);
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

int mk_config_get_bool(char *value)
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

struct host *mk_config_get_host(char *path)
{
	unsigned long len=0;
        char buffer[255];
        char *variable=0, *value=0, *last=0, *auxarg=0;
        FILE *configfile;
        struct stat checkdir;
        struct host *host;

        if( (configfile=fopen(path,"r"))==NULL ) {
                fprintf(stderr, "Error: I can't open %s file.\n", path);
                return NULL;
        }

        host = mk_mem_malloc_z(sizeof(struct host));
        host->servername = 0;
        host->file = mk_string_dup(path);

        while(fgets(buffer,255,configfile)) {
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
                        {
                                m_build_buffer(&host->servername, &len,
                                               "%s", value);
                        }

                /* Ubicacion directorio servidor */
                if(strcasecmp(variable,"DocumentRoot")==0) {

                        host->documentroot.data=mk_string_dup(value);
                        host->documentroot.len = strlen(value);

                        if(stat(host->documentroot.data, &checkdir)==-1) {
                                fprintf(stderr, 
                                        "ERROR: Invalid path to Server_root in %s\n\n", path); 
                                exit(1);
                        }
                        else if(!(checkdir.st_mode & S_IFDIR)) {
                                fprintf(stderr, 
                                        "ERROR: DocumentRoot variable in %s has an invalid directory path\n\n", path);
                                exit(1);
                        }
                }

                /* Access log */
                if(strcasecmp(variable,"AccessLog")==0) 
                        m_build_buffer(&host->access_log_path, 
                                       &len,"%s", value);
        
                /* Error log */
                if(strcasecmp(variable,"ErrorLog")==0)
                        m_build_buffer(&host->error_log_path, &len,
                                       "%s", value);

                /* GetDir Variable */
                if(strcasecmp(variable,"GetDir")==0)
                        {
                                if(strcasecmp(value,VALUE_ON) && strcasecmp(value,VALUE_OFF))
                                        mk_config_print_error_msg("GetDir", path);
                                else if(strcasecmp(value,VALUE_OFF)==0)
                                        host->getdir=VAR_OFF;
                        }

                /* Script_Alias del server */
                if(strcasecmp(variable,"ScriptAlias")==0)
                        {
                                if(!value) mk_config_print_error_msg("ScriptAlias", path);
                                host->scriptalias = (char **) mk_mem_malloc(sizeof(char *) * 3);
                                host->scriptalias[0]=mk_string_dup(value);
                                auxarg=strtok_r(NULL,"\"\t ", &last);

                                if(!auxarg) mk_config_print_error_msg("ScriptAlias", path);
                                host->scriptalias[1]=mk_string_dup(auxarg);
                                host->scriptalias[2]='\0';
                        }
        }
        fclose(configfile);
        if(!host->servername)
                {
                        return NULL;
                }

	/* Server Signature */
	if(config->hideversion==VAR_OFF){
		m_build_buffer(&host->host_signature, &len,
                               "Monkey/%s Server (Host: %s, Port: %i)",
                               VERSION, host->servername, config->serverport);
	}
	else{
		m_build_buffer(&host->host_signature, &len, 
                               "Monkey Server (Host: %s, Port: %i)",
                               host->servername, config->serverport);
	}
	m_build_buffer(&host->header_host_signature.data, 
                       &host->header_host_signature.len, 
                       "Server: %s", host->host_signature);

	if(pipe(host->log_access)<0){
                perror("pipe");
        }

	if(pipe(host->log_error)<0){
                perror("pipe");
        }

        fcntl(host->log_access[1], F_SETFL, O_NONBLOCK);
        fcntl(host->log_error[1], F_SETFL, O_NONBLOCK);

	host->next = NULL;
	return host;
}

/* Imprime error de configuracion y cierra */
void mk_config_print_error_msg(char *variable, char *path)
{
	fprintf(stderr, "\nError: %s variable in %s has an invalid value.\n", variable, path);
	fflush(stderr);
	exit(1);
}

/* Agrega distintos index.xxx */
void mk_config_add_index(char *indexname)
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

void mk_config_set_init_values(void)
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
	config->symlink=VAR_OFF;
	config->nhosts = 0;
	config->user = NULL;
}

/* read main configuration from monkey.conf */
void mk_config_start_configure(void)
{
	unsigned long len;

	mk_config_set_init_values();
	mk_config_read_files(config->file_config, M_DEFAULT_CONFIG_FILE);

	/* if not index names defined, set default */
	if(first_index==NULL) 
		mk_config_add_index("index.html");			

	/* Load mimes */
	mk_mimetype_read_config();

        /* Load dir_html configuration */
        mk_dirhtml_conf();

	/* Load security rules */
	Deny_Read_Config(); 

	/* Basic server information */
	if(config->hideversion==VAR_OFF)
	{
		m_build_buffer(&config->server_software.data, 
                               &len, "Monkey/%s (%s)",VERSION,OS);
                config->server_software.len = len;
	}
	else
	{
		m_build_buffer(&config->server_software.data, &len,
				"Monkey Server");
                config->server_software.len = len;
	}
}

struct host *mk_config_host_find(mk_pointer host)
{
	struct host *aux_host;
	
	aux_host = config->hosts;

	while(aux_host){
		if(strncasecmp(aux_host->servername, host.data, host.len)==0)
			break;
		else
			aux_host=aux_host->next;
	}

	return (struct host *) aux_host;
}

