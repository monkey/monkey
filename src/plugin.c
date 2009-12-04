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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
#include <err.h>

#include "config.h"
#include "plugin.h"
#include "monkey.h"
#include "request.h"
#include "scheduler.h"
#include "utils.h"
#include "str.h"
#include "file.h"
#include "header.h"
#include "iov.h"

void *mk_plugin_load(char *path)
{
        void *handle;

        handle = dlopen(path, RTLD_LAZY);
        if(!handle){
                fprintf(stderr, "Error during dlopen(): %s\n", dlerror());
                exit(1);
        }
        return handle;
}

void *mk_plugin_load_symbol(void *handler, const char *symbol)
{
        char *err;
        void *s;

        dlerror();
        s = dlsym(handler, symbol);
        if((err = dlerror()) != NULL){
                return NULL;
        }

        return s;
}

void mk_plugin_register_add_to_stage(struct plugin **st, struct plugin *p)
{
        struct plugin *list;

        if(!*st){
                *st = p;
                return;
        }

        list = *st;

        while(list->next){
                list = list->next;
        }

        list->next = p;
}

void mk_plugin_register_stages(struct plugin *p)
{
        struct plugin_list *new, *list;

        /* Main plugin list */
        new = mk_mem_malloc(sizeof(struct plugin_list));
        new->p = p;
        new->next = NULL;

        if(!plg_list){
                plg_list = new;
        }
        else{
                list = plg_list;
                while(list->next){
                        list = list->next;
                }
                list->next = new;
        }

        /* Assign plugin to stages */
        if(*p->stages & MK_PLUGIN_STAGE_10){
                mk_plugin_register_add_to_stage(&config->plugins->stage_10, p);
        }

        if(*p->stages & MK_PLUGIN_STAGE_20){
                mk_plugin_register_add_to_stage(&config->plugins->stage_20, p);   
        }

        if(*p->stages & MK_PLUGIN_STAGE_30){
                mk_plugin_register_add_to_stage(&config->plugins->stage_30, p);
        }

        if(*p->stages & MK_PLUGIN_STAGE_40){
                mk_plugin_register_add_to_stage(&config->plugins->stage_40, p);
        }

        if(*p->stages & MK_PLUGIN_STAGE_50){
                mk_plugin_register_add_to_stage(&config->plugins->stage_50, p);
        }

        if(*p->stages & MK_PLUGIN_STAGE_60){
                mk_plugin_register_add_to_stage(&config->plugins->stage_60, p);
        }
}

void *mk_plugin_register(void *handler, char *path)
{
        struct plugin *p;

        p = mk_mem_malloc_z(sizeof(struct plugin));
        p->name = mk_plugin_load_symbol(handler, "_name");
        p->version = mk_plugin_load_symbol(handler, "_version");
        p->path = mk_string_dup(path);
        p->handler = handler;
        p->stages = (mk_plugin_stage_t *) mk_plugin_load_symbol(handler, "_stages");

        /* Plugin external function */
        p->call_init = (int (*)()) mk_plugin_load_symbol(handler, 
                                                         "_mk_plugin_init");

        p->call_worker_init = (int (*)()) mk_plugin_load_symbol(handler,
                                                                "_mk_plugin_worker_init");

        p->call_stage_10 = (int (*)()) 
                mk_plugin_load_symbol(handler, "_mk_plugin_stage_10");

        p->call_stage_20 = (int (*)())
                mk_plugin_load_symbol(handler, "_mk_plugin_stage_20");

        p->call_stage_40 = (int (*)())
                mk_plugin_load_symbol(handler, "_mk_plugin_stage_40");

        p->next = NULL;

        if(!p->name || !p->version || !p->stages){
                mk_mem_free(p);
                return NULL;
        }

        mk_plugin_register_stages(p);
        return p;
}

void mk_plugin_init()
{
        int len;
        char *path;
        char *key, *value, *last;
        char buffer[255];
        FILE *fconf;
        void *handle;
        struct plugin *p;
        struct plugin_api *api;

        api = mk_mem_malloc_z(sizeof(struct plugin_api));
        
        /* Setup and connections list */
        api->config = config;
        api->sched_list = &sched_list;
        
        /* API plugins funcions */
        api->mem_alloc = (void *) mk_mem_malloc;
        api->mem_alloc_z = (void *) mk_mem_malloc_z;
        api->mem_free = (void *) mk_mem_free;
        api->str_build = (void *) m_build_buffer;
        api->str_dup = (void *) mk_string_dup;
        api->str_search = (void *) mk_string_search;
        api->str_search_n = (void *) mk_string_search_n;
        api->str_copy_substr = (void *) mk_string_copy_substr;
        api->file_to_buffer = (void *) mk_file_to_buffer;
        api->file_get_info = (void *) mk_file_get_info;
        api->header_send = (void *) mk_header_send;
        api->iov_create = (void *) mk_iov_create;
        api->iov_free = (void *) mk_iov_free;
        api->iov_add_entry = (void *) mk_iov_add_entry;
        api->iov_set_entry = (void *) mk_iov_set_entry;
        api->iov_send = (void *) mk_iov_send;
        api->pointer_set = (void *) mk_pointer_set;
        api->socket_cork_flag = (void *) mk_socket_set_cork_flag;
        api->config_create = (void *) mk_config_create;
        api->config_free = (void *) mk_config_free;
        api->config_getval = (void *) mk_config_getval;
        api->sched_get_connection = (void *) mk_sched_get_connection;
        
        path = mk_mem_malloc_z(1024);
        snprintf(path, 1024, "%s/%s", config->serverconf, MK_PLUGIN_LOAD);

	if((fconf=fopen(path, "r"))==NULL) {
		fprintf(stderr, "Error: I can't open %s file.\n", path);
		exit(1);
	}

        while(fgets(buffer, 255, fconf)) {
		len = strlen(buffer);
		if(buffer[len-1] == '\n') {
			buffer[--len] = 0;
			if(len && buffer[len-1] == '\r')
				buffer[--len] = 0;
		}
		
		if(!buffer[0] || buffer[0] == '#')
			continue;

		key = strtok_r(buffer, "\"\t ", &last);
		value = strtok_r(NULL, "\"\t ", &last);

		if (!key || !value) continue;

                if(strcasecmp(key, "LoadPlugin")==0){
                        handle = mk_plugin_load(value);
                        p = mk_plugin_register(handle, value);
                        if(!p){
                                fprintf(stderr, "Plugin error: %s", value);
                                dlclose(handle);
                        }
                        else{
                                p->call_init(&api);
                        }
                }
        }

        fclose(fconf);
}

int mk_plugin_stage_run(mk_plugin_stage_t stage,
                        unsigned int socket,
                        struct sched_connection *conx,
                        struct client_request *cr,
                        struct request *sr)
{
        int ret;
        struct plugin *p;

        if(stage & MK_PLUGIN_STAGE_10){
                p = config->plugins->stage_10;
                while(p){
                        p->call_stage_10();
                        p = p->next;
                }
        }
        if(stage & MK_PLUGIN_STAGE_20){
                p = config->plugins->stage_20;
                while(p){ 
                        ret = p->call_stage_20(socket, conx, NULL);
                        if(ret != 0){
                                return ret;
                        }
                        p = p->next;
                }
        }
        else if(stage & MK_PLUGIN_STAGE_40){
                p = config->plugins->stage_40;
                while(p){
                        ret = p->call_stage_40(cr, sr);
                        if(ret == 0){
                                return 0;
                        }
                        p = p->next;
                }
        }

        return -1;
}

/* This function is called by every created worker
 * for plugins which need to set some data under a thread
 * context 
 */
void mk_plugin_worker_startup()
{
        struct plugin_list *plg;

        plg = plg_list;
        
        while(plg){
                if(plg->p->call_worker_init){
                        plg->p->call_worker_init();
                }
                plg = plg->next;
        }
}
