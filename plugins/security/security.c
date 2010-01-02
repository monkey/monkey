/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2009, Eduardo Silva P.
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
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "plugin.h"
#include "security.h"

/* Plugin data for register */
mk_plugin_data_t _shortname = "security";
mk_plugin_data_t _name = "Security";
mk_plugin_data_t _version = "0.1";
mk_plugin_stage_t _stages = MK_PLUGIN_STAGE_20 | MK_PLUGIN_STAGE_30;

struct plugin_api *mk_api;
struct mk_config *conf;

/* Read database configuration parameters */
int mk_security_conf(char *confdir)
{
        int ret = 0;
        unsigned long len;
        char *conf_path;
        struct mk_config *p;
        struct mk_security *new, *r;

        mk_api->str_build(&conf_path, 
                          &len, 
                          "%s/security.conf",
                          confdir);

        p = conf = mk_api->config_create(conf_path);

        r = rules;
        while(p){
                /* Passing to internal struct */
                new = mk_api->mem_alloc(sizeof(struct mk_security));
                if(strcasecmp(p->key, "IP") == 0){
                        new->type = MK_SECURITY_TYPE_IP;
                }
                else if(strcasecmp(p->key, "URL") == 0){
                        new->type = MK_SECURITY_TYPE_URL;
                }

                new->value = p->val;
                new->next = NULL;

                /* Linking node */
                if(!rules){
                        rules = new;
                }
                else{
                        r = rules;
                        while(r->next){
                                r = r->next;
                        }
                        r->next = new;
                }
                p = p->next;
        }

        mk_api->mem_free(conf_path);
        return ret;
}

int mk_security_check_ip(char *ipv4)
{
        unsigned int i=0;
        struct mk_security *p;

        p = rules;
        while(p){
                if(p->type == MK_SECURITY_TYPE_IP){
                        for(i=0; p->value[i]; i ++) {
                                if (p->value[i]=='?') {
                                        if (ipv4[i]=='.' || ipv4[i]=='\0')	
                                                return -1;
                                        else
                                                continue;
                                }
				
                                if (p->value[i]=='*')
                                        return -1;
                                
                                if (p->value[i]!=ipv4[i])
                                        return 0;
                        }
                }
                p = p->next;
        }

        if(ipv4[i] == '\0'){
                return -1;
        }
        else{
                return 0;
        }
}

int mk_security_check_url(mk_pointer url)
{
        int n;
        struct mk_security *p;

        p = rules;
        while(p){
                if(p->type == MK_SECURITY_TYPE_URL){
                        n = (int) mk_api->str_search_n(url.data,p->value,url.len);
                        if(n>=0){
                                return -1;
                        }
                }
                p = p->next;
        }

        return 0;
}

int _mk_plugin_init(void **api, char *confdir)
{
        mk_api = *api;
        rules = 0;

        /* Read configuration */
        mk_security_conf(confdir);
        return 0;
}

int _mk_plugin_stage_20(unsigned int socket, struct sched_connection *conx)
{
        if(mk_security_check_ip(conx->ipv4)!=0){
                return MK_PLUGIN_RET_CLOSE_CONX;
        }

        return MK_PLUGIN_RET_CONTINUE;
}

int _mk_plugin_stage_30(struct client_request *cr, struct request *sr)
{
        if(mk_security_check_url(sr->uri) < 0){
                return MK_PLUGIN_RET_CLOSE_CONX;
        }
        
        return MK_PLUGIN_RET_CONTINUE;
}
