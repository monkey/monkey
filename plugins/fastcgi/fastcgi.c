/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <monkey/mk_api.h>
#include <dirent.h>

#include "fastcgi.h"
#include "fcgi_handler.h"

#define MAX_FCGI_SERVERS 5
struct mk_fcgi_conf* serverList[MAX_FCGI_SERVERS] = {NULL};

static int mk_fastcgi_config(struct mk_fcgi_conf *fcgi_conf, char *path)
{
    int ret;
    int sep;
    char *cnf_srv_name = NULL;
    char *cnf_srv_addr = NULL;
    char *cnf_srv_port = NULL;
    char *cnf_srv_path = NULL;
    struct file_info finfo;
    struct mk_rconf *conf;
    struct mk_rconf_section *section;

    conf = mk_api->config_create(path);
    if (!conf) {
        return -1;
    }

    section = mk_api->config_section_get(conf, "FASTCGI_SERVER");
    if (!section) {
        return -1;
    }

    /* Get section values */
    cnf_srv_name = mk_api->config_section_get_key(section,
                                                  "ServerName",
                                                  MK_RCONF_STR);
    cnf_srv_addr = mk_api->config_section_get_key(section,
                                                  "ServerAddr",
                                                  MK_RCONF_STR);
    cnf_srv_path = mk_api->config_section_get_key(section,
                                                  "ServerPath",
                                                  MK_RCONF_STR);

    /* Validations */
    if (!cnf_srv_name) {
        mk_warn("[fastcgi] Invalid ServerName in configuration.");
        return -1;
    }

    /* Split the address, try to lookup the TCP port */
    if (cnf_srv_addr) {
        sep = mk_api->str_char_search(cnf_srv_addr, ':', strlen(cnf_srv_addr));
        if (sep <= 0) {
            mk_warn("[fastcgi] Missing TCP port con ServerAddress key");
            return -1;
        }

        cnf_srv_port = mk_api->str_dup(cnf_srv_addr + sep + 1);
        cnf_srv_addr[sep] = '\0';
    }

    /* Just one mode can exist (for now) */
    if (cnf_srv_path && cnf_srv_addr) {
        mk_warn("[fastcgi] Use ServerAddr or ServerPath, not both");
        return -1;
    }

    /* Unix socket path */
    if (cnf_srv_path) {
        ret = mk_api->file_get_info(cnf_srv_path, &finfo, MK_FILE_READ);
        if (ret == -1) {
            mk_warn("[fastcgi] Cannot open unix socket: %s", cnf_srv_path);
            return -1;
        }
    }

    /* Set the global configuration */
    fcgi_conf->server_name = cnf_srv_name;
    fcgi_conf->server_addr = cnf_srv_addr;
    fcgi_conf->server_port = cnf_srv_port;
    fcgi_conf->server_path = cnf_srv_path;

    return 0;
}

/* Callback handler */
int mk_fastcgi_stage30(struct mk_plugin *plugin,
                       struct mk_http_session *cs,
                       struct mk_http_request *sr,
                       int n_params,
                       struct mk_list *params)
{
    (void) n_params;
    (void) params;
    struct fcgi_handler *handler;

    char * serverName = NULL;
    struct mk_fcgi_conf *fcgi_conf = serverList[0];
    int i = 0;

    struct mk_vhost_handler_param *param;

    if (n_params > 0) {
        /* ServerName */
        param = mk_api->handler_param_get(0, params);
        if (param) {
          serverName = param->p.data;
        }
    }

    if (serverName) {
        while (serverList[i] && i < MAX_FCGI_SERVERS) {
            if (strncasecmp(serverName, serverList[i]->server_name, strlen(serverName)) == 0) {
                fcgi_conf = serverList[i];
                break;
            }
            ++i;
        }
    }

    handler = fcgi_handler_new(plugin, fcgi_conf, cs, sr);
    if (!handler) {
        return MK_PLUGIN_RET_NOT_ME;
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int mk_fastcgi_stage30_hangup(struct mk_plugin *plugin,
                              struct mk_http_session *cs,
                              struct mk_http_request *sr)
{
    (void) plugin;
    (void) cs;
    struct fcgi_handler *handler;

    handler = sr->handler_data;
    if (!handler) {
        return -1;
    }

    if (handler->hangup == MK_TRUE) {
        return 0;
    }

    handler->active = MK_FALSE;
    handler->hangup = MK_TRUE;

    fcgi_exit(sr->handler_data);

    return 0;
}

int mk_fastcgi_plugin_init(struct plugin_api **api, char *confdir)
{
    mk_api = *api;

    struct dirent *entry;
    DIR *dir = opendir( confdir );
    struct mk_fcgi_conf *fcgi_conf;

    char *file = NULL;
    unsigned long len;

    int count = 0;
    while( ( entry = readdir( dir )) != NULL  && count < MAX_FCGI_SERVERS)
    {
        if (entry->d_name[0] == '.') {
            continue;
        }
        if (strcmp((char *) entry->d_name, "..") == 0) {
            continue;
        }
        if (entry->d_name[strlen(entry->d_name) - 1] ==  '~') {
            continue;
        }
        if (strcasecmp((char *) entry->d_name, "default") == 0) {
            continue;
        }

        fcgi_conf = mk_api->mem_alloc(sizeof(struct mk_fcgi_conf));
        if (!fcgi_conf) {
            mk_err("malloc failed: %s", strerror(errno));
            return -1;
        }

        file = NULL;
        mk_api->str_build(&file, &len, "%s%s", confdir, entry->d_name);

        /* read each configurations */
        if (mk_fastcgi_config(fcgi_conf, file) == -1) {
            mk_mem_free(fcgi_conf);
            mk_warn("[fastcgi] configuration %s error/missing, plugin disabled.", file);
        }
        else {
            serverList[count] = fcgi_conf;
            ++count;
        }
    }
    closedir( dir );

    return count > 0 ? 0 : -1;
}

int mk_fastcgi_plugin_exit()
{
    int i = 0;
    while (serverList[i])
    {
        mk_api->mem_free(serverList[i]);
        ++i;
    }
    return 0;
}

int mk_fastcgi_master_init(struct mk_server_config *config)
{
    (void) config;
    return 0;
}

void mk_fastcgi_worker_init()
{
}

struct mk_plugin_stage mk_plugin_stage_fastcgi = {
    .stage30        = &mk_fastcgi_stage30,
    .stage30_hangup = &mk_fastcgi_stage30_hangup
};

struct mk_plugin mk_plugin_fastcgi = {
    /* Identification */
    .shortname     = "fastcgi",
    .name          = "FastCGI Client",
    .version       = "1.0",
    .hooks         = MK_PLUGIN_STAGE,

    /* Init / Exit */
    .init_plugin   = mk_fastcgi_plugin_init,
    .exit_plugin   = mk_fastcgi_plugin_exit,

    /* Init Levels */
    .master_init   = mk_fastcgi_master_init,
    .worker_init   = mk_fastcgi_worker_init,

    /* Type */
    .stage         = &mk_plugin_stage_fastcgi
};
