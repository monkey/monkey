/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
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

#include <dlfcn.h>

#include "MKPlugin.h"

#include "conf.h"
#include "request.h"

MONKEY_PLUGIN("duda",                                     /* shortname */
              "Duda Web Services Framework",              /* name */
              VERSION,                                    /* version */
              MK_PLUGIN_CORE_THCTX | MK_PLUGIN_STAGE_30); /* hooks */


/* Load a shared library (service) */
void *duda_load_library(const char *path)
{
    void *handle;

    handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
        mk_warn("dlopen() %s", dlerror());
    }

    return handle;
}

/* get specific symbol from the library */
void *duda_load_symbol(void *handler, const char *symbol)
{
    void *s;
    char *err;

    dlerror();
    s = dlsym(handler, symbol);
    if ((err = dlerror()) != NULL) {
        return NULL;
    }

    return s;
}

int duda_service_register(struct web_service *ws)
{
    int (*map)();

    /* Load interfaces map */
    map = (int (*)()) duda_load_symbol(ws->handler, "duda_map");
    if (map() == 0) {
        ws->map = duda_load_symbol(ws->handler, "_duda_interfaces");
    }

    return 0;
}

/*
 * Load the web service shared library for each definition found in the
 * virtual host
 */
int duda_load_services()
{
    char *service_path;
    unsigned long len;
    struct file_info finfo;
    struct mk_list *head_vh;
    struct mk_list *head_ws;
    struct vhost_services *entry_vs;
    struct web_service *entry_ws;

    mk_list_foreach(head_vh, &services_list) {
        entry_vs = mk_list_entry(head_vh, struct vhost_services, _head);
        mk_list_foreach(head_ws, &entry_vs->services) {
            entry_ws = mk_list_entry(head_ws, struct web_service, _head);

            service_path = NULL;
            mk_api->str_build(&service_path, &len,
                              "%s/%s.duda", services_root, entry_ws->app_name);

            /* Validate path, file and library load */
            if (mk_api->file_get_info(service_path, &finfo) != 0 ||
                finfo.is_file != MK_TRUE ||
                !(entry_ws->handler = duda_load_library(service_path))) {

                entry_ws->app_enabled = 0;
                mk_api->mem_free(service_path);
                continue;
            }

            /* Success */
            PLUGIN_TRACE("Library loaded: %s", entry_ws->app_name);
            mk_api->mem_free(service_path);

            /* Register service */
            duda_service_register(entry_ws);
        }
    }

    return 0;
}


void _mkp_core_prctx(struct server_config *config)
{

}

void _mkp_core_thctx()
{
}

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;

    /* Load configuration */
    duda_conf_main_init(confdir);
    duda_conf_vhost_init();
    duda_load_services();

    return 0;
}

void _mkp_exit()
{
}

/* 
 * Request handler: when the request arrives, this callback is invoked.
 */
int _mkp_stage_30(struct plugin *plugin, struct client_session *cs, 
                  struct session_request *sr)
{
    return MK_PLUGIN_RET_CONTINUE;
}
