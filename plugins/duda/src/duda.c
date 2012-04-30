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
#include "duda.h"
#include "duda_conf.h"
#include "duda_event.h"
#include "duda_queue.h"
#include "duda_console.h"

MONKEY_PLUGIN("duda",                                     /* shortname */
              "Duda Web Services Framework",              /* name */
              VERSION,                                    /* version */
              MK_PLUGIN_CORE_THCTX | MK_PLUGIN_STAGE_30); /* hooks */


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
void *duda_load_symbol(void *handle, const char *symbol)
{
    void *s;
    char *err;

    dlerror();
    s = dlsym(handle, symbol);
    if ((err = dlerror()) != NULL) {
        return NULL;
    }

    return s;
}

/* Register the service interfaces into the main list of web services */
int duda_service_register(struct duda_api_objects *api, struct web_service *ws)
{
    int (*service_init) (struct duda_api_objects *);
    struct mk_list *head_iface, *head_method;
    struct duda_interface *entry_iface, *cs_iface;
    struct duda_method *entry_method, *cs_method;

    /* Load and invoke duda_main() */
    service_init = (int (*)()) duda_load_symbol(ws->handler, "duda_maina");
    if (!service_init) {
        mk_err("Duda: invalid web service %s", ws->app_name);
        exit(EXIT_FAILURE);
    }

    if (service_init(api) == 0) {
        PLUGIN_TRACE("[%s] duda_main()", ws->app_name);
        ws->map = (struct mk_list *) duda_load_symbol(ws->handler, "_duda_interfaces");
        ws->global = duda_load_symbol(ws->handler, "_duda_global_dist");

        /* Register Duda built-in interfaces: console */
        cs_iface  = api->map->interface_new("console");

        /* app/console/debug */
        cs_method = api->map->method_builtin_new("debug", duda_console_cb_debug, 0);
        api->map->interface_add_method(cs_method, cs_iface);

        /* app/console/map */
        cs_method = api->map->method_builtin_new("map", duda_console_cb_map, 0);
        api->map->interface_add_method(cs_method, cs_iface);

        mk_list_add(&cs_iface->_head, ws->map);


        /* Lookup callback functions for each registered method */
        mk_list_foreach(head_iface, ws->map) {
            entry_iface = mk_list_entry(head_iface, struct duda_interface, _head);
            mk_list_foreach(head_method, &entry_iface->methods) {
                entry_method = mk_list_entry(head_method, struct duda_method, _head);
                if (entry_method->callback) {
                    entry_method->cb_webservice = duda_load_symbol(ws->handler,
                                                                   entry_method->callback);
                    if (!entry_method->cb_webservice) {
                        mk_err("%s / callback not found '%s'", entry_method->uid, entry_method);
                        exit(EXIT_FAILURE);
                    }
                }
            }
        }
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
    struct mk_list *head_ws, *head_temp_ws;
    struct vhost_services *entry_vs;
    struct web_service *entry_ws;
    struct duda_api_objects *api;

    mk_list_foreach(head_vh, &services_list) {
        entry_vs = mk_list_entry(head_vh, struct vhost_services, _head);
        mk_list_foreach_safe(head_ws, head_temp_ws, &entry_vs->services) {
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
                mk_warn("Duda: service '%s' not found", entry_ws->app_name);
                mk_list_del(head_ws);
                mk_api->mem_free(entry_ws);
                continue;
            }

            /* Success */
            mk_info("Duda: loading service '%s'", entry_ws->app_name);
            mk_api->mem_free(service_path);

            /* Register service */
            api = duda_api_master();
            duda_service_register(api, entry_ws);
        }
    }

    return 0;
}

void duda_mem_init()
{
    int len;

    /* Init mk_pointer's */
    mk_api->pointer_set(&mk_cookie_crlf, COOKIE_CRLF);
    mk_api->pointer_set(&mk_cookie_equal, COOKIE_EQUAL);
    mk_api->pointer_set(&mk_cookie_set, COOKIE_SET);
    mk_api->pointer_set(&mk_cookie_expire, COOKIE_EXPIRE);
    mk_api->pointer_set(&mk_cookie_path, COOKIE_PATH);
    mk_api->pointer_set(&mk_cookie_semicolon, COOKIE_SEMICOLON);

    /* Default expire value */
    mk_cookie_expire_value.data = mk_api->mem_alloc_z(COOKIE_MAX_DATE_LEN);
    len = mk_api->time_to_gmt(&mk_cookie_expire_value.data, COOKIE_EXPIRE_TIME);
    mk_cookie_expire_value.len = len;
}

int _mkp_event_write(int sockfd)
{
    return duda_event_write_callback(sockfd);
}

void _mkp_core_prctx(struct server_config *config)
{
}

/* Thread context initialization */
void _mkp_core_thctx()
{
    struct mk_list *head_vs, *head_ws, *head_gl;
    struct mk_list *list_events_write;
    struct vhost_services *entry_vs;
    struct web_service *entry_ws;
    duda_global_t *entry_gl;
    void *data;

    /* Initialize some pointers */
    duda_mem_init();

    list_events_write = mk_api->mem_alloc(sizeof(struct mk_list));
    mk_list_init(list_events_write);
    pthread_setspecific(duda_global_events_write, (void *) list_events_write);

    /*
     * Load global data if applies, this is toooo recursive, we need to go through
     * every virtual host and check the services loaded for each one, then lookup
     * the global variables defined.
     */
    mk_list_foreach(head_vs, &services_list) {
        entry_vs = mk_list_entry(head_vs, struct vhost_services, _head);
        mk_list_foreach(head_ws, &entry_vs->services) {
            entry_ws = mk_list_entry(head_ws, struct web_service, _head);
            /* go around each global variable */
            mk_list_foreach(head_gl, entry_ws->global) {
                entry_gl = mk_list_entry(head_gl, duda_global_t, _head);
                /*
                 * If a global variable was defined we need to check if was requested
                 * to initialize it with a specific data returned by a callback
                 */
                data = NULL;
                if (entry_gl->callback) {
                    data = entry_gl->callback();
                }
                pthread_setspecific(entry_gl->key, data);
            }
        }
    }
}

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;

    /* Load configuration */
    duda_conf_main_init(confdir);
    duda_conf_vhost_init();
    duda_load_services();

    /* Global data / Thread scope */
    pthread_key_create(&duda_global_events_write, NULL);
    return 0;
}

/* Sets the duda_method structure variable in duda_request */
int duda_request_set_method(duda_request_t *dr)
{
    struct mk_list *head_iface, *head_method;
    struct duda_interface *entry_iface;
    struct duda_method *entry_method;

    /* Finds the corresponding duda_method structure */
    mk_list_foreach(head_iface, dr->ws_root->map) {
        entry_iface = mk_list_entry(head_iface, struct duda_interface, _head);

        if (entry_iface->uid_len == dr->interface.len &&
            strncmp(entry_iface->uid, dr->interface.data, dr->interface.len) == 0) {

            mk_list_foreach(head_method, &entry_iface->methods) {
                entry_method = mk_list_entry(head_method, struct duda_method, _head);
                if (entry_method->uid_len == dr->method.len &&
                    strncmp(entry_method->uid, dr->method.data, dr->method.len) == 0) {
                    dr->_method = entry_method;
                    break;
                }
            }
            if(dr->_method) {
                break;
            }
        }
    }

    if(!dr->_method) {
        PLUGIN_TRACE("Invoked method not found");
        return -1;
    }

    PLUGIN_TRACE("Method %s invoked", entry_method->uid);
    return 0;
}


int duda_request_parse(struct session_request *sr,
                       struct duda_request *dr)
{
    short int last_field = MAP_WS_APP_NAME;
    unsigned int i = 0, len, val_len;
    int end;
    short int allowed_params = 0;
    struct mk_list *head_param = NULL;
    struct duda_param *entry_param;

    len = sr->uri_processed.len;

    while (i < len) {
        end = mk_api->str_search_n(sr->uri_processed.data + i, "/",
                                   MK_STR_SENSITIVE, len - i);

        if (end >= 0 && end + i < len) {
            end += i;

            if (i == end) {
                i++;
                continue;
            }

            val_len = end - i;
        }
        else {
            val_len = len - i;
            end = len;
        }

        switch (last_field) {
        case MAP_WS_APP_NAME:
            dr->appname.data = sr->uri_processed.data + i;
            dr->appname.len  = val_len;
            last_field = MAP_WS_INTERFACE;
            break;
        case MAP_WS_INTERFACE:
            dr->interface.data = sr->uri_processed.data + i;
            dr->interface.len  = val_len;
            last_field = MAP_WS_METHOD;
            break;
        case MAP_WS_METHOD:
            dr->method.data    = sr->uri_processed.data + i;
            dr->method.len     = val_len;
            last_field = MAP_WS_PARAM;
            if(duda_request_set_method(dr) == -1) {
                console_debug(dr, "Error: unknown method");
                return -1;
            }
            allowed_params = dr->_method->num_params;
            break;
        case MAP_WS_PARAM:
            if (dr->n_params >= MAP_WS_MAX_PARAMS || dr->n_params >= allowed_params) {
                PLUGIN_TRACE("too much parameters (max=%i)",
                             (dr->n_params >= MAP_WS_MAX_PARAMS)?
                             MAP_WS_MAX_PARAMS:allowed_params);
                return -1;
            }
            if (dr->n_params == 0) {
                head_param = (&dr->_method->params)->next;
            }
            entry_param = mk_list_entry(head_param, struct duda_param, _head);
            if (val_len > entry_param->max_len && entry_param->max_len != 0) {
                PLUGIN_TRACE("too long param (max=%i)", entry_param->max_len);
                console_debug(dr, "Error: param %i is too long", dr->n_params);
                return -1;
            }
            dr->params[dr->n_params].data = sr->uri_processed.data + i;
            dr->params[dr->n_params].len  = val_len;
            dr->n_params++;
            last_field = MAP_WS_PARAM;
            head_param = head_param->next;
            break;
        }

        i = end + 1;
    }

    if (last_field < MAP_WS_METHOD) {
        console_debug(dr, "invalid method");
        return -1;
    }

    if ((dr->n_params) != allowed_params) {
        PLUGIN_TRACE("%i parameters required", allowed_params);
        console_debug(dr, "Error: unexpected number of parameters");
        return -1;
    }

    return 0;
}

int duda_service_end(duda_request_t *dr)
{
    int ret;

    /* call service end_callback() */
    if (dr->end_callback) {
        dr->end_callback(dr);
    }

    /* Finalize HTTP stuff with Monkey core */
    ret = mk_api->http_request_end(dr->cs->socket);

    /* free queue resources... */
    duda_queue_free(&dr->queue_out);
    mk_api->mem_free(dr);

    return ret;
}

int duda_service_run(struct client_session *cs,
                     struct session_request *sr,
                     struct web_service *web_service)
{
    struct duda_request *dr;

    dr = mk_api->mem_alloc(sizeof(duda_request_t));
    if (!dr) {
        PLUGIN_TRACE("could not allocate enough memory");
        return -1;
    }

    /* service details */
    dr->ws_root = web_service;
    dr->n_params = 0;
    dr->cs = cs;
    dr->sr = sr;

    /* method invoked */
    dr->_method = NULL;

    /* callbacks */
    dr->end_callback = NULL;

    /* data queues */
    mk_list_init(&dr->queue_out);

    /* statuses */
    dr->_st_http_headers_sent = MK_FALSE;
    dr->_st_body_writes = 0;

    /* Parse request */
    if (duda_request_parse(sr, dr) != 0) {
        mk_api->mem_free(dr);
        return -1;
    }

    if (!dr->_method) {
        PLUGIN_TRACE("method not found");
        return -1;
    }

    if (dr->_method->cb_webservice) {
        PLUGIN_TRACE("CB %s()", dr->_method->callback);
        dr->_method->cb_webservice(dr);
    }
    else if (dr->_method->cb_builtin) {
        dr->_method->cb_builtin(dr);
    }

    return 0;
}

/*
 * Get webservice given the processed URI.
 *
 * Check the web services registered under the virtual host and try to do a
 * match with the web services name
 */
struct web_service *duda_get_service_from_uri(struct session_request *sr,
                                              struct vhost_services *vs_host)
{
    int pos;
    struct mk_list *head;
    struct web_service *ws_entry;

    /* get web service name limit */
    pos = mk_api->str_search_n(sr->uri_processed.data + 1, "/",
                               MK_STR_SENSITIVE,
                               sr->uri_processed.len - 1);
    if (pos <= 1) {
        return NULL;
    }

    /* match services */
    mk_list_foreach(head, &vs_host->services) {
        ws_entry = mk_list_entry(head, struct web_service, _head);
        if (strncmp(ws_entry->app_name,
                    sr->uri_processed.data + 1,
                    pos - 1) == 0) {
            PLUGIN_TRACE("WebService match: %s", ws_entry->app_name);
            return ws_entry;
        }
    }

    return NULL;
}


void _mkp_exit()
{

}

/*
 * Request handler: when the request arrives this callback is invoked.
 */
int _mkp_stage_30(struct plugin *plugin, struct client_session *cs,
                  struct session_request *sr)
{
    struct mk_list *head;
    struct vhost_services *vs_entry, *vs_match=NULL;
    struct web_service *web_service;

    /* we don't care about '/' request */
    if (sr->uri_processed.len > 1) {
        /* Match virtual host */
        mk_list_foreach(head, &services_list) {
            vs_entry = mk_list_entry(head, struct vhost_services, _head);
            if (sr->host_conf == vs_entry->host) {
                vs_match = vs_entry;
                break;
            }
        }

        if (!vs_match) {
            return MK_PLUGIN_RET_NOT_ME;
        }

        /* Match web service */
        web_service = duda_get_service_from_uri(sr, vs_match);
        if (!web_service) {
            return MK_PLUGIN_RET_NOT_ME;
        }

        if (duda_service_run(cs, sr, web_service) == 0) {
            return MK_PLUGIN_RET_CONTINUE;
        }
    }

    return MK_PLUGIN_RET_NOT_ME;
}
