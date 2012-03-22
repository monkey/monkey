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

#ifndef DUDA_WEBSERVICE_H
#define DUDA_WEBSERVICE_H

/* System headers */
#include <sys/types.h>
#include <sys/syscall.h>

/* Monkey specifics */
#include "MKPlugin.h"
#include "duda_api.h"
#include "duda_global.h"
#include "duda_package.h"

struct duda_webservice ws;
struct mk_list _duda_interfaces;
struct mk_list _duda_global_dist;

/* Objects exported to the web service */
struct plugin_api *monkey;
struct duda_api_map *map;
struct duda_api_msg *msg;
struct duda_api_response *response;
struct duda_api_debug *debug;
struct duda_api_params *params;
struct duda_api_global *global;
duda_package_t *pkg_temp;

/* Duda Macros */
#define DUDA_REGISTER(app_name, app_path) struct duda_webservice ws = {app_name, app_path}

#define duda_load_package(object, package)          \
    pkg_temp = api->duda->package_load(package);    \
    object = pkg_temp->api;

#define duda_service_init()                                             \
    monkey   = api->monkey;                                             \
    map      = api->map;                                                \
    msg      = api->msg;                                                \
    response = api->response;                                           \
    debug    = api->debug;                                              \
    params   = api->params;                                             \
    global   = api->global;                                             \
    mk_list_init(&_duda_interfaces);                                    \
    mk_list_init(&_duda_global_dist);

#define duda_global_init(key_t, cb) do {                                \
        /* Make sure the developer has initialized variables from duda_init() */ \
        if (getpid() != syscall(__NR_gettid)) {                         \
            /* FIXME: error handler */                                  \
            monkey->_error(MK_ERR,                                      \
                           "Duda: You can only define global vars inside duda_init()"); \
            exit(EXIT_FAILURE);                                         \
        }                                                               \
        pthread_key_create(&key_t.key, NULL);                           \
        key_t.callback = cb;                                            \
        mk_list_add(&key_t._head, &_duda_global_dist);                  \
    } while(0);

#define duda_service_add_interface(iface) do {              \
        mk_list_add(&iface->_head,  &_duda_interfaces);     \
    } while(0);

#define duda_service_ready() do {               \
        PLUGIN_TRACE("service ready");          \
        return 0;                               \
    } while(0);

#define duda_map_add_interface(iface) mk_list_add(&iface->_head,  _duda_interfaces)

/* API functions */
duda_interface_t *duda_interface_new(char *uid);
duda_method_t *duda_method_new(char *uid, char *callback, int n_params);
duda_param_t *duda_param_new(char *uid, short int max_len);

void duda_interface_add_method(duda_method_t *method, duda_interface_t *iface);
void duda_method_add_param(duda_param_t *param, duda_method_t *method);

struct duda_api_objects *duda_new_api_objects();

#endif

