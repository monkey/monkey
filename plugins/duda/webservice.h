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

#include "MKPlugin.h"
#include "api.h"

struct duda_webservice ws;
struct mk_list _duda_interfaces;

struct plugin_api *monkey;
struct duda_api_map *map;
struct duda_api_msg *msg;
struct duda_api_debug *debug;

/* Duda Macros */
#define DUDA_REGISTER(app_name, app_path) struct duda_webservice ws = {app_name, app_path}
#define duda_service_init() do {                                        \
        monkey = api->monkey;                                           \
        map = api->map;                                                 \
        msg = api->msg;                                                 \
        debug = api->debug;                                             \
        mk_list_init(&_duda_interfaces);                                \
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
duda_method_t *duda_method_new(char *uid, void (*callback) (void *), int n_params);
duda_param_t *duda_param_new(char *uid, short int max_len);

void duda_interface_add_method(duda_method_t *method, duda_interface_t *iface);
void duda_method_add_param(duda_param_t *param, duda_method_t *method);

struct duda_api_objects *duda_new_api_objects();

/* 
 * Redefine messages macros 
 */

/*
#define mk_info(...) duda->_error(MK_INFO, __VA_ARGS__)
#define mk_err(...) duda->_error(MK_ERR, __VA_ARGS__)
#define mk_warn(...) duda->_error(MK_WARN, __VA_ARGS__)
#define mk_bug(condition) do {                  \
        if (mk_unlikely((condition)!=0)) {         \
            mk_api->_error(MK_BUG, "[%s] Bug found in %s() at %s:%d",    \
                           _plugin_info.shortname, __FUNCTION__, __FILE__, __LINE__); \
            abort();                                                    \
        }                                                               \
    } while(0)
*/

#define msg_info(...) mk_api->_error(MK_INFO, __VA_ARGS__)

#endif

