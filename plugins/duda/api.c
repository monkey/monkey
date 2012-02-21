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

#include "MKPlugin.h"
#include "webservice.h"
#include "debug.h"
#include "api.h"

struct duda_api_objects *duda_api_master()
{
    struct duda_api_objects *objs;

    /* Alloc memory */
    objs = mk_api->mem_alloc(sizeof(struct duda_api_objects));
    objs->monkey = mk_api;
    objs->map    = mk_api->mem_alloc(sizeof(struct duda_api_map));
    objs->msg    = mk_api->mem_alloc(sizeof(struct duda_api_msg));
    objs->debug  = mk_api->mem_alloc(sizeof(struct duda_api_debug));

    /* MAP object */
    objs->map->interface_new = duda_interface_new;
    objs->map->interface_add_method = duda_interface_add_method;
    objs->map->method_new = duda_method_new;
    objs->map->method_add_param = duda_method_add_param;
    objs->map->param_new = duda_param_new;

    /* MSG object */
    objs->msg->info  = duda_debug_info;
    objs->msg->warn  = duda_debug_warn;
    objs->msg->err   = duda_debug_err;
    objs->msg->bug   = duda_debug_bug;
 
    return objs;
}
