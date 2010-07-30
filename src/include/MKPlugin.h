/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P. <edsiper@gmail.com>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef MONKEY_PLUGIN_H
#define MONKEY_PLUGIN_H

/* Monkey Headers */
#include "plugin.h"
#include "http.h"

/* Registration variables */
mk_plugin_data_t _shortname;
mk_plugin_data_t _name;
mk_plugin_data_t _version;
mk_plugin_hook_t _hooks;

/* global vars */
struct plugin_api *mk_api;
mk_plugin_key_t _mkp_data;


#define MONKEY_PLUGIN(a, b, c, d)                   \
    struct plugin_info _plugin_info = {a, b, c, d}

#endif
