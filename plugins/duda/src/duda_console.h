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

#ifndef DUDA_CONSOLE_H
#define DUDA_CONSOLE_H

#include "duda.h"
#include "duda_api.h"

#define debug(dr, fmt, ...) _debug(dr, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define console_debug(dr, fmt, ...) duda_console_write(dr, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

struct duda_api_console {
    void (*_debug) (duda_request_t *, char *, int, char *, ...);
};

struct duda_api_console *duda_console_object();
void duda_console_cb_debug(duda_request_t *dr);
void duda_console_cb_map(duda_request_t *dr);
void duda_console_write(duda_request_t *dr, char *file, int line, char *format, ...);

#endif
