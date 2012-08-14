/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
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

#include "mk_memory.h"
#include "mk_list.h"

#ifndef MK_MIMETYPE_H
#define MK_MIMETYPE_H

#define MIMETYPE_DEFAULT_TYPE "text/plain\r\n"
#define MIMETYPE_DEFAULT_NAME "default"

struct mimetype
{
    const char *name;
    mk_pointer type;
};

/* amount of the top used mime types */
enum {
    MIME_COMMON=10
};

extern struct mimetype *mimetype_default;

int mk_mimetype_add(const char *name, const char *type, const int common);
void mk_mimetype_read_config(void);
struct mimetype *mk_mimetype_find(mk_pointer * filename);
struct mimetype *mk_mimetype_lookup(const char *name);
void mk_mimearr_sort();

#endif
