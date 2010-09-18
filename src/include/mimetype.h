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

/* mimetype.c */

/* MIME Structs variables*/
#include "memory.h"
#include "list.h"

#define MIMETYPE_DEFAULT_TYPE "text/plain\r\n"
#define MIMETYPE_DEFAULT_NAME "default"

#define MAX_MIMETYPES_NOMBRE 15
#define MAX_MIMETYPES_TIPO 55
#define MAX_SCRIPT_BIN_PATH 255

struct mimetype
{
    char *name;
    mk_pointer type;

    struct mk_list _head;

};

struct mk_list *mimetype_list;

struct mimetype *mimetype_default;

void mk_mimetype_read_config();

int mk_mimetype_free(char **arr);
int mk_mimetype_add(char *name, char *type);

struct mimetype *mk_mimetype_find(mk_pointer * filename);
struct mimetype *mk_mimetype_cmp(char *name);
