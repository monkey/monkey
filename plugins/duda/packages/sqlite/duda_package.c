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

#include "duda_api.h"
#include "duda_package.h"
#include "sqlite.h"

struct duda_api_sqlite *get_sqlite_api()
{
    struct duda_api_sqlite *sqlite;

    /* Alloc object */
    sqlite = malloc(sizeof(struct duda_api_sqlite));

    /* Map API calls */
    sqlite->open       = sql_open;
    sqlite->dump       = sql_dump;
    sqlite->step       = sql_step;
    sqlite->get_int    = sqlite3_column_int;
    sqlite->get_double = sqlite3_column_double;
    sqlite->get_text   = sqlite3_column_text;

    sqlite->done       = sqlite3_finalize;
    sqlite->exec       = sql_exec;
    sqlite->close      = sql_close;

    return sqlite;
}

duda_package_t *init_duda_package()
{
    duda_package_t *dpkg = malloc(sizeof(duda_package_t));

    sql_init();

    dpkg->name    = "sqlite";
    dpkg->version = "0.1";
    dpkg->api     = get_sqlite_api();

    return dpkg;
}
