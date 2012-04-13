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

#ifndef DUDA_PACKAGE_SQLITE_H
#define DUDA_PACKAGE_SQLITE_H

#include <sqlite3.h>
#include "duda_api.h"

struct sqlite_cb_data {
    duda_request_t *dr;
    void *data;
};

struct duda_api_sqlite {
    sqlite3 *(*open) (const char *);
    int (*dump)    (sqlite3 *, const char *, sqlite3_stmt **);
    int (*step)    (sqlite3_stmt *);

    /* retrieve fields from row */
    int (*get_int) (sqlite3_stmt *, int);
    double (*get_double) (sqlite3_stmt *, int);
    const unsigned char *(*get_text) (sqlite3_stmt *, int);

    int (*done)  (sqlite3_stmt *);
    int (*exec)  (duda_request_t *, sqlite3 *, const char *,
                  int (*) (struct sqlite_cb_data *, int, char **, char **), void *);
    int (*close) (sqlite3 *);
};

typedef struct duda_api_sqlite sqlite_object_t;
typedef sqlite3 sqlite_db_t;
typedef sqlite3_stmt sqlite_handle_t;

sqlite_object_t *sqlite;

int sql_init();

sqlite3 *sql_open(const char *path);
int sql_dump(sqlite3 *db, const char *query, sqlite3_stmt **handle);
int sql_exec(duda_request_t *dr, sqlite3 *db, const char *query,
             int (*callback) (void *, int, char **, char **), void *data);
int sql_step(sqlite3_stmt *handle);
int sql_close(sqlite3 *db);

#define SQLITE_FOREACH(handle) while (sqlite->step(handle) == SQLITE_ROW)

#endif
