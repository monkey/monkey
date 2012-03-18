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

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

#include "sqlite.h"


/* just in case we need some specific setup in the future */
int sql_init()
{
    return 0;
}

sqlite3 *sql_open(const char *path)
{
    int ret;
    sqlite3 *db;

    ret = sqlite3_open(path, &db);
    if (ret != SQLITE_OK) {
        printf("SQLITE: Can't open database: %s\n", path);
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    /* Try to use asynchronous mode */
    sql_exec(db, "PRAGMA synchronous = OFF;");
    return db;
}

int sql_exec(sqlite3 *db, const char *query)
{
    int ret;
    char *err;

    ret = sqlite3_exec(db, query, NULL, 0, &err);
    if (ret != SQLITE_OK) {
        printf("SQLITE: SQL error: %s\n", err);
        return -1;
    }

    return 0;
}

int sql_close(sqlite3 *db)
{
    return sqlite3_close(db);
}
