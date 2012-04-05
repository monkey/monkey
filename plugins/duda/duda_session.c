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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>

#include "MKPlugin.h"
#include "duda_session.h"
#include "duda.h"

int _duda_session_create_store(const char *path)
{
    int ret;

    ret = mkdir(path, SESSION_DEFAULT_PERM);
    if (ret != 0) {
        mk_warn("Error creating SESSION_STORE_PATH '%s'", SESSION_STORE_PATH);
        return -1;
    }

    return 0;
}

/* Initialize a duda session for the webservice in question */
int duda_session_init(const char *store_name)
{
    int ret;
    char *path = NULL;
    unsigned long len;
    struct file_info finfo;

    ret = mk_api->file_get_info(SESSION_STORE_PATH, &finfo);
    if (ret != 0) {
        if (_duda_session_create_store(SESSION_STORE_PATH) != 0) {
            return -1;
        }
    }

    mk_api->str_build(&path, &len, "%s/%s", SESSION_STORE_PATH, store_name);
    ret = mk_api->file_get_info(path, &finfo);
    if (ret != 0) {
        if (_duda_session_create_store(path) != 0) {
            return -1;
        }
    }

    return 0;
}


static inline int _rand(int entropy)
{
    struct timeval tm;

    gettimeofday(&tm, NULL);
    srand(tm.tv_usec + entropy);

    return rand();
}

int duda_session_create(duda_request_t *dr, char **uuid)
{
    long e;

    /* generate UUID */
    e = ((long) &dr) + ((long) &dr->cs) + (dr->cs->socket);
    snprintf(*uuid, SESSION_UUID_SIZE, "%x%x-%x%x",
             _rand(e), _rand(e),
             _rand(e), _rand(e));

    return 0;
}
