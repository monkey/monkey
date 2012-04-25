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

#ifndef DUDA_SESSION_H
#define DUDA_SESSION_H

#include "duda.h"

#define SESSION_STORE_PATH     "/dev/shm/duda_sessions"
#define SESSION_DEFAULT_PERM   0700
#define SESSION_UUID_SIZE      128  /* 128 bytes */
#define SESSION_KEY            "DUDA_SESSION"

struct mk_list session_list;

struct duda_api_session {
    int (*init)     ();
    int (*create)   (duda_request_t *, char *, char *, int);
    int (*destroy)  (duda_request_t *, char *);
    void *(*get)    (duda_request_t *, char *);
    int (*isset)    (duda_request_t *, char *);
};

struct duda_api_session *duda_session_object();
int duda_session_init();
int duda_session_create(duda_request_t *dr, char *name, char *value, int expires);
int duda_session_destroy(duda_request_t *dr, char *name);
void *duda_session_get(duda_request_t *dr, char *name);
int duda_session_isset(duda_request_t *dr, char *name);

#endif
