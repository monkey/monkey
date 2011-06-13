/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P.
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

#include "MKPlugin.h"

/* Header stuff */
#define MK_AUTH_HEADER_REQUEST   "Authorization:"
#define MK_AUTH_HEADER_BASIC     "Basic "

/* Credentials length */
#define MK_AUTH_CREDENTIALS_LEN 256

/*
 * The plugin hold one struct per virtual host and link to the
 * locations and users file associated:
 *
 *                    +---------------------------------+
 *      struct vhost  >            vhost (1:N)          |
 *                    |     +---------+----------+      |
 *                    |     |         |          |      |
 *   struct location  > location  location    location  |
 *                    |     |         |          |      |
 *                    |     +----+----+          +      |
 *                    |          |               |      |
 *      struct users  >        users           users    |
 *                    +---------------------------------+
 *
 */

/* main index for locations under a virtualhost */
struct vhost {
    struct host *host;
    struct mk_list location;
    struct mk_list _head;
};

/* 
 * A location restrict a filesystem path with a list
 * of allowed users
 */
struct location {
    char *path;
    char *title;

    struct mk_list users;
    struct mk_list _head;
};

/* 
 * a list of users, this list belongs to a  
 * struct location 
 */
struct users {
    char user[128];
    char passwd_raw[256];
    unsigned char *passwd_decoded;

    struct mk_list _head;
};

struct mk_list users_list;


/* Thread key */
mk_pointer auth_header_request;
mk_pointer auth_header_basic;

#define SHA1_DIGEST_LEN 20
