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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "monkey.h"

#include "str.h"
#include "memory.h"
#include "http.h"
#include "http_status.h"
#include "socket.h"
#include "config.h"
#include "utils.h"
#include "file.h"
#include "cache.h"

long int mk_method_post_content_length(char *body)
{
    struct header_toc *toc = NULL;
    long int len;
    mk_pointer tmp;

    /* obs: Table of Content (toc) is created when the full
     * request has arrived, this function cannot be used from
     * mk_http_pending_request().
     */
    toc = mk_cache_get(mk_cache_header_toc);
    tmp = mk_request_header_find(toc, MK_KNOWN_HEADERS, body,
                                 mk_rh_content_length);

    if (!tmp.data) {
        return -1;
    }

    len = atoi(tmp.data);

    return len;
}


/* POST METHOD */
int mk_method_post(struct client_request *cr, struct request *sr)
{
    struct header_toc *toc = NULL;
    mk_pointer tmp;
    long content_length_post = 0;

    content_length_post = mk_method_post_content_length(cr->body);

    /* Length Required */
    if (content_length_post == -1) {
        mk_request_error(M_CLIENT_LENGTH_REQUIRED, cr, sr);
        return -1;
    }

    /* Bad request */
    if (content_length_post <= 0) {
        mk_request_error(M_CLIENT_BAD_REQUEST, cr, sr);
        return -1;
    }

    /* Content length too large */
    if (content_length_post >= cr->body_size) {
        mk_request_error(M_CLIENT_REQUEST_ENTITY_TOO_LARGE, cr, sr);
        return -1;
    }

    toc = mk_cache_get(mk_cache_header_toc);
    tmp = mk_request_header_find(toc, MK_KNOWN_HEADERS, sr->body.data,
                                 mk_rh_content_type);

    if (!tmp.data) {
        mk_request_error(M_CLIENT_BAD_REQUEST, cr, sr);
        return -1;
    }
    sr->content_type = tmp;
    sr->content_length = content_length_post;

    return 0;
}

/* Return POST variables sent in request */
mk_pointer mk_method_post_get_vars(char *body, int index)
{
    long len = 1;
    char *str = 0;
    mk_pointer p;

    str = mk_string_copy_substr(body, index, strlen(body));
    if (str) {
        len = strlen(str);
    }

    p.data = str;
    p.len = len;

    return p;
}
