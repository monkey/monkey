/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P. <edsiper@gmail.com>
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
    tmp = mk_request_header_find(toc, body, mk_rh_content_length);

    if (!tmp.data) {
        int pos_header;
        int pos_crlf;
        char *str_cl;

        /* Pre-parsing mode: Check if content-length was sent */
        pos_header = mk_string_search(body, RH_CONTENT_LENGTH, MK_STR_INSENSITIVE);
        if (pos_header <= 0) {
            return -1;
        }

        pos_crlf = mk_string_search(body + pos_header, MK_IOV_CRLF, MK_STR_SENSITIVE);
        if (pos_crlf <= 0) {
            return -1;
        }

        str_cl = mk_string_copy_substr(body + pos_header + mk_rh_content_length.len + 1,
                                       0, pos_header + pos_crlf);
        len = strtol(str_cl, (char **) NULL, 10);
        mk_mem_free(str_cl);

        return len;
    }

    len = strtol(tmp.data, (char **) NULL, 10);

    return len;
}

/* POST METHOD */
int mk_method_post(struct client_session *cs, struct session_request *sr)
{
    mk_pointer tmp;
    long content_length_post = 0;

    content_length_post = mk_method_post_content_length(cs->body);

    /* Length Required */
    if (content_length_post == -1) {
        mk_request_error(M_CLIENT_LENGTH_REQUIRED, cs, sr);
        return -1;
    }

    /* Bad request */
    if (content_length_post <= 0) {
        mk_request_error(M_CLIENT_BAD_REQUEST, cs, sr);
        return -1;
    }

    /* Content length too large */
    if (content_length_post >= cs->body_size) {
        mk_request_error(M_CLIENT_REQUEST_ENTITY_TOO_LARGE, cs, sr);
        return -1;
    }

    tmp = mk_request_header_find(sr->headers_toc, sr->body.data, mk_rh_content_type);
    if (!tmp.data) {
        mk_request_error(M_CLIENT_BAD_REQUEST, cs, sr);
        return -1;
    }
    sr->content_type = tmp;
    sr->content_length = content_length_post;

    return 0;
}

/* Return POST variables sent in request */
mk_pointer mk_method_post_get_vars(void *data, int size)
{
    mk_pointer p;

    p.data = data;
    p.len = size;

    return p;
}
