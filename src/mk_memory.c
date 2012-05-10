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

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "monkey.h"
#include "mk_config.h"
#include "mk_memory.h"
#include "mk_request.h"
#include "mk_header.h"
#include "mk_http.h"
#include "mk_iov.h"
#include "mk_user.h"

inline ALLOCSZ_ATTR(1)
void *mk_mem_malloc(const size_t size)
{
    void *aux = malloc(size);

    if (!aux && size) {
        perror("malloc");
        return NULL;
    }

    return aux;
}

inline ALLOCSZ_ATTR(1)
void *mk_mem_malloc_z(const size_t size)
{
    void *buf = calloc(1, size);
    if (!buf)
        return NULL;

    return buf;
}

inline ALLOCSZ_ATTR(2)
void *mk_mem_realloc(void *ptr, const size_t size)
{
    void *aux = realloc(ptr, size);

    if (!aux && size) {
        perror("realloc");
        return NULL;
    }

    return aux;
}

void mk_mem_free(void *ptr)
{
    free(ptr);
}

mk_pointer mk_pointer_create(char *buf, long init, long end)
{
    mk_pointer p;

    mk_pointer_reset(&p);
    p.data = buf + init;

    if (init != end) {
        p.len = (end - init);
    }
    else {
        p.len = 1;
    }

    return p;
}

void mk_pointer_reset(mk_pointer * p)
{
    p->data = NULL;
    p->len = 0;
}

void mk_pointer_free(mk_pointer * p)
{
    mk_mem_free(p->data);
    p->len = 0;
}

char *mk_pointer_to_buf(mk_pointer p)
{
    char *buf;

    buf = mk_mem_malloc(p.len + 1);
    memcpy(buf, p.data, p.len);
    buf[p.len] = '\0';

    return (char *) buf;
}

void mk_pointer_print(mk_pointer p)
{
    unsigned int i;

    printf("\nDEBUG MK_POINTER: '");
    for (i = 0; i < p.len && p.data != NULL; i++) {
        printf("%c", p.data[i]);
    }
    printf("'");
    fflush(stdout);
}

void mk_pointer_set(mk_pointer *p, char *data)
{
    p->data = data;
    p->len = strlen(data);
}

void mk_mem_pointers_init()
{
    /* Short server response headers */
    mk_pointer_set(&mk_header_short_date, MK_HEADER_SHORT_DATE);
    mk_pointer_set(&mk_header_short_location, MK_HEADER_SHORT_LOCATION);
    mk_pointer_set(&mk_header_short_ct, MK_HEADER_SHORT_CT);

    /* Request vars */
    mk_pointer_set(&mk_crlf, MK_CRLF);
    mk_pointer_set(&mk_endblock, MK_ENDBLOCK);

    /* Client headers */
    mk_pointer_set(&mk_rh_accept, RH_ACCEPT);
    mk_pointer_set(&mk_rh_accept_charset, RH_ACCEPT_CHARSET);
    mk_pointer_set(&mk_rh_accept_encoding, RH_ACCEPT_ENCODING);
    mk_pointer_set(&mk_rh_accept_language, RH_ACCEPT_LANGUAGE);
    mk_pointer_set(&mk_rh_connection, RH_CONNECTION);
    mk_pointer_set(&mk_rh_cookie, RH_COOKIE);
    mk_pointer_set(&mk_rh_content_length, RH_CONTENT_LENGTH);
    mk_pointer_set(&mk_rh_content_range, RH_CONTENT_RANGE);
    mk_pointer_set(&mk_rh_content_type, RH_CONTENT_TYPE);
    mk_pointer_set(&mk_rh_if_modified_since, RH_IF_MODIFIED_SINCE);
    mk_pointer_set(&mk_rh_host, RH_HOST);
    mk_pointer_set(&mk_rh_last_modified, RH_LAST_MODIFIED);
    mk_pointer_set(&mk_rh_last_modified_since, RH_LAST_MODIFIED_SINCE);
    mk_pointer_set(&mk_rh_referer, RH_REFERER);
    mk_pointer_set(&mk_rh_range, RH_RANGE);
    mk_pointer_set(&mk_rh_user_agent, RH_USER_AGENT);

    /* Server response normal headers */
    mk_pointer_set(&mk_header_conn_ka, MK_HEADER_CONN_KA);
    mk_pointer_set(&mk_header_conn_close, MK_HEADER_CONN_CLOSE);
    mk_pointer_set(&mk_header_content_length, MK_HEADER_CONTENT_LENGTH);
    mk_pointer_set(&mk_header_content_encoding, MK_HEADER_CONTENT_ENCODING);
    mk_pointer_set(&mk_header_accept_ranges, MK_HEADER_ACCEPT_RANGES);
    mk_pointer_set(&mk_header_te_chunked, MK_HEADER_TE_CHUNKED);
    mk_pointer_set(&mk_header_last_modified, MK_HEADER_LAST_MODIFIED);

    mk_iov_separators_init();

    /* Server */
    mk_pointer_set(&mk_monkey_protocol, HTTP_PROTOCOL_11_STR);

    /* HTTP */
    mk_pointer_set(&mk_http_method_get_p, HTTP_METHOD_GET_STR);
    mk_pointer_set(&mk_http_method_post_p, HTTP_METHOD_POST_STR);
    mk_pointer_set(&mk_http_method_head_p, HTTP_METHOD_HEAD_STR);
    mk_pointer_set(&mk_http_method_put_p, HTTP_METHOD_PUT_STR);
    mk_pointer_set(&mk_http_method_delete_p, HTTP_METHOD_DELETE_STR);
    mk_pointer_reset(&mk_http_method_null_p);

    mk_pointer_set(&mk_http_protocol_09_p, HTTP_PROTOCOL_09_STR);
    mk_pointer_set(&mk_http_protocol_10_p, HTTP_PROTOCOL_10_STR);
    mk_pointer_set(&mk_http_protocol_11_p, HTTP_PROTOCOL_11_STR);
    mk_pointer_reset(&mk_http_protocol_null_p);

}

