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

#include "MKPlugin.h"
#include "duda_cookie.h"
#include "duda.h"

int duda_cookie_set(duda_request_t *dr, char *key, int key_len,
                    char *val, int val_len, int expires)
{
    mk_pointer exp;

    /*
     * Ugly hack: every session_request.headers contains a _extra_rows mk_iov
     * entry to add customized HTTP response headers. This is mostly used from
     * the plugins, as well by Duda when sending a response->header(...).
     *
     * We are in a very specific case, where the developer would like to set
     * some HTTP cookies, we want to avoid memory allocations if possible when
     * working with strings, so mk_api->header_add(..) cannot be used here as a
     * Cookie is composed by a few components like: key, value, expiration, etc.
     *
     * So here we will do a similar routine as mk_plugin_header_add(), if _extra_rows
     * has not been allocated, we will do it by our selfs and add the required iov
     * entries to compose the Cookie row.
     */
    if (!dr->sr->headers._extra_rows) {
        dr->sr->headers._extra_rows = mk_iov_create(MK_PLUGIN_HEADER_EXTRA_ROWS * 2, 0);
    }

    mk_api->iov_add_entry(dr->sr->headers._extra_rows, COOKIE_SET, sizeof(COOKIE_SET) -1,
                          mk_iov_none, MK_IOV_NOT_FREE_BUF);
    mk_api->iov_add_entry(dr->sr->headers._extra_rows, key, key_len,
                          mk_cookie_equal, MK_IOV_NOT_FREE_BUF);

    /* Destroy a cookie */
    if (expires == COOKIE_EXPIRE_TIME) {
        mk_api->iov_add_entry(dr->sr->headers._extra_rows, val, val_len,
                              mk_cookie_expire, MK_IOV_NOT_FREE_BUF);
        mk_api->iov_add_entry(dr->sr->headers._extra_rows,
                              mk_cookie_expire_value.data,
                              mk_cookie_expire_value.len,
                              mk_cookie_crlf, MK_IOV_NOT_FREE_BUF);
    }
    else if (expires > 0) {
        exp.data = mk_api->mem_alloc(COOKIE_MAX_DATE_LEN);
        exp.len = mk_api->time_to_gmt(&exp.data, expires);

        mk_api->iov_add_entry(dr->sr->headers._extra_rows, val, val_len,
                              mk_cookie_expire, MK_IOV_NOT_FREE_BUF);
        mk_api->iov_add_entry(dr->sr->headers._extra_rows,
                              exp.data, exp.len, mk_iov_none, MK_IOV_FREE_BUF);
    }
    else {
        mk_api->iov_add_entry(dr->sr->headers._extra_rows, val, val_len,
                              mk_cookie_crlf, MK_IOV_NOT_FREE_BUF);
    }

    return 0;
}

int duda_cookie_destroy(duda_request_t *dr, char *key, int key_len)
{
    return duda_cookie_set(dr, key, key_len, COOKIE_DELETED, sizeof(COOKIE_DELETED) -1,
                           COOKIE_EXPIRE_TIME);
}
