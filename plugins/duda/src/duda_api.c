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
#include <stdarg.h>

#include "MKPlugin.h"

#include "duda_debug.h"
#include "duda_console.h"
#include "duda.h"
#include "duda_api.h"
#include "duda_param.h"
#include "duda_session.h"
#include "duda_xtime.h"
#include "duda_cookie.h"
#include "duda_package.h"
#include "duda_event.h"
#include "duda_queue.h"
#include "duda_global.h"
#include "duda_sendfile.h"
#include "duda_body_buffer.h"

#include "webservice.h"

/* Send HTTP response headers just once */
int __http_send_headers_safe(duda_request_t *dr)
{
    int r;

    if (dr->_st_http_headers_sent == MK_TRUE) {
        return -1;
    }

    if (dr->_st_body_writes > 0) {
        /* FIXME: Console error */
        return -1;
    }

    /* Calculate body length */
    dr->sr->headers.content_length = duda_queue_length(&dr->queue_out);

    r = mk_api->header_send(dr->cs->socket, dr->cs, dr->sr);
    if (r != 0) {
        /* FIXME: Console error */
        return -1;
    }

    /* Change flag status */
    dr->_st_http_headers_sent = MK_TRUE;
    return 0;
}

/* set HTTP response status */
int http_status(duda_request_t *dr, int status)
{
    mk_api->header_set_http_status(dr->sr, status);
    return 0;
}

/* add a new HTTP response header */
int http_header(duda_request_t *dr, char *row, int len)
{
    mk_api->header_add(dr->sr, row, len);
    return 0;
}

/* Compose the body_buffer */
int _body_print(duda_request_t *dr, char *raw, int len, int free)
{
    int ret;
    struct duda_body_buffer *body_buffer;
    struct duda_queue_item *item;

    item = duda_queue_last(&dr->queue_out);
    if (!item || item->type != DUDA_QTYPE_BODY_BUFFER) {
        body_buffer = duda_body_buffer_new();
        item = duda_queue_item_new(DUDA_QTYPE_BODY_BUFFER);
        item->data = body_buffer;
        duda_queue_add(item, &dr->queue_out);
    }
    else {
        body_buffer = item->data;
    }

    /* perform realloc if body_write() is called more than body_buffer_size */
    if (body_buffer->buf->iov_idx >= body_buffer->size)  {
        ret = duda_body_buffer_expand(body_buffer);
        if (ret == -1) {
            return -1;
        }
    }

    /* Link data */
    if (free == MK_TRUE) {
        mk_api->iov_add_entry(body_buffer->buf, raw, len, mk_iov_none, MK_IOV_FREE_BUF);
    }
    else {
        mk_api->iov_add_entry(body_buffer->buf, raw, len, mk_iov_none, MK_IOV_NOT_FREE_BUF);
    }

    return 0;
}

/* Enqueue a constant raw buffer */
int body_print(duda_request_t *dr, char *raw, int len)
{
    return _body_print(dr, raw, len, MK_FALSE);
}

/*
 * Format a new buffer and enqueue it contents, when the queue is flushed all reference
 * to the buffers created here are freed
 */
int body_printf(duda_request_t *dr, const char *format, ...)
{
    int ret;
    int n, size = 128;
    char *p, *np;
    va_list ap;

    if ((p = mk_api->mem_alloc(size)) == NULL) {
        return -1;
    }

    while (1) {
        /* Try to print in the allocated space. */
        va_start(ap, format);
        n = vsnprintf(p, size, format, ap);
        va_end(ap);
        /* If that worked, return the string. */
        if (n > -1 && n < size)
            break;

        size *= 2;  /* twice the old size */
        if ((np = mk_api->mem_realloc(p, size)) == NULL) {
            mk_api->mem_free(p);
            return - 1;
        } else {
            p = np;
        }
    }

    ret = _body_print(dr, p, n, MK_TRUE);
    if (ret == -1) {
        mk_api->mem_free(p);
    }

    return ret;
}

int sendfile_enqueue(duda_request_t *dr, char *path)
{
    struct duda_sendfile *sf;
    struct duda_queue_item *item;

    sf = duda_sendfile_new(path);

    if (!sf) {
        return -1;
    }

    item = duda_queue_item_new(DUDA_QTYPE_SENDFILE);
    item->data = sf;
    duda_queue_add(item, &dr->queue_out);

    return 0;
}

/* Finalize the response process */
int end_response(duda_request_t *dr, void (*end_cb) (duda_request_t *))
{
    int ret;

    dr->end_callback = end_cb;
    __http_send_headers_safe(dr);
    ret = duda_queue_flush(dr);

    if (ret == 0) {
        duda_service_end(dr);
    }

    return 0;
}

struct duda_api_objects *duda_api_master()
{
    struct duda_api_objects *objs;

    /* Alloc memory */
    objs = mk_api->mem_alloc(sizeof(struct duda_api_objects));
    objs->duda     = mk_api->mem_alloc(sizeof(struct duda_api_main));
    objs->monkey   = mk_api;
    objs->map      = mk_api->mem_alloc(sizeof(struct duda_api_map));
    objs->msg      = mk_api->mem_alloc(sizeof(struct duda_api_msg));
    objs->response = mk_api->mem_alloc(sizeof(struct duda_api_response));
    objs->debug    = mk_api->mem_alloc(sizeof(struct duda_api_debug));
    objs->global   = mk_api->mem_alloc(sizeof(struct duda_api_global));

    /* MAP Duda calls */
    objs->duda->package_load = duda_package_load;

    /* MAP object */
    objs->map->interface_new = duda_interface_new;
    objs->map->interface_add_method = duda_interface_add_method;
    objs->map->method_new = duda_method_new;
    objs->map->method_builtin_new = duda_method_builtin_new;

    objs->map->method_add_param = duda_method_add_param;
    objs->map->param_new = duda_param_new;

    /* MSG object */
    objs->msg->info  = duda_debug_info;
    objs->msg->warn  = duda_debug_warn;
    objs->msg->err   = duda_debug_err;
    objs->msg->bug   = duda_debug_bug;

    /* RESPONSE object */
    objs->response->http_status = http_status;
    objs->response->http_header = http_header;
    objs->response->body_print  = body_print;
    objs->response->body_printf = body_printf;
    objs->response->sendfile    = sendfile_enqueue;
    objs->response->end         = end_response;

    /* Assign Objects */
    objs->console = duda_console_object();
    objs->param   = duda_param_object();
    objs->session = duda_session_object();
    objs->xtime   = duda_xtime_object();
    objs->cookie  = duda_cookie_object();

    /* Global data (thread scope) */
    objs->global->set  = duda_global_set;
    objs->global->get  = duda_global_get;

    /* FIXME - DEBUG object */
#ifdef DEBUG
    objs->debug->stacktrace = mk_api->stacktrace;
#endif

    return objs;
}
