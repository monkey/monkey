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
#include "webservice.h"
#include "debug.h"
#include "duda.h"
#include "api.h"
#include "event.h"

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
    dr->sr->headers.content_length = dr->body_buffer->total_len;

    r = mk_api->header_send(dr->cs->socket, dr->cs, dr->sr);
    if (r != 0) {
        /* FIXME: Console error */
        return -1;
    }

    /* Change flag status */
    dr->_st_http_headers_sent = MK_TRUE;
    return 0;
}

/* Send body buffers data to the remote socket */
int __body_flush(duda_request_t *dr)
{
    int i;
    int count = 0;
    int bytes_sent, bytes_to;
    int reset_to = -1;

    bytes_sent = mk_api->socket_sendv(dr->cs->socket, dr->body_buffer);
    PLUGIN_TRACE("body_flush: %i/%i", bytes_sent, dr->body_buffer->total_len);
    /*
     * If the call sent less data than total, we must modify the mk_iov struct
     * to mark the buffers already processed and set them with with length = zero,
     * so on the next calls to this function the Monkey will skip buffers with bytes
     * length = 0.
     */
    if (bytes_sent < dr->body_buffer->total_len) {
        /* Go around each buffer entry and check where the offset took place */
        for (i = 0; i < dr->body_buffer->iov_idx; i++) {
            if (count + dr->body_buffer->io[i].iov_len == bytes_sent) {
                reset_to = 1;
                break;
            }
            else if (bytes_sent < (count + dr->body_buffer->io[i].iov_len)) {
                reset_to = i - 1;
                bytes_to = (bytes_sent - count);
                dr->body_buffer->io[i].iov_base += bytes_to;
                dr->body_buffer->io[i].iov_len  = dr->body_buffer->io[i].iov_len - bytes_to;
                break;
            }
            count += dr->body_buffer->io[i].iov_len;
        }

        /* Reset entries */
        for (i = 0; i <= reset_to; i++) {
            dr->body_buffer->io[i].iov_len = 0;
        }

        dr->body_buffer->total_len -= bytes_sent;

#ifdef TRACE
        PLUGIN_TRACE("new total len: %i (iov_idx=%i)",
                     dr->body_buffer->total_len,
                     dr->body_buffer->iov_idx);
        int j;

        for (j=0; j<dr->body_buffer->iov_idx; j++) {
            PLUGIN_TRACE("io[%i] = %i", j, dr->body_buffer->io[j].iov_len);
        }
#endif

        /*
         * As pending data exists, we should check and possibly add this
         * request to the events manager
         */
        if (duda_event_is_registered_write(dr, DUDA_EVENT_BODYFLUSH) == MK_FALSE) {
            duda_event_register_write(dr, DUDA_EVENT_BODYFLUSH);
        }
    }

    /* Successfully end ? */
    if (bytes_sent == dr->body_buffer->total_len) {
        if (duda_event_is_registered_write(dr, DUDA_EVENT_BODYFLUSH) == MK_TRUE) {
            PLUGIN_TRACE("Unregister body_flush");
            duda_event_unregister_write(dr, DUDA_EVENT_BODYFLUSH);
        }
        return 0;
    }

    return bytes_sent;
}


/* set HTTP response status */
int _http_status(duda_request_t *dr, int status)
{
    mk_api->header_set_http_status(dr->sr, status);
    return 0;
}

/* add a new HTTP response header */
int _http_header(duda_request_t *dr, char *row, int len)
{
    mk_api->header_add(dr->sr, row, len);
    return 0;
}

/* Compose the body_buffer */
int _body_write(duda_request_t *dr, char *raw, int len)
{
    int size;

    if (!dr->body_buffer) {
        dr->body_buffer = mk_api->iov_create(BODY_BUFFER_SIZE, 0);
        dr->body_buffer_size = BODY_BUFFER_SIZE;
    }

    /* perform realloc if body_write() is called more than body_buffer_size */
    if (dr->body_buffer->iov_idx >= dr->body_buffer->size)  {
        size = dr->body_buffer_size + BODY_BUFFER_SIZE;
        if (mk_api->iov_realloc(dr->body_buffer, size) == -1) {
            return -1;
        }
        dr->body_buffer_size = size;
    }

    /* Link data */
    mk_api->iov_add_entry(dr->body_buffer, raw, len, mk_iov_none, MK_IOV_NOT_FREE_BUF);

    return 0;
}

/* Finalize the response process */
int _end_response(duda_request_t *dr, void (*end_cb) (duda_request_t *))
{
    int ret;

    dr->end_callback = end_cb;
    __http_send_headers_safe(dr);
    ret = __body_flush(dr);

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
    objs->monkey   = mk_api;
    objs->map      = mk_api->mem_alloc(sizeof(struct duda_api_map));
    objs->msg      = mk_api->mem_alloc(sizeof(struct duda_api_msg));
    objs->response = mk_api->mem_alloc(sizeof(struct duda_api_response));
    objs->debug    = mk_api->mem_alloc(sizeof(struct duda_api_debug));

    /* MAP object */
    objs->map->interface_new = duda_interface_new;
    objs->map->interface_add_method = duda_interface_add_method;
    objs->map->method_new = duda_method_new;
    objs->map->method_add_param = duda_method_add_param;
    objs->map->param_new = duda_param_new;

    /* MSG object */
    objs->msg->info  = duda_debug_info;
    objs->msg->warn  = duda_debug_warn;
    objs->msg->err   = duda_debug_err;
    objs->msg->bug   = duda_debug_bug;

    /* RESPONSE object */
    objs->response->http_status = _http_status;
    objs->response->http_header = _http_header;
    objs->response->body_write = _body_write;
    objs->response->end = _end_response;

    /* FIXME - DEBUG object */

    return objs;
}
