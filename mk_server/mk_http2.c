/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#define _GNU_SOURCE

#include <monkey/mk_http2.h>
#include <monkey/mk_http2_settings.h>
#include <monkey/mk_header.h>
#include <monkey/mk_scheduler.h>

/* HTTP/2 Connection Preface */
#define MK_HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
static mk_ptr_t http2_preface = {
    .data = MK_HTTP2_PREFACE,
    .len  = sizeof(MK_HTTP2_PREFACE) - 1
};

static struct mk_http2_session *mk_http2_session_create()
{
    struct mk_http2_session *h2s;

    h2s = mk_mem_malloc(sizeof(struct mk_http2_session));
    if (!h2s) {
        return NULL;
    }
    h2s->buffer = NULL;
    h2s->buffer_length = 0;
    h2s->buffer_size = sizeof(h2s->buffer_fixed);
    h2s->buffer = h2s->buffer_fixed;

    return h2s;
}

static int mk_http2_session_destroy(struct mk_http2_session *h2s)
{
    if (h2s->buffer != h2s->buffer_fixed) {
        mk_mem_free(h2s->buffer);
    }
    mk_mem_free(h2s);
    return 0;
}

static int mk_http2_frame_header(char *buf, uint32_t length, uint8_t type,
                                 uint32_t flags, void *data)
{
    struct mk_http2_frame *f = (struct mk_http2_frame *) buf;

    f->len_type = (length << 8 | type);
    f->flags    = flags;
    f->payload  = data;

    return sizeof(struct mk_http2_frame);
}

/* Handle an upgraded session */
static int mk_http2_upgrade(void *cs, void *sr)
{
    struct mk_http_session *s = cs;
    struct mk_http_request *r = sr;
    struct mk_http2_session *h2s;

    mk_header_set_http_status(r, MK_INFO_SWITCH_PROTOCOL);
    r->headers.connection = MK_HEADER_CONN_UPGRADED;
    r->headers.upgrade = MK_HEADER_UPGRADED_H2C;
    mk_header_prepare(s, r);

    h2s = mk_http2_session_create();
    if (!h2s) {
        return -1;
    }

    h2s->status = MK_HTTP2_UPGRADED;
    s->conn->data = h2s;

    return MK_HTTP_OK;
}

static int mk_http2_sched_read(struct mk_sched_conn *conn,
                               struct mk_sched_worker *worker)
{
    int bytes;
    int new_size;
    int available;
    char *tmp;
    struct mk_http2_session *h2s;
    (void) worker;

    h2s = conn->data;
    available = h2s->buffer_size - h2s->buffer_length;
    if (available == 0) {
        new_size = h2s->buffer_size + MK_HTTP2_CHUNK;
        if (h2s->buffer == h2s->buffer_fixed) {
            h2s->buffer = mk_mem_malloc(new_size);
            if (!h2s->buffer) {
                /* FIXME: send internal server error ? */
                return -1;
            }
            memcpy(h2s->buffer, h2s->buffer_fixed, h2s->buffer_length);
            MK_TRACE("[FD %i] Buffer new size: %i, length: %i",
                     conn->event.fd, new_size, h2s->buffer_length);
        }
        else {
            MK_TRACE("[FD %i] Buffer realloc from %i to %i",
                     conn->event.fd, h2s->buffer_size, new_size);
            tmp = mk_mem_realloc(h2s->buffer, new_size);
            if (tmp) {
                h2s->buffer = tmp;
                h2s->buffer_size = new_size;
            }
            else {
                /* FIXME: send internal server error ? */
                return -1;
            }

        }
    }

    /* Read the incoming data */
    bytes = mk_sched_conn_read(conn,
                               h2s->buffer,
                               h2s->buffer_size - h2s->buffer_length);
    if (bytes == 0) {
        errno = 0;
        return -1;
    }
    else if (bytes == -1) {
        return -1;
    }

    h2s->buffer_length += bytes;

    /* Upgraded connections from HTTP/1.x requires the preface */
    if (h2s->status == MK_HTTP2_UPGRADED) {
        if (h2s->buffer_length >= http2_preface.len) {
            if (memcmp(h2s->buffer,
                       http2_preface.data, http2_preface.len) != 0) {
                MK_TRACE("[FD %i] Invalid HTTP/2 preface",
                         conn->event.fd);
                return 0;
            }
            MK_TRACE("[FD %i] HTTP/2 preface OK",
                     conn->event.fd);

            /* Send out our default settings */
            mk_stream_set(&h2s->stream_settings,
                          MK_STREAM_RAW,
                          &conn->channel,
                          MK_HTTP2_SETTINGS_DEFAULT,
                          sizeof(MK_HTTP2_SETTINGS_DEFAULT) - 1,
                          NULL,
                          NULL, NULL, NULL);
        }
        else {
            return 0;
        }
    }

    return 0;
}


struct mk_sched_handler mk_http2_handler = {
    .name             = "http2",
    .cb_read          = mk_http2_sched_read,
    .cb_close         = NULL,
    .cb_done          = NULL,
    .cb_upgrade       = mk_http2_upgrade,
    .sched_extra_size = sizeof(struct mk_http2_session),
    .capabilities     = MK_CAP_HTTP2
};
