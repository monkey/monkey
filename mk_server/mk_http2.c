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
#include <monkey/mk_header.h>
#include <monkey/mk_scheduler.h>

int mk_http2_frame_header(char *buf, uint32_t length, uint8_t type,
                          uint32_t flags, void *data)
{
    struct mk_http2_frame *f = (struct mk_http2_frame *) buf;

    f->len_type = (length << 8 | type);
    f->flags    = flags;
    f->payload  = data;

    return sizeof(struct mk_http2_frame);
}

/* Handle an upgraded session */
int mk_http2_upgrade(struct mk_http_session *cs, struct mk_http_request *sr)
{
    mk_header_set_http_status(sr, MK_INFO_SWITCH_PROTOCOL);
    sr->headers.connection = MK_HEADER_CONN_UPGRADED;
    sr->headers.upgrade = MK_HEADER_UPGRADED_H2C;
    mk_header_prepare(cs, sr);


    return MK_HTTP_OK;
}

struct mk_sched_handler mk_http2_handler = {
  .name             = "http2",
  .cb_read          = NULL, //mk_http_sched_read,
  .cb_close         = NULL,
  .cb_done          = NULL,
  .sched_extra_size = 0,
  .capabilities     = MK_CAP_HTTP2
};
