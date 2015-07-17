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

#ifndef MK_FASTCGI_H
#define MK_FASTCGI_H

#include <monkey/mk_api.h>

/*
 * Based on the information provided by the FastCGI spec, we use the
 * following adapted structures:
 *
 * http://www.fastcgi.com/drupal/node/6?q=node/22
 */
struct fcgi_record_header {
    uint8_t  version;
    uint8_t  type;
    uint16_t request_id;
    uint16_t content_length;
    uint16_t padding_length;
    uint8_t reserved;
};

struct fcgi_begin_request_body {
    uint16_t role;
    uint8_t flags;
    uint8_t reserved[5];
};

#define FCGI_VERSION_1               1
#define FCGI_RECORD_HEADER_SIZE      sizeof(struct fcgi_record_header)
#define FCGI_BEGIN_REQUEST_BODY_SIZE sizeof(struct fcgi_begin_request_body)
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3

/*
 * Values for type component of FCGI_Header
 */
#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10

/*
 * FastCGI Handler context, it keeps information of states and other
 * request/response references.
 */
struct fcgi_handler {
    struct mk_event event;       /* built-in event-loop data */
    int server_fd;               /* backend FastCGI server   */
    struct mk_http_session *cs;  /* HTTP session context     */
    struct mk_http_request *sr;  /* HTTP request context     */

    /* FastCGI */
    char fcgi_begin_record[FCGI_RECORD_HEADER_SIZE +
                           FCGI_BEGIN_REQUEST_BODY_SIZE];

    int buf_len;
    char buf_data[4096];

    struct mk_iov *iov;
    struct mk_list _head;
};

static inline void fcgi_encode16(void *a, unsigned b)
{
    unsigned char *c = a;

    c[0] = (unsigned char) (b >> 8);
    c[1] = (unsigned char) b;
}

struct fcgi_handler *fcgi_handler_new(struct mk_http_session *cs,
                                      struct mk_http_request *sr);

#endif
