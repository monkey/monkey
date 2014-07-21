/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
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

#ifndef MK_HTTP_H
#define MK_HTTP_H

/* Hard coded restrictions */
#define MK_HTTP_DIRECTORY_BACKWARD ".."

/* Methods */
#define MK_HTTP_METHOD_UNKNOWN      -1
#define MK_HTTP_METHOD_GET           0
#define MK_HTTP_METHOD_POST          1
#define MK_HTTP_METHOD_HEAD          2
#define MK_HTTP_METHOD_PUT           3
#define MK_HTTP_METHOD_DELETE        4
#define MK_HTTP_METHOD_OPTIONS       5

#define MK_HTTP_METHOD_GET_STR       "GET"
#define MK_HTTP_METHOD_POST_STR      "POST"
#define MK_HTTP_METHOD_HEAD_STR      "HEAD"
#define MK_HTTP_METHOD_PUT_STR       "PUT"
#define MK_HTTP_METHOD_DELETE_STR    "DELETE"
#define MK_HTTP_METHOD_OPTIONS_STR   "OPTIONS"

/* Available methods */
#define MK_HTTP_METHOD_AVAILABLE   \
    MK_HTTP_METHOD_GET_STR "," MK_HTTP_METHOD_POST_STR "," \
    MK_HTTP_METHOD_HEAD_STR "," MK_HTTP_METHOD_PUT_STR "," \
    MK_HTTP_METHOD_DELETE_STR "," MK_HTTP_METHOD_OPTIONS_STR  \
    MK_CRLF

#define MK_HTTP_PROTOCOL_UNKNOWN (-1)
#define MK_HTTP_PROTOCOL_09 (9)
#define MK_HTTP_PROTOCOL_10 (10)
#define MK_HTTP_PROTOCOL_11 (11)

#define MK_HTTP_PROTOCOL_09_STR "HTTP/0.9"
#define MK_HTTP_PROTOCOL_10_STR "HTTP/1.0"
#define MK_HTTP_PROTOCOL_11_STR "HTTP/1.1"

#include "mk_memory.h"

extern const mk_ptr_t mk_http_method_get_p;
extern const mk_ptr_t mk_http_method_post_p;
extern const mk_ptr_t mk_http_method_head_p;
extern const mk_ptr_t mk_http_method_put_p;
extern const mk_ptr_t mk_http_method_delete_p;
extern const mk_ptr_t mk_http_method_options_p;
extern const mk_ptr_t mk_http_method_null_p;

extern const mk_ptr_t mk_http_protocol_09_p;
extern const mk_ptr_t mk_http_protocol_10_p;
extern const mk_ptr_t mk_http_protocol_11_p;
extern const mk_ptr_t mk_http_protocol_null_p;

#include "mk_request.h"

int mk_http_method_check(mk_ptr_t method);
mk_ptr_t mk_http_method_check_str(int method);
int mk_http_method_get(char *body);

int mk_http_protocol_check(char *protocol, int len);
mk_ptr_t mk_http_protocol_check_str(int protocol);

int mk_http_init(struct client_session *cs, struct session_request *sr);
int mk_http_keepalive_check(struct client_session *cs);

int mk_http_pending_request(struct client_session *cs);
int mk_http_send_file(struct client_session *cs, struct session_request *sr);
int mk_http_request_end(int socket);

#endif
