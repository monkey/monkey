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

#include "mk_memory.h"

#ifndef MK_HTTP_H
#define MK_HTTP_H

/* Hard coded restrictions */
#define HTTP_DIRECTORY_BACKWARD ".."

/* Methods */
#define HTTP_METHOD_UNKNOWN        -1
#define HTTP_METHOD_GET             0
#define HTTP_METHOD_POST            1
#define HTTP_METHOD_HEAD            2
#define HTTP_METHOD_PUT             3
#define HTTP_METHOD_DELETE          4

#define HTTP_METHOD_GET_STR         "GET"
#define HTTP_METHOD_POST_STR        "POST"
#define HTTP_METHOD_HEAD_STR        "HEAD"
#define HTTP_METHOD_PUT_STR         "PUT"
#define HTTP_METHOD_DELETE_STR      "DELETE"

mk_pointer mk_http_method_get_p;
mk_pointer mk_http_method_post_p;
mk_pointer mk_http_method_head_p;
mk_pointer mk_http_method_put_p;
mk_pointer mk_http_method_delete_p;
mk_pointer mk_http_method_null_p;

#define HTTP_PROTOCOL_UNKNOWN (-1)
#define HTTP_PROTOCOL_09 (9)
#define HTTP_PROTOCOL_10 (10)
#define HTTP_PROTOCOL_11 (11)

#define HTTP_PROTOCOL_09_STR "HTTP/0.9"
#define HTTP_PROTOCOL_10_STR "HTTP/1.0"
#define HTTP_PROTOCOL_11_STR "HTTP/1.1"

mk_pointer mk_http_protocol_09_p;
mk_pointer mk_http_protocol_10_p;
mk_pointer mk_http_protocol_11_p;
mk_pointer mk_http_protocol_null_p;

#include "mk_request.h"
#include "mk_memory.h"

int mk_http_method_check(mk_pointer method);
mk_pointer mk_http_method_check_str(int method);
int mk_http_method_get(char *body);

int mk_http_protocol_check(char *protocol, int len);
mk_pointer mk_http_protocol_check_str(int protocol);

int mk_http_init(struct client_session *cs, struct session_request *sr);
int mk_http_keepalive_check(struct client_session *cs);
int mk_http_directory_redirect_check(struct client_session *cs,
                                     struct session_request *sr);
int mk_http_range_set(struct session_request *sr, long file_size);
int mk_http_range_parse(struct session_request *sr);

int mk_http_pending_request(struct client_session *cs);
int mk_http_send_file(struct client_session *cs, struct session_request *sr);
int mk_http_request_end(int socket);

#endif
