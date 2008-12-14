/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2008, Eduardo Silva P.
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

#ifndef MK_HTTP_H
#define MK_HTTP_H

/* Methods */
#define HTTP_METHOD_GET (0)
#define HTTP_METHOD_POST (1)
#define HTTP_METHOD_HEAD (2)

#define HTTP_METHOD_GET_STR "GET"
#define HTTP_METHOD_POST_STR "POST"
#define HTTP_METHOD_HEAD_STR "HEAD"

/* Method status */
#define METHOD_NOT_ALLOWED (-1)
#define METHOD_NOT_FOUND (-2)
#define METHOD_EMPTY (-3)

#define HTTP_PROTOCOL_UNKNOWN (-1)
#define HTTP_PROTOCOL_09 (9)
#define HTTP_PROTOCOL_10 (10)
#define HTTP_PROTOCOL_11 (11)

#define HTTP_PROTOCOL_09_STR "HTTP/0.9"
#define HTTP_PROTOCOL_10_STR "HTTP/1.0"
#define HTTP_PROTOCOL_11_STR "HTTP/1.1"

#include "request.h"
#include "memory.h"

int mk_http_method_check(char *method);
char *mk_http_method_check_str(int method);
int mk_http_method_get(char *body);

int mk_http_protocol_check(char *protocol);
char *mk_http_protocol_check_str(int protocol);

int mk_http_init(struct client_request *cr, struct request *sr);
int mk_http_keepalive_check(int socket, struct client_request *cr);
int mk_http_range_set(struct request *sr, long file_size);
int mk_http_range_parse(struct request *sr);

mk_pointer *mk_http_status_get(short int code);
void mk_http_status_list_init();
int mk_http_pendient_request(struct client_request *cr);

#endif
