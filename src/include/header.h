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

#include "request.h"
#include "logfile.h"

#ifndef MK_HEADER_H
#define MK_HEADER_H

#define MK_HEADER_BREAKLINE 1

/* 
 * Response headers: We handle this as static global data in order
 * to save some process time when building the response header.
 */

#define RESP_HTTP_OK "HTTP/1.1 200 OK"
#define LEN_RESP_HTTP_OK 15

#define RESP_HTTP_PARTIAL "HTTP/1.1 206 Partial Content"
#define LEN_RESP_HTTP_PARTIAL 28

#define RESP_REDIR_MOVED "HTTP/1.1 301 Moved Permanently"
#define LEN_RESP_REDIR_MOVED 30

#define RESP_REDIR_MOVED_T "HTTP/1.1 302 Found"
#define LEN_RESP_REDIR_MOVED_T 18

#define RESP_NOT_MODIFIED "HTTP/1.1 304 Not Modified"
#define LEN_RESP_NOT_MODIFIED 25

#define RESP_CLIENT_BAD_REQUEST "HTTP/1.1 400 Bad Request"
#define LEN_RESP_CLIENT_BAD_REQUEST 24

#define RESP_CLIENT_FORBIDDEN "HTTP/1.1 403 Forbidden"
#define LEN_RESP_CLIENT_FORBIDDEN 22

#define RESP_CLIENT_NOT_FOUND "HTTP/1.1 404 Not Found"
#define LEN_RESP_CLIENT_NOT_FOUND 22

#define RESP_CLIENT_METHOD_NOT_ALLOWED "HTTP/1.1 405 Method Not Allowed"
#define LEN_RESP_CLIENT_METHOD_NOT_ALLOWED 31

#define RESP_CLIENT_REQUEST_TIMEOUT "HTTP/1.1 408 Request Timeout"
#define LEN_RESP_CLIENT_REQUEST_TIMEOUT 28

#define RESP_CLIENT_LENGTH_REQUIRED "HTTP/1.1 411 Length Required"
#define LEN_RESP_CLIENT_LENGTH_REQUIRED 28

#define RESP_SERVER_INTERNAL_ERROR "HTTP/1.1 500 Internal Server Error"
#define LEN_RESP_SERVER_INTERNAL_ERROR 34

#define RESP_SERVER_HTTP_VERSION_UNSUP "HTTP/1.1 505 HTTP Version Not Supported"
#define LEN_RESP_SERVER_HTTP_VERSION_UNSUP 39


/* Short header values */
#define MK_HEADER_SHORT_DATE "Date"
#define MK_HEADER_SHORT_LOCATION "Location"
#define MK_HEADER_SHORT_CT "Content-Type"
#define MK_HEADER_SHORT_LOCATION "Location"

mk_pointer mk_header_short_date;
mk_pointer mk_header_short_location;
mk_pointer mk_header_short_ct;

/* Accept ranges */
#define MK_HEADER_ACCEPT_RANGES "Accept-Ranges: bytes"

#define MK_HEADER_CONN_KA "Connection: Keep-Alive" 
#define MK_HEADER_CONN_CLOSE "Connection: Close"

/* Transfer Encoding */
#define MK_HEADER_TE_TYPE_CHUNKED 0
#define MK_HEADER_TE_CHUNKED "Transfer-Encoding: Chunked"

/* mk pointers with response server headers */
mk_pointer mk_header_conn_ka;
mk_pointer mk_header_conn_close;
mk_pointer mk_header_accept_ranges;
mk_pointer mk_header_te_chunked;


int mk_header_send(int fd, struct client_request *cr,
		struct request *sr, struct log_info *s_log);
struct header_values *mk_header_create();

#endif

