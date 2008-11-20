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
 * header response: We handle this as static global data in order
 * to save some process time when building the response header.
 */

#define MK_HR_HTTP_OK "HTTP/1.1 200 OK"
#define MK_HR_HTTP_PARTIAL "HTTP/1.1 206 Partial Content"
#define MK_HR_REDIR_MOVED "HTTP/1.1 301 Moved Permanently"
#define MK_HR_REDIR_MOVED_T "HTTP/1.1 302 Found"
#define MK_HR_NOT_MODIFIED "HTTP/1.1 304 Not Modified"
#define MK_HR_CLIENT_BAD_REQUEST "HTTP/1.1 400 Bad Request"
#define MK_HR_CLIENT_FORBIDDEN "HTTP/1.1 403 Forbidden"
#define MK_HR_CLIENT_NOT_FOUND "HTTP/1.1 404 Not Found"
#define MK_HR_CLIENT_METHOD_NOT_ALLOWED "HTTP/1.1 405 Method Not Allowed"
#define MK_HR_CLIENT_REQUEST_TIMEOUT "HTTP/1.1 408 Request Timeout"
#define MK_HR_CLIENT_LENGTH_REQUIRED "HTTP/1.1 411 Length Required"
#define MK_HR_SERVER_INTERNAL_ERROR "HTTP/1.1 500 Internal Server Error"
#define MK_HR_SERVER_NOT_IMPLEMENTED "HTTP/1.1 501 Method Not Implemented"
#define MK_HR_SERVER_HTTP_VERSION_UNSUP "HTTP/1.1 505 HTTP Version Not Supported"

/* mk pointer for header responses */
mk_pointer mk_hr_http_ok;
mk_pointer mk_hr_http_partial;
mk_pointer mk_hr_redir_moved;
mk_pointer mk_hr_redir_moved_t;
mk_pointer mk_hr_not_modified;
mk_pointer mk_hr_client_bad_request;
mk_pointer mk_hr_client_forbidden;
mk_pointer mk_hr_client_not_found;
mk_pointer mk_hr_client_method_not_allowed;
mk_pointer mk_hr_client_request_timeout;
mk_pointer mk_hr_client_length_required;
mk_pointer mk_hr_server_internal_error;
mk_pointer mk_hr_server_not_implemented;
mk_pointer mk_hr_server_http_version_unsup;

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

