/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2009, Eduardo Silva P.
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

/* cgi.c */
#include "memory.h"

#define MK_CGI_DOCUMENT_ROOT "DOCUMENT_ROOT"
#define MK_CGI_CONTENT_LENGTH "CONTENT_LENGTH"
#define MK_CGI_CONTENT_TYPE "CONTENT_TYPE"
#define MK_CGI_SERVER_ADDR "SERVER_ADDR"
#define MK_CGI_SERVER_NAME "SERVER_NAME"
#define MK_CGI_SERVER_PROTOCOL "SERVER_PROTOCOL"
#define MK_CGI_SERVER_SOFTWARE "SERVER_SOFTWARE"
#define MK_CGI_SERVER_SIGNATURE "SERVER_SIGNATURE"


#define MK_CGI_HTTP_USER_AGENT "HTTP_USER_AGENT"
#define MK_CGI_HTTP_ACCEPT "HTTP_ACCEPT"
#define MK_CGI_HTTP_ACCEPT_CHARSET "HTTP_ACCEPT_CHARSET"
#define MK_CGI_HTTP_ACCEPT_ENCODING "HTTP_ACCEPT_ENCODING"
#define MK_CGI_HTTP_ACCEPT_LANGUAGE "HTTP_ACCEPT_LANGUAGE"
#define MK_CGI_HTTP_HOST "HTTP_HOST"
#define MK_CGI_HTTP_COOKIE "HTTP_COOKIE"
#define MK_CGI_HTTP_REFERER "HTTP_REFERER"

#define MK_CGI_SERVER_PORT "SERVER_PORT"
#define MK_CGI_CGI_VERSION "CGI_VERSION"
#define MK_CGI_GATEWAY_INTERFACE "GATEWAY_INTERFACE"
#define MK_CGI_REMOTE_ADDR "REMOTE_ADDR"
#define MK_CGI_REQUEST_URI "REQUEST_URI"
#define MK_CGI_REQUEST_METHOD "REQUEST_METHOD"
#define MK_CGI_SCRIPT_NAME "SCRIPT_NAME"
#define MK_CGI_SCRIPT_FILENAME "SCRIPT_FILENAME"
#define MK_CGI_REMOTE_PORT "REMOTE_PORT"
#define MK_CGI_QUERY_STRING "QUERY_STRING"
#define MK_CGI_POST_VARS "POST_VARS"

mk_pointer mk_cgi_document_root;
mk_pointer mk_cgi_content_length;
mk_pointer mk_cgi_content_type;
mk_pointer mk_cgi_server_addr;
mk_pointer mk_cgi_server_name;
mk_pointer mk_cgi_server_protocol;
mk_pointer mk_cgi_server_software;
mk_pointer mk_cgi_server_signature;
mk_pointer mk_cgi_http_user_agent;
mk_pointer mk_cgi_http_accept;
mk_pointer mk_cgi_http_accept_charset;
mk_pointer mk_cgi_http_accept_encoding;
mk_pointer mk_cgi_http_accept_language;
mk_pointer mk_cgi_http_host;
mk_pointer mk_cgi_http_cookie;
mk_pointer mk_cgi_http_referer;
mk_pointer mk_cgi_server_port;
mk_pointer mk_cgi_cgi_version;
mk_pointer mk_cgi_gateway_interface;
mk_pointer mk_cgi_remote_addr;
mk_pointer mk_cgi_request_uri;
mk_pointer mk_cgi_request_method;
mk_pointer mk_cgi_script_name;
mk_pointer mk_cgi_script_filename;
mk_pointer mk_cgi_remote_port;
mk_pointer mk_cgi_query_string;
mk_pointer mk_cgi_post_vars;

#define MK_CGI_VERSION "1.1"
mk_pointer mk_cgi_version;

struct mk_cgi_environment
{
    mk_pointer p;
    struct mk_cgi_environment *next;
};

void mk_cgi_env();
