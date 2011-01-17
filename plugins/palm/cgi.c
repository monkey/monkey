/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P.
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

#include <stdio.h>
#include <stdlib.h>

#include "palm.h"
#include "plugin.h"
#include "cgi.h"

void mk_cgi_env()
{

    mk_api->pointer_set(&mk_cgi_document_root, MK_CGI_DOCUMENT_ROOT);

    /* CONTENT_ */
    mk_api->pointer_set(&mk_cgi_content_length, MK_CGI_CONTENT_LENGTH);
    mk_api->pointer_set(&mk_cgi_content_type, MK_CGI_CONTENT_TYPE);

    /* SERVER_ */
    mk_api->pointer_set(&mk_cgi_server_addr, MK_CGI_SERVER_ADDR);
    mk_api->pointer_set(&mk_cgi_server_port, MK_CGI_SERVER_PORT);
    mk_api->pointer_set(&mk_cgi_server_name, MK_CGI_SERVER_NAME);
    mk_api->pointer_set(&mk_cgi_server_protocol, MK_CGI_SERVER_PROTOCOL);
    mk_api->pointer_set(&mk_cgi_server_software, MK_CGI_SERVER_SOFTWARE);
    mk_api->pointer_set(&mk_cgi_server_signature, MK_CGI_SERVER_SIGNATURE);

    /* HTTP_ */
    mk_api->pointer_set(&mk_cgi_http_user_agent, MK_CGI_HTTP_USER_AGENT);
    mk_api->pointer_set(&mk_cgi_http_accept, MK_CGI_HTTP_ACCEPT);

    mk_api->pointer_set(&mk_cgi_http_accept_charset,
                        MK_CGI_HTTP_ACCEPT_CHARSET);
    mk_api->pointer_set(&mk_cgi_http_accept_encoding,
                        MK_CGI_HTTP_ACCEPT_ENCODING);
    mk_api->pointer_set(&mk_cgi_http_accept_language,
                        MK_CGI_HTTP_ACCEPT_LANGUAGE);
    mk_api->pointer_set(&mk_cgi_http_host, MK_CGI_HTTP_HOST);
    mk_api->pointer_set(&mk_cgi_http_cookie, MK_CGI_HTTP_COOKIE);
    mk_api->pointer_set(&mk_cgi_http_referer, MK_CGI_HTTP_REFERER);

    mk_api->pointer_set(&mk_cgi_cgi_version, MK_CGI_CGI_VERSION);
    mk_api->pointer_set(&mk_cgi_gateway_interface, MK_CGI_GATEWAY_INTERFACE);
    mk_api->pointer_set(&mk_cgi_remote_addr, MK_CGI_REMOTE_ADDR);

    /* REQUEST_ */
    mk_api->pointer_set(&mk_cgi_request_uri, MK_CGI_REQUEST_URI);
    mk_api->pointer_set(&mk_cgi_request_method, MK_CGI_REQUEST_METHOD);
    mk_api->pointer_set(&mk_cgi_script_name, MK_CGI_SCRIPT_NAME);
    mk_api->pointer_set(&mk_cgi_script_filename, MK_CGI_SCRIPT_FILENAME);
    mk_api->pointer_set(&mk_cgi_remote_port, MK_CGI_REMOTE_PORT);
    mk_api->pointer_set(&mk_cgi_query_string, MK_CGI_QUERY_STRING);
    mk_api->pointer_set(&mk_cgi_post_vars, MK_CGI_POST_VARS);
    mk_api->pointer_set(&mk_cgi_version, MK_CGI_VERSION);
}
