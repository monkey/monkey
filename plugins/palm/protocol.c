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
#include <string.h>
#include <ctype.h>

#include "MKPlugin.h"
#include "palm.h"
#include "protocol.h"
#include "cgi.h"

static void prot_add_header(struct mk_iov *iov, mk_pointer header, mk_pointer value)
{
    mk_api->iov_add_entry(iov, header.data, header.len,
                          mk_iov_equal, MK_IOV_NOT_FREE_BUF);
    mk_api->iov_add_entry(iov, value.data, value.len,
                          mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
}

struct mk_iov *prot_template()
{
    struct mk_iov *iov;

    /* Use cached iov_request */
    iov = pthread_getspecific(iov_protocol_request);
    return iov;
}

/* 
 * Convert a request HTTP header into HTTP_ CGI style, e.g:
 *
 *   Accept-Charset:  ->  HTTP_ACCEPT_CHARSET
 */
static int prot_header2cgi(const char *buf, int len, char **dest)
{
    int i;
    int offset = 5;
    char *p;
    const char *prefix = "HTTP_";
    
    memcpy(*dest, prefix, offset);
    p = *dest + offset;

    for (i=0; i < len; i++) {
        if (buf[i] == ':') {
            *p++ = '\0';
            break;
        }

        if (buf[i] == '-') {
            *p++ = '_';
        }
        else {
            *p++ = toupper(buf[i]);
        }
    }

    /* Return the new buffer length */
    i += offset;
    return i;
}

static int get_port_by_socket(int fd)
{
    socklen_t len = sizeof(struct sockaddr_in);
    struct sockaddr_in m_addr;

    getpeername(fd, (struct sockaddr *) &m_addr, &len);
    return (int) m_addr.sin_port;
}

/*
 * Returns an 'iov' palm request array with the CGI data
 */
struct mk_iov *mk_palm_protocol_request_new(struct client_session *cs,
                                            struct session_request *sr)
{
    int i;
    int row_len;
    char *row_buf;

    mk_pointer iov_temp;
    struct mk_iov *iov;
    struct header_toc_row *row;

    /* Use cached iov_request */
    iov = prot_template();

    /* DOCUMENT_ROOT */
    prot_add_header(iov, mk_cgi_document_root, sr->host_conf->documentroot);

    /* CONTENT_XYZ */
    //mk_api->pointer_reset(&iov_temp);
    if (sr->method == HTTP_METHOD_POST && sr->content_length >= 0) {
        iov_temp.data = mk_api->mem_alloc(32);
        mk_string_itop(sr->content_length, &iov_temp);
        prot_add_header(iov, mk_cgi_content_length, iov_temp);
    }
    if (sr->headers.content_type.len > 0) {
        prot_add_header(iov, mk_cgi_content_type, sr->headers.content_type);
    }

    /* SERVER_ADDR */
    prot_add_header(iov, mk_cgi_server_addr, mk_server_address);

    /* SERVER_PORT */
    prot_add_header(iov, mk_cgi_server_port, mk_server_port);

    /* 
     * SERVER_NAME
     * -----------
     *
     * Server name belongs to the value specified in the conf/sites/XYZ vhost file
     * under key 'ServerName'. 
     */
    iov_temp.data = sr->host_alias->name;
    iov_temp.len = sr->host_alias->len;
    prot_add_header(iov, mk_cgi_server_name, iov_temp);

    /* SERVER_PROTOCOL */
    prot_add_header(iov, mk_cgi_server_protocol, mk_server_protocol);

    /* 
     * SERVER_SIGNATURE 
     * ----------------
     * we use an offset of 8 bytes as each host signature is composed in 
     * the following way:
     *
     *   server: Monkey/x.y.x
     *
     * so the 8 bytes do the offset for 'server: ' which is not useful for
     * the CGI environment variable.
     */
    iov_temp.data = sr->host_conf->header_host_signature.data + 8;
    iov_temp.len = sr->host_conf->header_host_signature.len - 8;
    prot_add_header(iov, mk_cgi_server_signature, iov_temp);

    /* 
     * HTTP_*
     * --------
     *
     * CGI spec specify that incomming HTTP headers by the client must be 
     * converted to uppercase, replace '-' by '_' and prefix the 'HTTP_' 
     * string. e.g:
     *
     *   Accept-Encoding: -> HTTP_ACCEPT_ENCODING
     */
    short int len;
    short int offset = 5;

    for (i=0; i < sr->headers_toc.length; i++) {
        row = &sr->headers_toc.rows[i];
        /* let's match common CGI HTTP_ headers */
        len = row->end - row->init;
        row_buf = mk_api->mem_alloc(len + 1);
        row_len = prot_header2cgi(row->init, len, &row_buf);

        /* Row key */
        mk_api->iov_add_entry(iov, row_buf, row_len,
                              mk_iov_equal, MK_IOV_FREE_BUF);
        /* Row value */
        mk_api->iov_add_entry(iov, row->init + (row_len - offset) + 2,
                              len - (row_len - offset) - 2,
                              mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
    }

    /* REMOTE_ADDR */
    prot_add_header(iov, mk_cgi_remote_addr, *cs->ipv4);

    /* REMOTE_PORT */
    iov_temp.data = mk_api->mem_alloc(8);
    mk_api->str_itop(get_port_by_socket(cs->socket), &iov_temp);
    iov_temp.len -=2;
    mk_api->iov_add_entry(iov, mk_cgi_remote_port.data, mk_cgi_remote_port.len,
                          mk_iov_equal, MK_IOV_NOT_FREE_BUF);
    mk_api->iov_add_entry(iov, iov_temp.data, iov_temp.len,
                          mk_iov_crlf, MK_IOV_FREE_BUF);

    /* Miscellaneus CGI headers */
    prot_add_header(iov, mk_cgi_gateway_interface, mk_cgi_version);
    prot_add_header(iov, mk_cgi_request_uri, sr->uri);
    prot_add_header(iov, mk_cgi_request_method, sr->method_p);
    prot_add_header(iov, mk_cgi_script_name, sr->uri);
    prot_add_header(iov, mk_cgi_script_filename, sr->real_path);

    /* QUERY_STRING */
    if (sr->query_string.len > 0) {
        prot_add_header(iov, mk_cgi_query_string, sr->query_string);
    }

    /* 
     * POST_VARIABLES
     * --------------
     * non-standard field of CGI, it just used by Palm protocol 
     */
    if (sr->content_length > 0 && sr->post_variables.len > 0) {
        prot_add_header(iov, mk_cgi_post_vars, sr->post_variables);
    }

    
#ifdef TRACE
    PLUGIN_TRACE("Palm protocol request");
    mk_api->iov_send(0, iov);
#endif

    return iov;
}

void mk_palm_protocol_thread_init()
{
    struct mk_iov *iov;

    iov = mk_api->iov_create(128,0);
    pthread_setspecific(iov_protocol_request, iov);
}
