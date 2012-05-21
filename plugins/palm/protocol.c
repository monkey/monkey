/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
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

static struct mk_iov *prot_template()
{
    struct mk_iov *iov;

    /* Use cached iov_request */
    iov = pthread_getspecific(iov_protocol_request);

    /* Remove any previous data used */
    mk_api->iov_free_marked(iov);
    iov->iov_idx = 0;
    iov->buf_idx = 0;
    iov->total_len = 0;

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
    int offset = 0;
    int prefix_len = 5;
    char *p;
    const char *prefix = "HTTP_";

    /* 
     * There're two exception when the prefix HTTP_ must not
     * be added: Content-Type and Content-Length headers, 
     * i cannot find the reason for that so this belongs to a 
     * stupid way to work.
     */
    if (strncasecmp(buf, "Content-", 8) == 0 || 
        strncasecmp(buf, "Cookie-", 7) == 0) {
        offset = 0;
    }
    else {
        memcpy(*dest, prefix, prefix_len);
        offset = prefix_len;
    }

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
    int i, ret;
    int row_len;
    char *ip_str;
    unsigned long ip_len;
    char *row_buf;

    mk_pointer iov_temp;
    struct mk_iov *iov;
    struct header_toc_row *row;

    /* Use cached iov_request */
    iov = prot_template();
    iov->iov_idx = 0;

    /* DOCUMENT_ROOT */
    prot_add_header(iov, mk_cgi_document_root, sr->host_conf->documentroot);

    /* CONTENT_XYZ */
    //mk_api->pointer_reset(&iov_temp);
    if (sr->method == HTTP_METHOD_POST && sr->content_length >= 0) {
        iov_temp.data = mk_api->mem_alloc(32);
        mk_api->str_itop(sr->content_length, &iov_temp);

        iov_temp.len -= 2;
        prot_add_header(iov, mk_cgi_content_length, iov_temp);
    }
    if (sr->headers.content_type.len > 0) {
        prot_add_header(iov, mk_cgi_content_type, sr->headers.content_type);
    }

    /* SERVER_ADDR */
    //prot_add_header(iov, mk_cgi_server_addr, mk_server_address);

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
    short int offset;
    short int prefix_len = 5;

    for (i=0; i < sr->headers_toc.length; i++) {
        row = &sr->headers_toc.rows[i];
        /* let's match common CGI HTTP_ headers */
        len = row->end - row->init;
        row_buf = mk_api->mem_alloc(len + 1);
        row_len = prot_header2cgi(row->init, len, &row_buf);

        /* Row key */
        mk_api->iov_add_entry(iov, row_buf, row_len,
                              mk_iov_equal, MK_IOV_FREE_BUF);

        /* Just prefixed HEADERS requires the offset */
        if (strncmp(row_buf, "HTTP_", 5) == 0) {
            offset = prefix_len;
        }
        else {
            offset = 0;
        }

        /* Row value */
        mk_api->iov_add_entry(iov, row->init + (row_len - offset) + 2,
                              len - (row_len - offset) - 2,
                              mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
    }

    /* REMOTE_ADDR */
    ip_str = pthread_getspecific(cache_ip_str);
    ret = mk_api->socket_ip_str(cs->socket, (char **) &ip_str, INET6_ADDRSTRLEN + 1, &ip_len);
    if (ret < 0) {
        PLUGIN_TRACE("[FD %i] Error formatting IP address", cs->socket);
        return NULL;
    }

    iov_temp.len = ip_len;
    iov_temp.data = ip_str;

    prot_add_header(iov, mk_cgi_remote_addr, iov_temp);

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

    /*
     * REQUEST_URI
     *
     * if the request URI contains a query string, we must re-compose the full
     * string as Monkey splits URI from query string
     */
    iov_temp.data = sr->uri.data;
    if (sr->query_string.len > 0) {
        iov_temp.len = sr->uri.len + sr->query_string.len + 1;
    }
    else {
        iov_temp.len = sr->uri.len;
    }
    prot_add_header(iov, mk_cgi_request_uri, iov_temp);

    /* REQUEST_METHOD */
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
    if (sr->content_length > 0 && sr->data.len > 0) {
        prot_add_header(iov, mk_cgi_post_vars, sr->data);
    }

    /* Ending CRLFCRLF (\r\n\r\n) */
    mk_api->iov_add_entry(iov, 
                          mk_iov_crlfcrlf.data, mk_iov_crlfcrlf.len,
                          mk_iov_none, MK_IOV_NOT_FREE_BUF);
#ifdef TRACE
    PLUGIN_TRACE("Palm protocol request");
    mk_api->iov_send(0, iov);
#endif

    return iov;
}

void mk_palm_protocol_thread_init()
{
    char *ip_str;
    struct mk_iov *iov;

    iov = mk_api->iov_create(128,0);
    pthread_setspecific(iov_protocol_request, iov);

    ip_str = mk_api->mem_alloc(INET6_ADDRSTRLEN + 1);
    pthread_setspecific(cache_ip_str, ip_str);
}
