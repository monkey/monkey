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

#include "MKPlugin.h"
#include "palm.h"
#include "protocol.h"
#include "cgi.h"

void _iov_add_header(struct mk_iov *iov, mk_pointer header, mk_pointer value)
{
    mk_api->iov_add_entry(iov, header.data, header.len,
                          mk_iov_equal, MK_IOV_NOT_FREE_BUF);
    mk_api->iov_add_entry(iov, value.data, value.len,
                          mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
}

void _iov_add_row(struct mk_iov *iov, mk_pointer header)
{
    _iov_add_header(iov, header, mk_iov_empty);
}

/* Fill an empty space in IOV and return the index of the next empty space */
int _iov_fill_empty(struct mk_iov *iov, mk_pointer data, int idx)
{
    int i = idx;
    
    /* FIXME: Validate empty space, should we do this ?
    if (iov->io[idx].iov_len != 0) {
        mk_err("idx %i is NOT empty", idx);
        exit(EXIT_FAILURE);
    }
    */
    mk_api->iov_set_entry(iov, data.data, data.len, MK_IOV_NOT_FREE_BUF, idx);
    
    for (i=idx + 1; i < iov->iov_idx; i++) {
        if (iov->io[i].iov_len == 0) {
            return i;
        }
    }

    return -1;
}

/* Function invoked when the plugin startup for every working thread */
void mk_palm_protocol_thread_init()
{
    int i;
    struct mk_iov *iov;

    /* 
     * Set thread key for iov_request for palm server, we set a maximum of 72 slots
     * in the iov buf array and we set the internal offset to 2, as the first position of the
     * array 0 and 1, are used to hold the script path used in Palm protocol
     */
    iov = mk_api->iov_create(96, 2);
    
    /* Add static data to cached iov struct, this data never change once Monkey is running */
    mk_api->iov_set_entry(iov, 
                          mk_iov_crlf.data, mk_iov_crlf.len, 
                          MK_IOV_NOT_FREE_BUF, 1);

    //_iov_add_header(iov, mk_cgi_server_port, mk_api->config->port);
    _iov_add_header(iov, mk_cgi_server_protocol, mk_monkey_protocol);
    _iov_add_header(iov, mk_cgi_server_software,
                    mk_api->config->server_software);
    _iov_add_header(iov, mk_cgi_gateway_interface, mk_cgi_version);

    /* 
     * Add template rows, this rows fills information in the following way:
     *
     *     HEADER_NAME=[empty]CRLF
     *
     * then '[empty]' space is filled for each request, so we avoid to do 3 iov_add
     * per palm request row, we reduce to just one using the template.
     */
    _iov_add_row(iov, mk_cgi_document_root);
    _iov_add_row(iov, mk_cgi_server_name);
    _iov_add_row(iov, mk_cgi_http_user_agent);
    _iov_add_row(iov, mk_cgi_http_accept);
    _iov_add_row(iov, mk_cgi_http_accept_charset);
    _iov_add_row(iov, mk_cgi_http_accept_encoding);
    _iov_add_row(iov, mk_cgi_http_accept_language);
    _iov_add_row(iov, mk_cgi_http_host);
    _iov_add_row(iov, mk_cgi_http_cookie);
    _iov_add_row(iov, mk_cgi_http_referer);
    _iov_add_row(iov, mk_cgi_remote_addr);
    _iov_add_row(iov, mk_cgi_request_uri);
    _iov_add_row(iov, mk_cgi_request_method);
    _iov_add_row(iov, mk_cgi_script_name);
    _iov_add_row(iov, mk_cgi_script_filename);

    /* FIXME */
    /* _iov_add_row(iov, mk_cgi_remote_port); */

    _iov_add_row(iov, mk_cgi_query_string);
    _iov_add_row(iov, mk_cgi_content_length);
    _iov_add_row(iov, mk_cgi_content_type);
    _iov_add_row(iov, mk_cgi_post_vars);

    /* CRLFCRLF */
    mk_api->iov_add_entry(iov, mk_iov_crlfcrlf.data, mk_iov_crlfcrlf.len,
                          mk_iov_none, MK_IOV_NOT_FREE_BUF);    

    /* Map empty array fields for future resets */
    struct request_reset *r;
    r = mk_api->mem_alloc(sizeof(struct request_reset));
    r->idx = mk_api->mem_alloc(sizeof(int) * (iov->iov_idx/2));
    r->len = 0;

    for (i=0; i < iov->iov_idx; i++) {
        if (iov->io[i].iov_len == 0) {
            r->idx[r->len] = i;
            r->len++;
        }
    }

    /* Export data as a thread key */
    pthread_setspecific(iov_protocol_request, (void *) iov);
    pthread_setspecific(iov_protocol_request_idx, (void *) r);
}

struct mk_iov *mk_palm_protocol_template()
{
    int i;
    struct mk_iov *iov;
    struct request_reset *r;

    /* Use cached iov_request */
    iov = pthread_getspecific(iov_protocol_request);
    r = pthread_getspecific(iov_protocol_request_idx);

    /* Reset template */
    for (i=0; i < r->len; i++) {
        iov->io[r->idx[i]].iov_len = 0;
    }

    return iov;
}

struct mk_iov *mk_palm_protocol_request_new(struct client_session *cs,
                                            struct session_request *sr)
{
    int idx = 0;

    struct mk_iov *iov;

    /* Use cached iov_request */
    iov = mk_palm_protocol_template();
    
    idx = _iov_fill_empty(iov, sr->real_path, 0);
    idx = _iov_fill_empty(iov, sr->host_conf->documentroot, idx);

    //mk_palm_iov_add_header(iov, mk_cgi_server_addr, mk_api->config->server_addr);
    //mk_palm_iov_add_header(iov, mk_cgi_server_signature, sr->host_conf->host_signature);

    idx = _iov_fill_empty(iov, sr->host, idx);
    idx = _iov_fill_empty(iov, sr->user_agent, idx);
    idx = _iov_fill_empty(iov, sr->accept, idx);
    idx = _iov_fill_empty(iov, sr->accept_charset, idx);
    idx = _iov_fill_empty(iov, sr->accept_encoding, idx);
    idx = _iov_fill_empty(iov, sr->accept_language, idx);

    if (sr->port != mk_api->config->standard_port) {
        idx = _iov_fill_empty(iov, sr->host_port, idx);
    }
    else {
        idx = _iov_fill_empty(iov, sr->host, idx);
    }

    idx = _iov_fill_empty(iov, sr->cookies, idx);
    idx = _iov_fill_empty(iov, sr->referer, idx);

    idx = _iov_fill_empty(iov, *cs->ipv4, idx);
    idx = _iov_fill_empty(iov, sr->uri, idx);
    idx = _iov_fill_empty(iov, sr->method_p, idx);
    idx = _iov_fill_empty(iov, sr->uri, idx);

    /* real path is not an mk_pointer */
    idx = _iov_fill_empty(iov, sr->real_path, idx);
    //mk_palm_iov_add_header(iov, mk_cgi_remote_port, mk_api->config->port);
    idx = _iov_fill_empty(iov, sr->query_string, idx);

    if (sr->method == HTTP_METHOD_POST && sr->content_length > 0) {
        /* Content length */
        mk_pointer p;
        unsigned long len;
        char *length = 0;
        mk_api->str_build(&length, &len, "%i", sr->content_length);
        p.data = length;
        p.len = len;

        idx = _iov_fill_empty(iov, p, idx);
        idx = _iov_fill_empty(iov, sr->content_type, idx);
    }
    else {
        idx = _iov_fill_empty(iov, mk_iov_none, idx);
        idx = _iov_fill_empty(iov, mk_iov_none, idx);
    }

    /* Post data */
    idx = _iov_fill_empty(iov, sr->post_variables, idx);

    return iov;
}
