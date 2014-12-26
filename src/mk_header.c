/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <monkey/monkey.h>
#include <monkey/mk_server.h>
#include <monkey/mk_header.h>
#include <monkey/mk_memory.h>
#include <monkey/mk_iov.h>
#include <monkey/mk_http_status.h>
#include <monkey/mk_config.h>
#include <monkey/mk_socket.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_cache.h>
#include <monkey/mk_http.h>
#include <monkey/mk_string.h>
#include <monkey/mk_macros.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_tls.h>

#define MK_HEADER_SHORT_DATE       "Date: "
#define MK_HEADER_SHORT_LOCATION   "Location: "
#define MK_HEADER_SHORT_CT         "Content-Type: "
#define MK_HEADER_ACCEPT_RANGES    "Accept-Ranges: bytes" MK_CRLF
#define MK_HEADER_ALLOWED_METHODS  "Allow: "
#define MK_HEADER_CONN_KA          "Connection: Keep-Alive" MK_CRLF
#define MK_HEADER_CONN_CLOSE       "Connection: Close" MK_CRLF
#define MK_HEADER_CONTENT_LENGTH   "Content-Length: "
#define MK_HEADER_CONTENT_ENCODING "Content-Encoding: "
#define MK_HEADER_TE_CHUNKED       "Transfer-Encoding: Chunked" MK_CRLF
#define MK_HEADER_LAST_MODIFIED    "Last-Modified: "

const mk_ptr_t mk_header_short_date = mk_ptr_init(MK_HEADER_SHORT_DATE);
const mk_ptr_t mk_header_short_location = mk_ptr_init(MK_HEADER_SHORT_LOCATION);
const mk_ptr_t mk_header_short_ct = mk_ptr_init(MK_HEADER_SHORT_CT);
const mk_ptr_t mk_header_allow = mk_ptr_init(MK_HEADER_ALLOWED_METHODS);

const mk_ptr_t mk_header_conn_ka = mk_ptr_init(MK_HEADER_CONN_KA);
const mk_ptr_t mk_header_conn_close = mk_ptr_init(MK_HEADER_CONN_CLOSE);
const mk_ptr_t mk_header_content_length = mk_ptr_init(MK_HEADER_CONTENT_LENGTH);
const mk_ptr_t mk_header_content_encoding = mk_ptr_init(MK_HEADER_CONTENT_ENCODING);
const mk_ptr_t mk_header_accept_ranges = mk_ptr_init(MK_HEADER_ACCEPT_RANGES);
const mk_ptr_t mk_header_te_chunked = mk_ptr_init(MK_HEADER_TE_CHUNKED);
const mk_ptr_t mk_header_last_modified = mk_ptr_init(MK_HEADER_LAST_MODIFIED);

#define status_entry(num, str) {num, sizeof(str) - 1, str}

static const struct header_status_response status_response[] = {

    /*
     * The most used first:
     *
     *  - HTTP/1.1 200 OK
     *  - HTTP/1.1 404 Not Found
     */
    status_entry(MK_HTTP_OK, MK_RH_HTTP_OK),
    status_entry(MK_CLIENT_NOT_FOUND, MK_RH_CLIENT_NOT_FOUND),

    /* Informational */
    status_entry(MK_INFO_CONTINUE, MK_RH_INFO_CONTINUE),
    status_entry(MK_INFO_SWITCH_PROTOCOL, MK_RH_INFO_SWITCH_PROTOCOL),

    /* Successful */
    status_entry(MK_HTTP_CREATED, MK_RH_HTTP_CREATED),
    status_entry(MK_HTTP_ACCEPTED, MK_RH_HTTP_ACCEPTED),
    status_entry(MK_HTTP_NON_AUTH_INFO, MK_RH_HTTP_NON_AUTH_INFO),
    status_entry(MK_HTTP_NOCONTENT, MK_RH_HTTP_NOCONTENT),
    status_entry(MK_HTTP_RESET, MK_RH_HTTP_RESET),
    status_entry(MK_HTTP_PARTIAL, MK_RH_HTTP_PARTIAL),

    /* Redirections */
    status_entry(MK_REDIR_MULTIPLE, MK_RH_REDIR_MULTIPLE),
    status_entry(MK_REDIR_MOVED, MK_RH_REDIR_MOVED),
    status_entry(MK_REDIR_MOVED_T, MK_RH_REDIR_MOVED_T),
    status_entry(MK_REDIR_SEE_OTHER, MK_RH_REDIR_SEE_OTHER),
    status_entry(MK_NOT_MODIFIED, MK_RH_NOT_MODIFIED),
    status_entry(MK_REDIR_USE_PROXY, MK_RH_REDIR_USE_PROXY),

    /* Client side errors */
    status_entry(MK_CLIENT_BAD_REQUEST, MK_RH_CLIENT_BAD_REQUEST),
    status_entry(MK_CLIENT_UNAUTH, MK_RH_CLIENT_UNAUTH),
    status_entry(MK_CLIENT_PAYMENT_REQ, MK_RH_CLIENT_PAYMENT_REQ),
    status_entry(MK_CLIENT_FORBIDDEN, MK_RH_CLIENT_FORBIDDEN),
    status_entry(MK_CLIENT_METHOD_NOT_ALLOWED, MK_RH_CLIENT_METHOD_NOT_ALLOWED),
    status_entry(MK_CLIENT_NOT_ACCEPTABLE, MK_RH_CLIENT_NOT_ACCEPTABLE),
    status_entry(MK_CLIENT_PROXY_AUTH, MK_RH_CLIENT_PROXY_AUTH),
    status_entry(MK_CLIENT_REQUEST_TIMEOUT, MK_RH_CLIENT_REQUEST_TIMEOUT),
    status_entry(MK_CLIENT_CONFLICT, MK_RH_CLIENT_CONFLICT),
    status_entry(MK_CLIENT_GONE, MK_RH_CLIENT_GONE),
    status_entry(MK_CLIENT_LENGTH_REQUIRED, MK_RH_CLIENT_LENGTH_REQUIRED),
    status_entry(MK_CLIENT_PRECOND_FAILED, MK_RH_CLIENT_PRECOND_FAILED),
    status_entry(MK_CLIENT_REQUEST_ENTITY_TOO_LARGE,
                 MK_RH_CLIENT_REQUEST_ENTITY_TOO_LARGE),
    status_entry(MK_CLIENT_REQUEST_URI_TOO_LONG,
                 MK_RH_CLIENT_REQUEST_URI_TOO_LONG),
    status_entry(MK_CLIENT_UNSUPPORTED_MEDIA, MK_RH_CLIENT_UNSUPPORTED_MEDIA),
    status_entry(MK_CLIENT_REQUESTED_RANGE_NOT_SATISF,
                 MK_RH_CLIENT_REQUESTED_RANGE_NOT_SATISF),

    /* Server side errors */
    status_entry(MK_SERVER_INTERNAL_ERROR, MK_RH_SERVER_INTERNAL_ERROR),
    status_entry(MK_SERVER_NOT_IMPLEMENTED, MK_RH_SERVER_NOT_IMPLEMENTED),
    status_entry(MK_SERVER_BAD_GATEWAY, MK_RH_SERVER_BAD_GATEWAY),
    status_entry(MK_SERVER_SERVICE_UNAV, MK_RH_SERVER_SERVICE_UNAV),
    status_entry(MK_SERVER_GATEWAY_TIMEOUT, MK_RH_SERVER_GATEWAY_TIMEOUT),
    status_entry(MK_SERVER_HTTP_VERSION_UNSUP, MK_RH_SERVER_HTTP_VERSION_UNSUP)
};

static const int status_response_len =
    (sizeof(status_response)/(sizeof(status_response[0])));


static void mk_header_iov_free(struct mk_iov *iov)
{
    mk_iov_free_marked(iov);
}

/* Send response headers */
int mk_header_send(int fd, struct mk_http_session *cs,
                   struct mk_http_request *sr)
{
    int i=0;
    unsigned long len = 0;
    char *buffer = 0;
    mk_ptr_t response;
    struct response_headers *sh;
    struct mk_list *head;
    struct custom_header *entry;
    struct mk_iov *iov;

    sh = &sr->headers;

    iov = MK_TLS_GET(mk_tls_cache_iov_header);

    /* HTTP Status Code */
    if (sh->status == MK_CUSTOM_STATUS) {
        response.data = sh->custom_status.data;
        response.len = sh->custom_status.len;
    }
    else {
        for (i=0; i < status_response_len; i++) {
            if (status_response[i].status == sh->status) {
                response.data = status_response[i].response;
                response.len  = status_response[i].length;
                break;
            }
        }
    }

    /* Invalid status set */
    mk_bug(i == status_response_len);

    mk_iov_add(iov, response.data, response.len, MK_IOV_NOT_FREE_BUF);

    /*
     * Preset headers (mk_clock.c):
     *
     * - Server
     * - Date
     */
    mk_iov_add(iov,
               headers_preset.data,
               headers_preset.len,
               MK_IOV_NOT_FREE_BUF);

    /* Last-Modified */
    if (sh->last_modified > 0) {
        mk_ptr_t *lm = MK_TLS_GET(mk_tls_cache_header_lm);
        lm->len = mk_utils_utime2gmt(&lm->data, sh->last_modified);

        mk_iov_add(iov,
                   mk_header_last_modified.data,
                   mk_header_last_modified.len,
                   MK_IOV_NOT_FREE_BUF);
        mk_iov_add(iov,
                   lm->data,
                   lm->len,
                   MK_IOV_NOT_FREE_BUF);
    }

    /* Connection */
    if (sh->connection == 0) {
        if (mk_http_keepalive_check(cs) == 0) {
            if (sr->connection.len > 0) {
                if (sr->protocol != MK_HTTP_PROTOCOL_11) {
                    /* Get cached mk_ptr_ts */
                    mk_ptr_t *ka_format = MK_TLS_GET(mk_tls_cache_header_ka);
                    mk_ptr_t *ka_header = MK_TLS_GET(mk_tls_cache_header_ka_max);

                    /* Compose header and add entries to iov */
                    mk_string_itop(mk_config->max_keep_alive_request - cs->counter_connections, ka_header);
                    mk_iov_add(iov, ka_format->data, ka_format->len,
                               MK_IOV_NOT_FREE_BUF);
                    mk_iov_add(iov, ka_header->data, ka_header->len,
                               MK_IOV_NOT_FREE_BUF);
                    mk_iov_add(iov,
                               mk_header_conn_ka.data,
                               mk_header_conn_ka.len,
                               MK_IOV_NOT_FREE_BUF);
                }
            }
        }
        else {
            mk_iov_add(iov,
                       mk_header_conn_close.data,
                       mk_header_conn_close.len,
                       MK_IOV_NOT_FREE_BUF);
        }
    }

    /* Location */
    if (sh->location != NULL) {
        mk_iov_add(iov,
                   mk_header_short_location.data,
                   mk_header_short_location.len,
                   MK_IOV_NOT_FREE_BUF);

        mk_iov_add(iov,
                   sh->location,
                   strlen(sh->location),
                   MK_IOV_FREE_BUF);
    }

    /* allowed methods */
    if (sh->allow_methods.len > 0) {
        mk_iov_add(iov,
                   mk_header_allow.data,
                   mk_header_allow.len,
                   MK_IOV_NOT_FREE_BUF);
        mk_iov_add(iov,
                   sh->allow_methods.data,
                   sh->allow_methods.len,
                   MK_IOV_NOT_FREE_BUF);
    }

    /* Content type */
    if (sh->content_type.len > 0) {
        mk_iov_add(iov,
                   sh->content_type.data,
                   sh->content_type.len,
                   MK_IOV_NOT_FREE_BUF);
    }

    /*
     * Transfer Encoding: the transfer encoding header is just sent when
     * the response has some content defined by the HTTP status response
     */
    if ((sh->status < MK_REDIR_MULTIPLE) || (sh->status > MK_REDIR_USE_PROXY)) {
        switch (sh->transfer_encoding) {
        case MK_HEADER_TE_TYPE_CHUNKED:
            mk_iov_add(iov,
                       mk_header_te_chunked.data,
                       mk_header_te_chunked.len,
                       MK_IOV_NOT_FREE_BUF);
            break;
        }
    }

    /* Content-Encoding */
    if (sh->content_encoding.len > 0) {
        mk_iov_add(iov, mk_header_content_encoding.data,
                   mk_header_content_encoding.len,
                   MK_IOV_NOT_FREE_BUF);
        mk_iov_add(iov, sh->content_encoding.data,
                   sh->content_encoding.len,
                   MK_IOV_NOT_FREE_BUF);
    }

    /* Content-Length */
    if (sh->content_length >= 0 && sh->transfer_encoding != 0) {
        /* Map content length to MK_POINTER */
        mk_ptr_t *cl = MK_TLS_GET(mk_tls_cache_header_cl);
        mk_string_itop(sh->content_length, cl);

        /* Set headers */
        mk_iov_add(iov,
                   mk_header_content_length.data,
                   mk_header_content_length.len,
                   MK_IOV_NOT_FREE_BUF);
        mk_iov_add(iov,
                   cl->data,
                   cl->len,
                   MK_IOV_NOT_FREE_BUF);
    }

    if ((sh->content_length != 0 && (sh->ranges[0] >= 0 || sh->ranges[1] >= 0)) &&
        mk_config->resume == MK_TRUE) {
        buffer = 0;

        /* yyy- */
        if (sh->ranges[0] >= 0 && sh->ranges[1] == -1) {
            mk_string_build(&buffer,
                            &len,
                            "%s bytes %d-%ld/%ld\r\n",
                            RH_CONTENT_RANGE,
                            sh->ranges[0],
                            (sh->real_length - 1), sh->real_length);
            mk_iov_add(iov, buffer, len, MK_IOV_FREE_BUF);
        }

        /* yyy-xxx */
        if (sh->ranges[0] >= 0 && sh->ranges[1] >= 0) {
            mk_string_build(&buffer,
                            &len,
                            "%s bytes %d-%d/%ld\r\n",
                            RH_CONTENT_RANGE,
                            sh->ranges[0], sh->ranges[1], sh->real_length);

            mk_iov_add(iov, buffer, len, MK_IOV_FREE_BUF);
        }

        /* -xxx */
        if (sh->ranges[0] == -1 && sh->ranges[1] > 0) {
            mk_string_build(&buffer,
                            &len,
                            "%s bytes %ld-%ld/%ld\r\n",
                            RH_CONTENT_RANGE,
                            (sh->real_length - sh->ranges[1]),
                            (sh->real_length - 1), sh->real_length);
            mk_iov_add(iov, buffer, len, MK_IOV_FREE_BUF);
        }
    }

    /* Custom headers */
    mk_list_foreach(head, &sr->host_conf->custom_headers) {
        entry = mk_list_entry(head, struct custom_header, _head);

        mk_iov_add_entry(iov, entry->response_header,
                         strlen(entry->response_header),
                         mk_iov_crlf, MK_IOV_NOT_FREE_BUF);
    }

    mk_server_cork_flag(fd, TCP_CORK_ON);

    if (sh->cgi == SH_NOCGI || sh->breakline == MK_HEADER_BREAKLINE) {
        if (!sr->headers._extra_rows) {
            mk_iov_add(iov, mk_iov_crlf.data, mk_iov_crlf.len,
                       MK_IOV_NOT_FREE_BUF);
        }
        else {
            mk_iov_add(sr->headers._extra_rows, mk_iov_crlf.data,
                       mk_iov_crlf.len, MK_IOV_NOT_FREE_BUF);
        }
    }

    mk_socket_sendv(fd, iov);
    if (sr->headers._extra_rows) {
        mk_socket_sendv(fd, sr->headers._extra_rows);
        mk_iov_free(sr->headers._extra_rows);
        sr->headers._extra_rows = NULL;
    }

    mk_header_iov_free(iov);
    sh->sent = MK_TRUE;

    return 0;
}

void mk_header_set_http_status(struct mk_http_request *sr, int status)
{
    mk_bug(!sr);
    sr->headers.status = status;

    MK_TRACE("Set HTTP status = %i", status);
}

void mk_header_response_reset(struct response_headers *header)
{
    header->status = 0;
    header->sent = MK_FALSE;
    header->ranges[0] = -1;
    header->ranges[1] = -1;
    header->content_length = -1;
    header->connection = 0;
    header->transfer_encoding = -1;
    header->last_modified = -1;
    header->cgi = SH_NOCGI;
    mk_ptr_reset(&header->content_type);
    mk_ptr_reset(&header->content_encoding);
    header->location = NULL;
    header->_extra_rows = NULL;
    header->allow_methods.len = 0;
}
