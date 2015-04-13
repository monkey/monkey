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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <monkey/mk_user.h>
#include <monkey/monkey.h>
#include <monkey/mk_memory.h>
#include <monkey/mk_http.h>
#include <monkey/mk_http_status.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_file.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_config.h>
#include <monkey/mk_string.h>
#include <monkey/mk_socket.h>
#include <monkey/mk_mimetype.h>
#include <monkey/mk_header.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_macros.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_server.h>
#include <monkey/mk_plugin_stage.h>

const mk_ptr_t mk_http_method_get_p = mk_ptr_init(MK_METHOD_GET_STR);
const mk_ptr_t mk_http_method_post_p = mk_ptr_init(MK_METHOD_POST_STR);
const mk_ptr_t mk_http_method_head_p = mk_ptr_init(MK_METHOD_HEAD_STR);
const mk_ptr_t mk_http_method_put_p = mk_ptr_init(MK_METHOD_PUT_STR);
const mk_ptr_t mk_http_method_delete_p = mk_ptr_init(MK_METHOD_DELETE_STR);
const mk_ptr_t mk_http_method_options_p = mk_ptr_init(MK_METHOD_OPTIONS_STR);
const mk_ptr_t mk_http_method_null_p = { NULL, 0 };

const mk_ptr_t mk_http_protocol_09_p = mk_ptr_init(MK_HTTP_PROTOCOL_09_STR);
const mk_ptr_t mk_http_protocol_10_p = mk_ptr_init(MK_HTTP_PROTOCOL_10_STR);
const mk_ptr_t mk_http_protocol_11_p = mk_ptr_init(MK_HTTP_PROTOCOL_11_STR);
const mk_ptr_t mk_http_protocol_null_p = { NULL, 0 };

/* Create a memory allocation in order to handle the request data */
void mk_http_request_init(struct mk_http_session *session,
                          struct mk_http_request *request)
{
    struct mk_list *host_list = &mk_config->hosts;

    request->port = 0;
    request->status = MK_TRUE;
    request->uri.data = NULL;
    request->method = MK_METHOD_UNKNOWN;
    request->protocol = MK_HTTP_PROTOCOL_UNKNOWN;
    request->connection.len = -1;
    request->file_info.size = -1;
    request->file_stream.fd = 0;
    request->file_stream.bytes_total = -1;
    request->file_stream.bytes_offset = 0;
    request->file_stream.preserve = MK_FALSE;
    request->vhost_fdt_enabled = MK_FALSE;
    request->host.data = NULL;
    request->stage30_blocked = MK_FALSE;
    request->session = session;
    request->host_conf = mk_list_entry_first(host_list, struct host, _head);
    request->uri_processed.data = NULL;
    request->real_path.data = NULL;
    request->keep_alive = MK_TRUE;
    request->close_now = MK_TRUE;

    /* Response Headers */
    mk_header_response_reset(&request->headers);
}

static inline int mk_http_point_header(mk_ptr_t *h,
                                       struct mk_http_parser *parser, int key)
{
    struct mk_http_header *header;

    header = &parser->headers[key];
    if (header->type == key) {
        h->data = header->val.data;
        h->len  = header->val.len;
        return 0;
    }
    else {
        h->data = NULL;
        h->len  = -1;
    }

    return -1;
}

static int mk_http_request_prepare(struct mk_http_session *cs,
                                   struct mk_http_request *sr)
{
    int status = 0;
    char *temp;
    struct mk_list *hosts = &mk_config->hosts;
    struct mk_list *alias;
    struct mk_http_header *header;

    /*
     * Process URI, if it contains ASCII encoded strings like '%20',
     * it will return a new memory buffer with the decoded string, otherwise
     * it returns NULL
     */
    temp = mk_utils_url_decode(sr->uri);
    if (temp) {
        sr->uri_processed.data = temp;
        sr->uri_processed.len  = strlen(temp);
    }
    else {
        sr->uri_processed.data = sr->uri.data;
        sr->uri_processed.len  = sr->uri.len;
    }

    /* Always assign the default vhost' */
    sr->host_conf = mk_list_entry_first(hosts, struct host, _head);

    sr->user_home = MK_FALSE;

    /* Valid request URI? */
    if (sr->uri_processed.data[0] != '/') {
        mk_http_error(MK_CLIENT_BAD_REQUEST, cs, sr);
        return EXIT_NORMAL;
    }

    /* Check if we have a Host header: Hostname ; port */
    mk_http_point_header(&sr->host, &cs->parser, MK_HEADER_HOST);

    /* Header: Connection */
    mk_http_point_header(&sr->connection, &cs->parser, MK_HEADER_CONNECTION);

    /* Header: Range */
    mk_http_point_header(&sr->range, &cs->parser, MK_HEADER_RANGE);

    /* Header: If-Modified-Since */
    mk_http_point_header(&sr->if_modified_since,
                         &cs->parser,
                         MK_HEADER_IF_MODIFIED_SINCE);

    /* HTTP/1.1 needs Host header */
    if (!sr->host.data && sr->protocol == MK_HTTP_PROTOCOL_11) {
        mk_http_error(MK_CLIENT_BAD_REQUEST, cs, sr);
        return EXIT_NORMAL;
    }

    /* Default Keepalive is off */
    if (sr->protocol == MK_HTTP_PROTOCOL_10) {
        sr->keep_alive = MK_FALSE;
        sr->close_now = MK_TRUE;
    }
    else if (sr->protocol == MK_HTTP_PROTOCOL_11) {
        sr->keep_alive = MK_TRUE;
        sr->close_now = MK_FALSE;
    }

    if (sr->connection.data) {
        if (cs->parser.header_connection == MK_HTTP_PARSER_CONN_KA) {
            sr->keep_alive = MK_TRUE;
            sr->close_now  = MK_FALSE;
        }
        else if (cs->parser.header_connection == MK_HTTP_PARSER_CONN_CLOSE) {
            sr->keep_alive = MK_FALSE;
            sr->close_now  = MK_TRUE;
        }
        else {
            if (sr->protocol == MK_HTTP_PROTOCOL_11) {
                sr->keep_alive = MK_TRUE;
                sr->close_now = MK_FALSE;
            }
        }
    }

    /* Content Length */
    header = &cs->parser.headers[MK_HEADER_CONTENT_LENGTH];
    if (header->type == MK_HEADER_CONTENT_LENGTH) {
        sr->_content_length.data = header->val.data;
        sr->_content_length.len  = header->val.len;
    }
    else {
        sr->_content_length.data = NULL;
    }

    /* Assign the first node alias */
    alias = &sr->host_conf->server_names;
    sr->host_alias = mk_list_entry_first(alias,
                                         struct host_alias, _head);

    if (sr->host.data) {
        /* Set the given port */
        if (cs->parser.header_host_port > 0) {
            sr->port = cs->parser.header_host_port;
        }

        /* Match the virtual host */
        mk_vhost_get(sr->host, &sr->host_conf, &sr->host_alias);

        /* Check if this virtual host have some redirection */
        if (sr->host_conf->header_redirect.data) {
            mk_header_set_http_status(sr, MK_REDIR_MOVED);
            sr->headers.location = mk_string_dup(sr->host_conf->header_redirect.data);
            sr->headers.content_length = 0;
            sr->headers.location = NULL;
            mk_header_prepare(cs, sr);
            mk_channel_write(&cs->channel);
            mk_server_cork_flag(cs->socket, TCP_CORK_OFF);
            return 0;
        }
    }

    /* Is requesting an user home directory ? */
    if (mk_config->user_dir &&
        sr->uri_processed.len > 2 &&
        sr->uri_processed.data[1] == MK_USER_HOME) {

        if (mk_user_init(cs, sr) != 0) {
            mk_http_error(MK_CLIENT_NOT_FOUND, cs, sr);
            return EXIT_ABORT;
        }
    }

    /* Plugins Stage 20 */
    int ret;
    ret = mk_plugin_stage_run_20(cs, sr);
    if (ret == MK_PLUGIN_RET_CLOSE_CONX) {
        MK_TRACE("STAGE 20 requested close conexion");
        return EXIT_ABORT;
    }

    /* Normal HTTP process */
    status = mk_http_init(cs, sr);

    MK_TRACE("[FD %i] HTTP Init returning %i", cs->socket, status);

    return status;
}

/*
 * This function allow the core to invoke the closing connection process
 * when some connection was not proceesed due to a premature close or similar
 * exception, it also take care of invoke the STAGE_40 and STAGE_50 plugins events
 */
static void mk_request_premature_close(int http_status, struct mk_http_session *cs)
{
    struct mk_http_request *sr;
    struct mk_list *sr_list = &cs->request_list;
    struct mk_list *host_list = &mk_config->hosts;

    /*
     * If the connection is too premature, we need to allocate a temporal session_request
     * to do not break the plugins stages
     */
    if (mk_list_is_empty(sr_list) == 0) {
        sr = &cs->sr_fixed;
        memset(sr, 0, sizeof(struct mk_http_request));
        mk_http_request_init(cs, sr);
        mk_list_add(&sr->_head, &cs->request_list);
    }
    else {
        sr = mk_list_entry_first(sr_list, struct mk_http_request, _head);
    }

    /* Raise error */
    if (http_status > 0) {
        if (!sr->host_conf) {
            sr->host_conf = mk_list_entry_first(host_list, struct host, _head);
        }
        mk_http_error(http_status, cs, sr);

        /* STAGE_40, request has ended */
        mk_plugin_stage_run_40(cs, sr);
    }

    /* STAGE_50, connection closed and remove the http_session */
    mk_plugin_stage_run_50(cs->socket);
    mk_http_session_remove(cs->socket);
}

int mk_http_handler_read(int socket, struct mk_http_session *cs)
{
    int bytes;
    int max_read;
    int available = 0;
    int new_size;
    int total_bytes = 0;
    char *tmp = 0;

    MK_TRACE("MAX REQUEST SIZE: %i", mk_config->max_request_size);

 try_pending:

    available = cs->body_size - cs->body_length;
    if (available <= 0) {
        /* Reallocate buffer size if pending data does not have space */
        new_size = cs->body_size + mk_config->transport_buffer_size;
        if (new_size > mk_config->max_request_size) {
            MK_TRACE("Requested size is > mk_config->max_request_size");
            mk_request_premature_close(MK_CLIENT_REQUEST_ENTITY_TOO_LARGE, cs);
            return -1;
        }

        /*
         * Check if the body field still points to the initial body_fixed, if so,
         * allow the new space required in body, otherwise perform a realloc over
         * body.
         */
        if (cs->body == cs->body_fixed) {
            cs->body = mk_mem_malloc(new_size + 1);
            cs->body_size = new_size;
            memcpy(cs->body, cs->body_fixed, cs->body_length);
            MK_TRACE("[FD %i] New size: %i, length: %i",
                     cs->socket, new_size, cs->body_length);
        }
        else {
            MK_TRACE("[FD %i] Realloc from %i to %i",
                     cs->socket, cs->body_size, new_size);
            tmp = mk_mem_realloc(cs->body, new_size + 1);
            if (tmp) {
                cs->body = tmp;
                cs->body_size = new_size;
            }
            else {
                mk_request_premature_close(MK_SERVER_INTERNAL_ERROR, cs);
                return -1;
            }
        }
    }

    /* Read content */
    max_read = (cs->body_size - cs->body_length);
    bytes = mk_socket_read(socket, cs->body + cs->body_length, max_read);

    MK_TRACE("[FD %i] read %i", socket, bytes);

    if (bytes < 0) {
        if (errno == EAGAIN) {
            return -EAGAIN;
        }
        else {
            mk_http_session_remove(socket);
            return -1;
        }
    }
    if (bytes == 0) {
        mk_http_session_remove(socket);
        return -1;
    }

    if (bytes > 0) {
        if (bytes > max_read) {
            MK_TRACE("[FD %i] Buffer still have data: %i",
                     cs->socket, bytes - max_read);

            cs->body_length += max_read;
            cs->body[cs->body_length] = '\0';
            total_bytes += max_read;

            goto try_pending;
        }
        else {
            cs->body_length += bytes;
            cs->body[cs->body_length] = '\0';

            total_bytes += bytes;
        }

        MK_TRACE("[FD %i] Retry total bytes: %i",
                 cs->socket, total_bytes);
        return total_bytes;
    }

    return bytes;
}

int mk_http_handler_write(int socket, struct mk_http_session *cs)
{
    int ret;
    int final_status = 0;
    struct mk_http_request *sr_node;
    struct mk_list *sr_list;
    struct mk_list *sr_head;
    (void) socket;

    /* Check if our embedded channel have some data to stream out */
    ret = mk_channel_write(&cs->channel);
    if (ret == MK_CHANNEL_ERROR) {
        return MK_CHANNEL_ERROR;
    }
    else if (ret == MK_CHANNEL_FLUSH) {
        return MK_CHANNEL_FLUSH;
    }
    else if (ret == MK_CHANNEL_DONE) {
        return MK_CHANNEL_DONE;
    }
    else if (ret == MK_CHANNEL_EMPTY) {
        sr_list = &cs->request_list;
        mk_list_foreach(sr_head, sr_list) {
            sr_node = mk_list_entry_first(sr_list,
                                          struct mk_http_request, _head);
            final_status = mk_http_request_prepare(cs, sr_node);
            /*
             * If we got an error, we don't want to parse
             * and send information for another pipelined request
             */
            if (final_status >= 0) {
                return MK_CHANNEL_FLUSH;
            }
            else {
                /* STAGE_40, request has ended */
                mk_plugin_stage_run_40(cs, sr_node);
                switch (final_status) {
                case EXIT_NORMAL:
                case EXIT_ERROR:
                    if (sr_node->close_now == MK_TRUE) {
                        return -1;
                    }
                    break;
                case EXIT_ABORT:
                    return -1;
                }
            }
        }
        /*
         * If we are here, is because all pipelined request were
         * processed successfully, let's return 0
         */
    }
    return 0;
}

/* Build error page */
static mk_ptr_t *mk_http_error_page(char *title, mk_ptr_t *message,
                                    char *signature)
{
    char *temp;
    mk_ptr_t *p;

    p = mk_mem_malloc(sizeof(mk_ptr_t));
    p->data = NULL;

    if (message) {
        temp = mk_ptr_to_buf(*message);
    }
    else {
        temp = "";
    }

    mk_string_build(&p->data, &p->len,
                    MK_REQUEST_DEFAULT_PAGE, title, temp, signature);

    if (message) {
        mk_mem_free(temp);
    }
    return p;
}

int mk_http_method_check(mk_ptr_t method)
{
    if (strncmp(method.data, MK_METHOD_GET_STR, method.len) == 0) {
        return MK_METHOD_GET;
    }

    if (strncmp(method.data, MK_METHOD_POST_STR, method.len) == 0) {
        return MK_METHOD_POST;
    }

    if (strncmp(method.data, MK_METHOD_HEAD_STR, method.len) == 0) {
        return MK_METHOD_HEAD;
    }

    if (strncmp(method.data, MK_METHOD_PUT_STR, method.len) == 0) {
        return MK_METHOD_PUT;
    }

    if (strncmp(method.data, MK_METHOD_DELETE_STR, method.len) == 0) {
        return MK_METHOD_DELETE;
    }

    if (strncmp(method.data, MK_METHOD_OPTIONS_STR, method.len) == 0) {
        return MK_METHOD_OPTIONS;
    }

    return MK_METHOD_UNKNOWN;
}

mk_ptr_t mk_http_method_check_str(int method)
{
    switch (method) {
    case MK_METHOD_GET:
        return mk_http_method_get_p;
    case MK_METHOD_POST:
        return mk_http_method_post_p;
    case MK_METHOD_HEAD:
        return mk_http_method_head_p;
    case MK_METHOD_PUT:
        return mk_http_method_put_p;
    case MK_METHOD_DELETE:
        return mk_http_method_delete_p;
    case MK_METHOD_OPTIONS:
        return mk_http_method_options_p;
    }
    return mk_http_method_null_p;
}

static int mk_http_range_set(struct mk_http_request *sr, size_t file_size)
{
    struct response_headers *sh = &sr->headers;

    sr->file_stream.bytes_total  = file_size;
    sr->file_stream.bytes_offset = 0;

    if (mk_config->resume == MK_TRUE && sr->range.data) {
        /* yyy- */
        if (sh->ranges[0] >= 0 && sh->ranges[1] == -1) {
            sr->file_stream.bytes_offset = sh->ranges[0];
            sr->file_stream.bytes_total = file_size - sr->file_stream.bytes_offset;
        }

        /* yyy-xxx */
        if (sh->ranges[0] >= 0 && sh->ranges[1] >= 0) {
            sr->file_stream.bytes_offset = sh->ranges[0];
            sr->file_stream.bytes_total = labs(sh->ranges[1] - sh->ranges[0]) + 1;
        }

        /* -xxx */
        if (sh->ranges[0] == -1 && sh->ranges[1] > 0) {
            sr->file_stream.bytes_total = sh->ranges[1];
            sr->file_stream.bytes_offset = file_size - sh->ranges[1];
        }

        if ((size_t) sr->file_stream.bytes_offset >= file_size ||
            sr->file_stream.bytes_total > file_size) {
            return -1;
        }

        lseek(sr->file_stream.fd, sr->file_stream.bytes_offset, SEEK_SET);
    }
    return 0;
}

static int mk_http_range_parse(struct mk_http_request *sr)
{
    int eq_pos, sep_pos, len;
    char *buffer = 0;
    struct response_headers *sh;

    if (!sr->range.data)
        return -1;

    if ((eq_pos = mk_string_char_search(sr->range.data, '=', sr->range.len)) < 0)
        return -1;

    if (strncasecmp(sr->range.data, "Bytes", eq_pos) != 0)
        return -1;

    if ((sep_pos = mk_string_char_search(sr->range.data, '-', sr->range.len)) < 0)
        return -1;

    len = sr->range.len;
    sh = &sr->headers;

    /* =-xxx */
    if (eq_pos + 1 == sep_pos) {
        sh->ranges[0] = -1;
        sh->ranges[1] = (unsigned long) atol(sr->range.data + sep_pos + 1);

        if (sh->ranges[1] <= 0) {
            return -1;
        }

        sh->content_length = sh->ranges[1];
        return 0;
    }

    /* =yyy-xxx */
    if ((eq_pos + 1 != sep_pos) && (len > sep_pos + 1)) {
        buffer = mk_string_copy_substr(sr->range.data, eq_pos + 1, sep_pos);
        sh->ranges[0] = (unsigned long) atol(buffer);
        mk_mem_free(buffer);

        buffer = mk_string_copy_substr(sr->range.data, sep_pos + 1, len);
        sh->ranges[1] = (unsigned long) atol(buffer);
        mk_mem_free(buffer);

        if (sh->ranges[1] < 0 || (sh->ranges[0] > sh->ranges[1])) {
            return -1;
        }

        sh->content_length = abs(sh->ranges[1] - sh->ranges[0]) + 1;
        return 0;
    }
    /* =yyy- */
    if ((eq_pos + 1 != sep_pos) && (len == sep_pos + 1)) {
        buffer = mk_string_copy_substr(sr->range.data, eq_pos + 1, len);
        sr->headers.ranges[0] = (unsigned long) atol(buffer);
        mk_mem_free(buffer);

        sh->content_length = (sh->content_length - sh->ranges[0]);
        return 0;
    }

    return -1;
}

int mk_http_method_get(char *body)
{
    int int_method, pos = 0;
    int max_len_method = 8;
    mk_ptr_t method;

    /* Max method length is 7 (GET/POST/HEAD/PUT/DELETE/OPTIONS) */
    pos = mk_string_char_search(body, ' ', max_len_method);
    if (mk_unlikely(pos <= 2 || pos >= max_len_method)) {
        return MK_METHOD_UNKNOWN;
    }

    method.data = body;
    method.len = (unsigned long) pos;

    int_method = mk_http_method_check(method);

    return int_method;
}

int mk_http_protocol_check(char *protocol, int len)
{
    if (strncmp(protocol, MK_HTTP_PROTOCOL_11_STR, len) == 0) {
        return MK_HTTP_PROTOCOL_11;
    }
    if (strncmp(protocol, MK_HTTP_PROTOCOL_10_STR, len) == 0) {
        return MK_HTTP_PROTOCOL_10;
    }
    if (strncmp(protocol, MK_HTTP_PROTOCOL_09_STR, len) == 0) {
        return MK_HTTP_PROTOCOL_09;
    }

    return MK_HTTP_PROTOCOL_UNKNOWN;
}

mk_ptr_t mk_http_protocol_check_str(int protocol)
{
    if (protocol == MK_HTTP_PROTOCOL_11) {
        return mk_http_protocol_11_p;
    }
    if (protocol == MK_HTTP_PROTOCOL_10) {
        return mk_http_protocol_10_p;
    }
    if (protocol == MK_HTTP_PROTOCOL_09) {
        return mk_http_protocol_09_p;
    }

    return mk_http_protocol_null_p;
}

static int mk_http_directory_redirect_check(struct mk_http_session *cs,
                                            struct mk_http_request *sr)
{
    int port_redirect = 0;
    char *host;
    char *location = 0;
    char *real_location = 0;
    unsigned long len;

    /*
     * We have to check if there is a slash at the end of
     * this string. If it doesn't exist, we send a redirection header.
     */
    if (sr->uri_processed.data[sr->uri_processed.len - 1] == '/') {
        return 0;
    }

    host = mk_ptr_to_buf(sr->host);

    /*
     * Add ending slash to the location string
     */
    location = mk_mem_malloc(sr->uri_processed.len + 2);
    memcpy(location, sr->uri_processed.data, sr->uri_processed.len);
    location[sr->uri_processed.len]     = '/';
    location[sr->uri_processed.len + 1] = '\0';

    /* FIXME: should we done something similar for SSL = 443 */
    if (sr->host.data && sr->port > 0) {
        if (sr->port != mk_config->standard_port) {
            port_redirect = sr->port;
        }
    }

    if (port_redirect > 0) {
        mk_string_build(&real_location, &len, "%s://%s:%i%s\r\n",
                        mk_config->transport, host, port_redirect, location);
    }
    else {
        mk_string_build(&real_location, &len, "%s://%s%s\r\n",
                        mk_config->transport, host, location);
    }

    MK_TRACE("Redirecting to '%s'", real_location);

    mk_mem_free(host);

    mk_header_set_http_status(sr, MK_REDIR_MOVED);
    sr->headers.content_length = 0;

    mk_ptr_reset(&sr->headers.content_type);
    sr->headers.location = real_location;
    sr->headers.cgi = SH_NOCGI;
    sr->headers.pconnections_left =
        (mk_config->max_keep_alive_request - cs->counter_connections);


    mk_header_prepare(cs, sr);
    mk_channel_write(&cs->channel);
    mk_server_cork_flag(cs->socket, TCP_CORK_OFF);

    /*
     *  we do not free() real_location
     *  as it's freed by iov
     */
    mk_mem_free(location);
    sr->headers.location = NULL;
    return -1;
}

/* Look for some  index.xxx in pathfile */
mk_ptr_t mk_http_index_file(char *pathfile, char *file_aux,
                            const unsigned int flen)
{
    unsigned long len;
    mk_ptr_t f;
    struct mk_string_line *entry;
    struct mk_list *head;

    mk_ptr_reset(&f);
    if (!mk_config->index_files) return f;

    mk_list_foreach(head, mk_config->index_files) {
        entry = mk_list_entry(head, struct mk_string_line, _head);
        len = snprintf(file_aux, flen, "%s%s", pathfile, entry->val);
        if (mk_unlikely(len > flen)) {
            len = flen - 1;
            mk_warn("Path too long, truncated! '%s'", file_aux);
        }

        if (access(file_aux, F_OK) == 0) {
            f.data = file_aux;
            f.len = len;
            return f;
        }
    }

    return f;
}

void mk_http_cb_file_finished(struct mk_stream *stream)
{
    (void) stream;

    MK_TRACE("File finished");
}

#if defined (__linux__)
void mk_http_cb_file_on_consume(struct mk_stream *stream, long bytes)
{
    (void) bytes;

    /*
     * This callback is invoked just once as we want to turn off
     * the TCP Cork. We do this just overriding the callback for
     * the file stream.
     */
    mk_server_cork_flag(stream->channel->fd, TCP_CORK_OFF);
    stream->cb_bytes_consumed = NULL;
}
#endif

int mk_http_init(struct mk_http_session *cs, struct mk_http_request *sr)
{
    int ret;
    struct mimetype *mime;

    MK_TRACE("[FD %i] HTTP Protocol Init, session %p", cs->socket, sr);

    /* Request to root path of the virtualhost in question */
    if (sr->uri_processed.len == 1 && sr->uri_processed.data[0] == '/') {
        sr->real_path.data = sr->host_conf->documentroot.data;
        sr->real_path.len = sr->host_conf->documentroot.len;
    }

    /* Compose real path */
    if (sr->user_home == MK_FALSE) {
        int len;

        len = sr->host_conf->documentroot.len + sr->uri_processed.len;
        if (len < MK_PATH_BASE) {
            memcpy(sr->real_path_static,
                   sr->host_conf->documentroot.data,
                   sr->host_conf->documentroot.len);
            memcpy(sr->real_path_static + sr->host_conf->documentroot.len,
                   sr->uri_processed.data,
                   sr->uri_processed.len);
            sr->real_path_static[len] = '\0';
            sr->real_path.data = sr->real_path_static;
            sr->real_path.len = len;
        }
        else {
            ret = mk_buffer_cat(&sr->real_path,
                                sr->host_conf->documentroot.data,
                                sr->host_conf->documentroot.len,
                                sr->uri_processed.data,
                                sr->uri_processed.len);

            if (ret < 0) {
                MK_TRACE("Error composing real path");
                return EXIT_ERROR;
            }
        }
    }

    /* Check backward directory request */
    if (memmem(sr->uri_processed.data, sr->uri_processed.len,
               MK_HTTP_DIRECTORY_BACKWARD,
               sizeof(MK_HTTP_DIRECTORY_BACKWARD) - 1)) {
        return mk_http_error(MK_CLIENT_FORBIDDEN, cs, sr);
    }

    if (sr->_content_length.data &&
        (sr->method != MK_METHOD_POST &&
         sr->method != MK_METHOD_PUT)) {
        return mk_http_error(MK_CLIENT_BAD_REQUEST, cs, sr);
    }


    if (mk_file_get_info(sr->real_path.data,
                         &sr->file_info,
                         MK_FILE_READ) != 0) {
        /* if the requested resource doesn't exist,
         * check if some plugin would like to handle it
         */
        MK_TRACE("No file, look for handler plugin");
        ret = mk_plugin_stage_run_30(cs, sr);
        if (ret == MK_PLUGIN_RET_CLOSE_CONX) {
            if (sr->headers.status > 0) {
                return mk_http_error(sr->headers.status, cs, sr);
            }
            else {
                return mk_http_error(MK_CLIENT_FORBIDDEN, cs, sr);
            }
        }
        else if (ret == MK_PLUGIN_RET_CONTINUE) {
            return MK_PLUGIN_RET_CONTINUE;
        }
        else if (ret == MK_PLUGIN_RET_END) {
            return EXIT_NORMAL;
        }

        if (sr->file_info.exists == MK_FALSE) {
            return mk_http_error(MK_CLIENT_NOT_FOUND, cs, sr);
        }
        else if (sr->stage30_blocked == MK_FALSE) {
            return mk_http_error(MK_CLIENT_FORBIDDEN, cs, sr);
        }
    }

    /* is it a valid directory ? */
    if (sr->file_info.is_directory == MK_TRUE) {
        /* Send redirect header if end slash is not found */
        if (mk_http_directory_redirect_check(cs, sr) == -1) {
            MK_TRACE("Directory Redirect");

            /* Redirect has been sent */
            return -1;
        }

        /* looking for an index file */
        mk_ptr_t index_file;
        char tmppath[MK_MAX_PATH];
        index_file = mk_http_index_file(sr->real_path.data, tmppath, MK_MAX_PATH);

        if (index_file.data) {
            if (sr->real_path.data != sr->real_path_static) {
                mk_ptr_free(&sr->real_path);
                sr->real_path = index_file;
                sr->real_path.data = mk_string_dup(index_file.data);
            }
            /* If it's static and it still fits */
            else if (index_file.len < MK_PATH_BASE) {
                memcpy(sr->real_path_static, index_file.data, index_file.len);
                sr->real_path_static[index_file.len] = '\0';
                sr->real_path.len = index_file.len;
            }
            /* It was static, but didn't fit */
            else {
                sr->real_path = index_file;
                sr->real_path.data = mk_string_dup(index_file.data);
            }

            mk_file_get_info(sr->real_path.data, &sr->file_info, MK_FILE_READ);
        }
    }

    /* Check symbolic link file */
    if (sr->file_info.is_link == MK_TRUE) {
        if (mk_config->symlink == MK_FALSE) {
            return mk_http_error(MK_CLIENT_FORBIDDEN, cs, sr);
        }
        else {
            int n;
            char linked_file[MK_MAX_PATH];
            n = readlink(sr->real_path.data, linked_file, MK_MAX_PATH);
            if (n < 0) {
                return mk_http_error(MK_CLIENT_FORBIDDEN, cs, sr);
            }
        }
    }

    /* Plugin Stage 30: look for handlers for this request */
    if (sr->stage30_blocked == MK_FALSE) {
        ret = mk_plugin_stage_run_30(cs, sr);
        MK_TRACE("[FD %i] STAGE_30 returned %i", cs->socket, ret);
        switch (ret) {
        case MK_PLUGIN_RET_CONTINUE:
            return MK_PLUGIN_RET_CONTINUE;
        case MK_PLUGIN_RET_CLOSE_CONX:
            if (sr->headers.status > 0) {
                return mk_http_error(sr->headers.status, cs, sr);
            }
            else {
                return mk_http_error(MK_CLIENT_FORBIDDEN, cs, sr);
            }
        case MK_PLUGIN_RET_END:
            return EXIT_NORMAL;
        }
    }

    /*
     * Monkey listens for PUT and DELETE methods in addition to GET, POST and
     * HEAD, but it does not care about them, so if any plugin did not worked
     * on it, Monkey will return error 501 (501 Not Implemented).
     */
    if (sr->method == MK_METHOD_PUT || sr->method == MK_METHOD_DELETE ||
        sr->method == MK_METHOD_UNKNOWN) {
        return mk_http_error(MK_SERVER_NOT_IMPLEMENTED, cs, sr);
    }

    /* counter connections */
    sr->headers.pconnections_left = (int)
        (mk_config->max_keep_alive_request - cs->counter_connections);

    /* Set default value */
    mk_header_set_http_status(sr, MK_HTTP_OK);
    sr->headers.location = NULL;
    sr->headers.content_length = 0;

    /*
     * For OPTIONS method, we let the plugin handle it and
     * return without any content.
     */
    if (sr->method == MK_METHOD_OPTIONS) {
        /* FIXME: OPTIONS NOT WORKING */
        //sr->headers.allow_methods.data = MK_METHOD_AVAILABLE;
        //sr->headers.allow_methods.len = strlen(MK_METHOD_AVAILABLE);

        mk_ptr_reset(&sr->headers.content_type);
        mk_header_prepare(cs, sr);
        mk_channel_write(&cs->channel);
        return EXIT_NORMAL;
    }
    else {
        mk_ptr_reset(&sr->headers.allow_methods);
    }

    /* read permissions and check file */
    if (sr->file_info.read_access == MK_FALSE) {
        return mk_http_error(MK_CLIENT_FORBIDDEN, cs, sr);
    }

    /* Matching MimeType  */
    mime = mk_mimetype_find(&sr->real_path);
    if (!mime) {
        mime = mimetype_default;
    }

    if (sr->file_info.is_directory == MK_TRUE) {
        return mk_http_error(MK_CLIENT_FORBIDDEN, cs, sr);
    }

    /* get file size */
    if (sr->file_info.size < 0) {
        return mk_http_error(MK_CLIENT_NOT_FOUND, cs, sr);
    }

    sr->headers.last_modified = sr->file_info.last_modification;

    if (sr->if_modified_since.data && sr->method == MK_METHOD_GET) {
        time_t date_client;       /* Date sent by client */
        time_t date_file_server;  /* Date server file */

        date_client = mk_utils_gmt2utime(sr->if_modified_since.data);
        date_file_server = sr->file_info.last_modification;

        if (date_file_server <= date_client &&
            date_client > 0) {
            mk_header_set_http_status(sr, MK_NOT_MODIFIED);
            mk_header_prepare(cs, sr);
            mk_channel_write(&cs->channel);
            return EXIT_NORMAL;
        }
    }

    /* Object size for log and response headers */
    sr->headers.content_length = sr->file_info.size;
    sr->headers.real_length = sr->file_info.size;

    /* Open file */
    sr->file_stream.channel = &cs->channel;

    if (mk_likely(sr->file_info.size > 0)) {
        sr->file_stream.fd = mk_vhost_open(sr);
        if (sr->file_stream.fd == -1) {
            MK_TRACE("open() failed");
            return mk_http_error(MK_CLIENT_FORBIDDEN, cs, sr);
        }
        sr->file_stream.bytes_offset = 0;
        sr->file_stream.bytes_total  = sr->file_info.size;
    }

    /* Process methods */
    if (sr->method == MK_METHOD_GET || sr->method == MK_METHOD_HEAD) {
        sr->headers.content_type = mime->header_type;

        /* HTTP Ranges */
        if (sr->range.data != NULL && mk_config->resume == MK_TRUE) {
            if (mk_http_range_parse(sr) < 0) {
                sr->headers.ranges[0] = -1;
                sr->headers.ranges[1] = -1;
                return mk_http_error(MK_CLIENT_BAD_REQUEST, cs, sr);
            }
            if (sr->headers.ranges[0] >= 0 || sr->headers.ranges[1] >= 0) {
                mk_header_set_http_status(sr, MK_HTTP_PARTIAL);
            }

            /* Calc bytes to send & offset */
            if (mk_http_range_set(sr, sr->file_info.size) != 0) {
                sr->headers.content_length = -1;
                sr->headers.ranges[0] = -1;
                sr->headers.ranges[1] = -1;
                return mk_http_error(MK_CLIENT_REQUESTED_RANGE_NOT_SATISF, cs, sr);
            }
        }
    }
    else {
        /* without content-type */
        mk_ptr_reset(&sr->headers.content_type);
    }

    /* Send headers */
    mk_header_prepare(cs, sr);
    if (mk_unlikely(sr->headers.content_length == 0)) {
        return 0;
    }

    /* Send file content */
    if (sr->method == MK_METHOD_GET || sr->method == MK_METHOD_POST) {
        /* Note: bytes and offsets are set after the Range check */
        sr->file_stream.type = MK_STREAM_FILE;
        mk_channel_append_stream(&cs->channel, &sr->file_stream);
    }

    /*
     * Enable TCP Cork for the remote socket. It will be disabled
     * later by the file stream on the channel after send the first
     * file bytes.
     */
#if defined(__linux__)
    sr->file_stream.cb_bytes_consumed = mk_http_cb_file_on_consume;
#endif
    sr->file_stream.cb_finished       = mk_http_cb_file_finished;

    /*
     * Enable CORK/NO_PUSH
     * -------------------
     * If it was compiled for Linux, it will turn the Cork off after
     * send the first round of bytes from the target static file.
     *
     * For OSX, it sets TCP_NOPUSH off after send all HTTP headers. Refer
     * to mk_header.c for more details.
     */
    mk_server_cork_flag(cs->socket, TCP_CORK_ON);

    /* Start sending data to the channel */
    return mk_channel_write(&cs->channel);
}

/*
 * Check if a connection can stay open using
 * the keepalive headers vars and Monkey configuration as criteria
 */
int mk_http_keepalive_check(struct mk_http_session *cs)
{
    struct mk_http_request *sr_node;
    struct mk_list *sr_head;

    if (mk_list_is_empty(&cs->request_list) == 0) {
        return -1;
    }

    sr_head = &cs->request_list;
    sr_node = mk_list_entry_last(sr_head, struct mk_http_request, _head);
    if (mk_config->keep_alive == MK_FALSE || sr_node->keep_alive == MK_FALSE) {
        return -1;
    }

    /* Old client without Connection header */
    if (sr_node->protocol < MK_HTTP_PROTOCOL_11 &&
        sr_node->connection.len <= 0) {
        return -1;
    }

    /* Old client and content length to send is unknown */
    if (sr_node->protocol < MK_HTTP_PROTOCOL_11 &&
        sr_node->headers.content_length < 0) {
        return -1;
    }

    /* Connection was forced to close */
    if (sr_node->close_now == MK_TRUE) {
        return -1;
    }

    /* Client has reached keep-alive connections limit */
    if (cs->counter_connections >= mk_config->max_keep_alive_request) {
        return -1;
    }

    return 0;
}

int mk_http_request_end(int socket)
{
    int ka;
    struct mk_http_session *cs;
    struct mk_http_request *sr;
    struct sched_list_node *sched;

    sched = mk_sched_get_thread_conf();
    cs = mk_http_session_get(socket);
    if (!cs) {
        MK_TRACE("[FD %i] Not found", socket);
        return -1;
    }

    if (mk_unlikely(!sched)) {
        MK_TRACE("Could not find sched list node :/");
        return -1;
    }

    /* Check if we have some enqueued pipeline requests */
    if (cs->pipelined == MK_TRUE) {
        sr =  mk_list_entry_first(&cs->request_list, struct mk_http_request, _head);
        MK_TRACE("[FD %i] Pipeline finishing %p", socket, sr);

        /* Remove node and release resources */
        mk_list_del(&sr->_head);
        mk_http_request_free(sr);

        if (mk_list_is_empty(&cs->request_list) != 0) {
#ifdef TRACE
            sr = mk_list_entry_first(&cs->request_list, struct mk_http_request, _head);
            MK_TRACE("[FD %i] Pipeline next is %p", socket, sr);
#endif
            return 0;
        }
    }


    /*
     * We need to ask to http_keepalive if this
     * connection can continue working or we must
     * close it.
     */
    ka = mk_http_keepalive_check(cs);
    mk_http_request_free_list(cs);

    if (ka < 0) {
        MK_TRACE("[FD %i] No KeepAlive mode, remove", socket);
        mk_http_session_remove(socket);
    }
    else {
        mk_http_request_ka_next(cs);
        mk_event_add(sched->loop, socket, MK_EVENT_READ, NULL);
        return 0;
    }

    return -1;
}

void cb_stream_page_finished(struct mk_stream *stream)
{
    mk_ptr_t *page = stream->buffer;

    mk_ptr_free(page);
    mk_mem_free(page);
}

/* Send error responses */
int mk_http_error(int http_status, struct mk_http_session *cs,
                  struct mk_http_request *sr) {
    int ret, fd;
    mk_ptr_t message;
    mk_ptr_t *page = NULL;
    struct error_page *entry;
    struct mk_list *head;
    struct file_info finfo;

    mk_header_set_http_status(sr, http_status);

    /*
     * We are nice sending error pages for clients who at least respect
     * the especification
     */
    if (http_status != MK_CLIENT_LENGTH_REQUIRED &&
        http_status != MK_CLIENT_BAD_REQUEST &&
        http_status != MK_CLIENT_REQUEST_ENTITY_TOO_LARGE) {

        /* Lookup a customized error page */
        mk_list_foreach(head, &sr->host_conf->error_pages) {
            entry = mk_list_entry(head, struct error_page, _head);
            if (entry->status != http_status) {
                continue;
            }

            /* validate error file */
            ret = mk_file_get_info(entry->real_path, &finfo, MK_FILE_READ);
            if (ret == -1) {
                break;
            }

            /* open file */
            fd = open(entry->real_path, mk_config->open_flags);
            if (fd == -1) {
                break;
            }

            /* Outgoing headers */
            sr->headers.content_length = finfo.size;
            sr->headers.real_length    = finfo.size;
            mk_header_prepare(cs, sr);

            /* Stream setup */
            memcpy(&sr->file_info, &finfo, sizeof(struct file_info));
            sr->file_stream.type         = MK_STREAM_FILE;
            sr->file_stream.fd           = fd;
            sr->file_stream.bytes_total  = finfo.size;
            sr->file_stream.bytes_offset = 0;
            mk_channel_append_stream(&cs->channel, &sr->file_stream);

            return mk_channel_write(&cs->channel);
        }
    }

    mk_ptr_reset(&message);

    switch (http_status) {
    case MK_CLIENT_BAD_REQUEST:
        page = mk_http_error_page("Bad Request",
                                  NULL,
                                  mk_config->server_signature);
        break;

    case MK_CLIENT_FORBIDDEN:
        page = mk_http_error_page("Forbidden",
                                  &sr->uri,
                                  mk_config->server_signature);
        break;

    case MK_CLIENT_NOT_FOUND:
        mk_string_build(&message.data, &message.len,
                        "The requested URL was not found on this server.");
        page = mk_http_error_page("Not Found",
                                  &message,
                                  mk_config->server_signature);
        mk_ptr_free(&message);
        break;

    case MK_CLIENT_REQUEST_ENTITY_TOO_LARGE:
        mk_string_build(&message.data, &message.len,
                        "The request entity is too large.");
        page = mk_http_error_page("Entity too large",
                                  &message,
                                  mk_config->server_signature);
        mk_ptr_free(&message);
        break;

    case MK_CLIENT_METHOD_NOT_ALLOWED:
        page = mk_http_error_page("Method Not Allowed",
                                  &sr->uri,
                                  mk_config->server_signature);
        break;

    case MK_CLIENT_REQUEST_TIMEOUT:
    case MK_CLIENT_LENGTH_REQUIRED:
        break;

    case MK_SERVER_NOT_IMPLEMENTED:
        page = mk_http_error_page("Method Not Implemented",
                                  &sr->uri,
                                  mk_config->server_signature);
        break;

    case MK_SERVER_INTERNAL_ERROR:
        page = mk_http_error_page("Internal Server Error",
                                  &sr->uri,
                                  mk_config->server_signature);
        break;

    case MK_SERVER_HTTP_VERSION_UNSUP:
        mk_ptr_reset(&message);
        page = mk_http_error_page("HTTP Version Not Supported",
                                  &message,
                                  mk_config->server_signature);
        break;
    }

    if (page) {
        sr->headers.content_length = page->len;
    }

    sr->headers.location = NULL;
    sr->headers.cgi = SH_NOCGI;
    sr->headers.pconnections_left = 0;
    sr->headers.last_modified = -1;

    if (!page) {
        mk_ptr_reset(&sr->headers.content_type);
    }
    else {
        mk_ptr_set(&sr->headers.content_type, "Content-Type: text/html\r\n");
    }

    mk_header_prepare(cs, sr);
    if (page) {
        if (sr->method != MK_METHOD_HEAD) {
            mk_stream_set(&sr->page_stream,
                          MK_STREAM_PTR,
                          &cs->channel,
                          page,
                          -1,
                          NULL,
                          cb_stream_page_finished, NULL, NULL);
        }
    }

    /* Turn off TCP_CORK */
    mk_server_cork_flag(cs->socket, TCP_CORK_OFF);
    mk_channel_write(&cs->channel);

    return EXIT_NORMAL;
}

/*
 * From thread sched_list_node "list", remove the http_session
 * struct information
 */
void mk_http_session_remove(int socket)
{
    struct mk_http_session *cs_node;

    cs_node = mk_http_session_get(socket);
    if (cs_node) {
        rb_erase(&cs_node->_rb_head, cs_list);
        if (cs_node->body != cs_node->body_fixed) {
            mk_mem_free(cs_node->body);
        }
        if (cs_node->status == MK_REQUEST_STATUS_INCOMPLETE) {
            mk_list_del(&cs_node->request_incomplete);
        }
        mk_http_request_free_list(cs_node);
        mk_list_del(&cs_node->request_list);
        mk_mem_free(cs_node);
    }
}

struct mk_http_session *mk_http_session_get(int socket)
{
    struct mk_http_session *cs;
    struct rb_node *node;

    node = cs_list->rb_node;
  	while (node) {
  		cs = container_of(node, struct mk_http_session, _rb_head);
		if (socket < cs->socket)
  			node = node->rb_left;
		else if (socket > cs->socket)
  			node = node->rb_right;
		else {
  			return cs;
        }
	}
	return NULL;
}


/*
 * Create a client request struct and put it on the
 * main list
 */
struct mk_http_session *mk_http_session_create(int socket,
                                               struct sched_list_node *sched)
{
    struct mk_http_session *cs;
    struct sched_connection *sc;

    sc = mk_sched_get_connection(sched, socket);

    if (!sc) {
        MK_TRACE("[FD %i] No sched node, could not create session", socket);
        return NULL;
    }

    /* Alloc memory for node */
    cs = mk_mem_malloc(sizeof(struct mk_http_session));
    cs->pipelined = MK_FALSE;
    cs->counter_connections = 0;
    cs->socket = socket;
    cs->status = MK_REQUEST_STATUS_INCOMPLETE;
    mk_list_add(&cs->request_incomplete, cs_incomplete);

    /* Stream channel */
    cs->channel.type = MK_CHANNEL_SOCKET;
    cs->channel.fd   = socket;
    mk_list_init(&cs->channel.streams);

    /* creation time in unix time */
    cs->init_time = sc->arrive_time;

    /* alloc space for body content */
    if (mk_config->transport_buffer_size > MK_REQUEST_CHUNK) {
        cs->body = mk_mem_malloc(mk_config->transport_buffer_size);
        cs->body_size = mk_config->transport_buffer_size;
    }
    else {
        /* Buffer size based in Chunk bytes */
        cs->body = cs->body_fixed;
        cs->body_size = MK_REQUEST_CHUNK;
    }

    /* Current data length */
    cs->body_length = 0;

    /* Init session request list */
    mk_list_init(&cs->request_list);

    /* Initialize the parser */
    mk_http_parser_init(&cs->parser);

    /* Add this SESSION to the thread list */

    /* Add node to list */
    /* Red-Black tree insert routine */
    struct rb_node **new = &(cs_list->rb_node);
    struct rb_node *parent = NULL;

    /* Figure out where to put new node */
    while (*new) {
        struct mk_http_session *this = container_of(*new, struct mk_http_session, _rb_head);

        parent = *new;
        if (cs->socket < this->socket)
            new = &((*new)->rb_left);
        else if (cs->socket > this->socket)
            new = &((*new)->rb_right);
        else {
            /*
             * If we reach here, means there is a corruption. We should not create
             * a session of the value exists on the rbtree.
             *
             * Just warn about the situation, release resources and continue.
             */
            mk_exception();

            /* prepare exit */
            if (cs->body != cs->body_fixed) {
                mk_mem_free(cs->body);
            }
            mk_mem_free(cs);
            return NULL;
        }
    }
    /* Add new node and rebalance tree. */
    rb_link_node(&cs->_rb_head, parent, new);
    rb_insert_color(&cs->_rb_head, cs_list);

    return cs;
}


void mk_http_request_free(struct mk_http_request *sr)
{
    if (sr->vhost_fdt_enabled == MK_TRUE) {
        mk_vhost_close(sr);
    }
    else if(sr->file_stream.fd > 0) {
        close(sr->file_stream.fd);
    }

    if (sr->headers.location) {
        mk_mem_free(sr->headers.location);
    }

    if (sr->uri_processed.data != sr->uri.data) {
        mk_ptr_free(&sr->uri_processed);
    }

    if (sr->real_path.data != sr->real_path_static) {
        mk_ptr_free(&sr->real_path);
    }
}

void mk_http_request_free_list(struct mk_http_session *cs)
{
    struct mk_http_request *sr_node;
    struct mk_list *sr_head, *temp;

    /* sr = last node */
    MK_TRACE("[FD %i] Free struct client_session", cs->socket);

    mk_list_foreach_safe(sr_head, temp, &cs->request_list) {
        sr_node = mk_list_entry(sr_head, struct mk_http_request, _head);
        mk_list_del(sr_head);

        mk_http_request_free(sr_node);
        if (sr_node != &cs->sr_fixed) {
            mk_mem_free(sr_node);
        }
    }
}

void mk_http_request_ka_next(struct mk_http_session *cs)
{
    cs->body_length = 0;
    cs->counter_connections++;

    /* Update data for scheduler */
    cs->init_time = log_current_utime;
    cs->status = MK_REQUEST_STATUS_INCOMPLETE;
    mk_list_add(&cs->request_incomplete, cs_incomplete);
    mk_http_parser_init(&cs->parser);
}

/*
 * Lookup a known header or a non-known header. For unknown headers
 * set the 'key' value wth a lowercase string
 */
struct mk_http_header *mk_http_header_get(int name, struct mk_http_request *req,
                                          const char *key, unsigned int len)
{
    int i;
    struct mk_http_parser *parser = &req->session->parser;
    struct mk_http_header *header;

    /* Known header */
    if (name >= 0 && name < MK_HEADER_SIZEOF) {
        return &parser->headers[name];
    }

    /* Check if want to retrieve a custom header */
    if (name == MK_HEADER_OTHER) {
        /* Iterate over the extra headers identified by the parser */
        for (i = 0; i < parser->headers_extra_count; i++) {
            header = &parser->headers_extra[i];
            if (header->key.len != len) {
                continue;
            }

            if (strncmp(header->key.data, key, len) == 0) {
                return header;
            }
        }
        return NULL;
    }

    return NULL;
}
