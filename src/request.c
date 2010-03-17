/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P. <edsiper@gmail.com>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netdb.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "request.h"
#include "monkey.h"
#include "http.h"
#include "http_status.h"
#include "string.h"
#include "str.h"
#include "config.h"
#include "scheduler.h"
#include "epoll.h"
#include "socket.h"
#include "logfile.h"
#include "utils.h"
#include "header.h"
#include "user.h"
#include "method.h"
#include "memory.h"
#include "socket.h"
#include "cache.h"
#include "clock.h"
#include "utils.h"

struct request *mk_request_parse(struct client_request *cr)
{
    int i, end;
    int blocks = 0;
    struct request *cr_buf = 0, *cr_search = 0;

    for (i = 0; i <= cr->body_pos_end; i++) {
        /* Look for CRLFCRLF (\r\n\r\n), maybe some pipelining 
         * request can be involved. 
         */
        end = mk_string_search(cr->body + i, mk_endblock.data) + i;

        if (end <  0) {
            return NULL;
        }

        /* Allocating request block */
        cr_buf = mk_request_alloc();

        /* We point the block with a mk_pointer */
        cr_buf->body.data = cr->body + i;
        cr_buf->body.len = end - i;

        /* Method, previous catch in mk_http_pending_request */
        if (i == 0) {
            cr_buf->method = cr->first_method;
        }
        else {
            cr_buf->method = mk_http_method_get(cr_buf->body.data);
        }
        cr_buf->next = NULL;

        /* Looking for POST data */
        if (cr_buf->method == HTTP_METHOD_POST) {
            cr_buf->post_variables = mk_method_post_get_vars(cr->body, 
                                                             end + mk_endblock.len);
            if (cr_buf->post_variables.len >= 0) {
                i += cr_buf->post_variables.len;
            }
        }

        /* Increase index to the end of the current block */
        i = (end + mk_endblock.len) - 1;

        /* Link block */
        if (!cr->request) {
            cr->request = cr_buf;
        }
        else {
            cr_search = cr->request;
            while (cr_search) {
                if (cr_search->next == NULL) {
                    cr_search->next = cr_buf;
                    break;
                }
                else {
                    cr_search = cr_search->next;
                }
            }
        }

        /* Update counter */
        blocks++;
    }

     
    /* DEBUG BLOCKS 
    cr_search = cr->request;
    while(cr_search){
        printf("\n");
        MK_TRACE("BLOCK INIT");
        mk_pointer_print(cr_search->body);
        MK_TRACE("BLOCK_END");

        cr_search = cr_search->next;
    }
    */

    /* Checking pipelining connection */
    cr_search = cr->request;
    if (blocks > 1) {
        while (cr_search) {
            /* Pipelining request must use GET or HEAD methods */
            if (cr_search->method != HTTP_METHOD_GET &&
                cr_search->method != HTTP_METHOD_HEAD) {
                return NULL;
            }
            cr_search = cr_search->next;
        }
        
        cr->pipelined = TRUE;
    }

    return cr->request;
}

int mk_handler_read(int socket, struct client_request *cr)
{
    int bytes;

    bytes = read(socket, cr->body + cr->body_length,
                 MAX_REQUEST_BODY - cr->body_length);

    if (bytes < 0) {
        if (errno == EAGAIN) {
            return 1;
        }
        else {
            mk_request_client_remove(socket);
            return -1;
        }
    }
    if (bytes == 0) {
        mk_request_client_remove(socket);
        return -1;
    }

    if (bytes > 0) {
        cr->body_length += bytes;
        cr->body[cr->body_length] = '\0';
    }

    return bytes;
}

int mk_handler_write(int socket, struct client_request *cr)
{
    int bytes, final_status = 0;
    struct request *sr;

    /* 
     * Get node from schedule list node which contains
     * the information regarding to the current thread
     */
    if (!cr) {
        return -1;
    }

    if (!cr->request) {
        if (!mk_request_parse(cr)) {
            return -1;
        }
    }

    sr = cr->request;

    while (sr) {
        /* Request not processed also no plugin has take some action */
        if (sr->bytes_to_send < 0 && !sr->handled_by) {
            final_status = mk_request_process(cr, sr);
        }
        /* Request with data to send by static file sender */
        else if (sr->bytes_to_send > 0 && !sr->handled_by) {
            bytes = SendFile(socket, cr, sr);
            final_status = bytes;
        }
        else if (sr->handled_by){
            /* FIXME: Look for loops 
             * sr->handled_by; */
        }

        /*
         * If we got an error, we don't want to parse
         * and send information for another pipelined request
         */
        if (final_status > 0) {
            return final_status;
        }
        else if (final_status <= 0) {
            switch (final_status) {
            case EXIT_NORMAL:
                mk_logger_write_log(cr, sr->log, sr->host_conf);
                if (sr->close_now == VAR_ON) {
                    return -1;
                }
                break;
            case EXIT_ABORT:
                return -1;
                break;
            }
        }

        sr = sr->next;
    }

    /* If we are here, is because all pipelined request were
     * processed successfully, let's return 0;
     */
    return 0;
}

int mk_request_process(struct client_request *cr, struct request *s_request)
{
    int status = 0;
    struct host *host;

    status = mk_request_header_process(s_request);

    if (status < 0) {
        return EXIT_ABORT;
    }

    switch (s_request->method) {
    case METHOD_NOT_ALLOWED:
        mk_request_error(M_CLIENT_METHOD_NOT_ALLOWED, cr,
                         s_request, 1, s_request->log);
        return EXIT_NORMAL;
    case METHOD_NOT_FOUND:
        mk_request_error(M_SERVER_NOT_IMPLEMENTED, cr,
                         s_request, 1, s_request->log);
        return EXIT_NORMAL;
    }

    s_request->user_home = VAR_OFF;
    s_request->log->method = s_request->method;

    /* Valid request URI? */
    if (s_request->uri_processed == NULL) {
        mk_request_error(M_CLIENT_BAD_REQUEST, cr, s_request, 1,
                         s_request->log);
        return EXIT_NORMAL;
    }

    /* HTTP/1.1 needs Host header */
    if (!s_request->host.data && s_request->protocol == HTTP_PROTOCOL_11) {
        s_request->log->final_response = M_CLIENT_BAD_REQUEST;
        mk_request_error(M_CLIENT_BAD_REQUEST, cr, s_request, 1,
                         s_request->log);
        return EXIT_NORMAL;
    }

    /* Method not allowed ? */
    if (s_request->method == METHOD_NOT_ALLOWED) {
        s_request->log->final_response = M_CLIENT_METHOD_NOT_ALLOWED;
        mk_request_error(M_CLIENT_METHOD_NOT_ALLOWED, cr, s_request, 1,
                         s_request->log);
        return EXIT_NORMAL;
    }

    /* Validating protocol version */
    if (s_request->protocol == HTTP_PROTOCOL_UNKNOWN) {

        s_request->log->final_response = M_SERVER_HTTP_VERSION_UNSUP;
        mk_request_error(M_SERVER_HTTP_VERSION_UNSUP, cr, s_request, 1,
                         s_request->log);
        return EXIT_NORMAL;
    }

    if (s_request->host.data) {
        host = mk_config_host_find(s_request->host);
        if (host) {
            s_request->host_conf = host;
        }
        else {
            s_request->host_conf = config->hosts;
        }
    }
    else {
        s_request->host_conf = config->hosts;
    }
    s_request->log->host_conf = s_request->host_conf;

    /* is requesting an user home directory ? */
    if (config->user_dir) {
        if (strncmp(s_request->uri_processed,
                    mk_user_home.data, mk_user_home.len) == 0) {
            if (mk_user_init(cr, s_request) != 0) {
                return EXIT_NORMAL;
            }
        }
    }

    /* Handling method requested */
    if (s_request->method == HTTP_METHOD_POST) {
        if ((status = mk_method_post(cr, s_request)) == -1) {
            return status;
        }
    }

    status = mk_http_init(cr, s_request);

#ifdef TRACE
    MK_TRACE("HTTP Init returning %i", status);
#endif

    return status;
}

/* Return a struct with method, URI , protocol version 
and all static headers defined here sent in request */
int mk_request_header_process(struct request *sr)
{
    int uri_init = 0, uri_end = 0;
    char *query_init = 0;
    int prot_init = 0, prot_end = 0, pos_sep = 0;
    int fh_limit;
    char *port = 0;
    char *headers;
    mk_pointer host;

    /* If verification fails it will return always
     * a bad request status
     */
    sr->log->final_response = M_CLIENT_BAD_REQUEST;

    /* Method */
    sr->method_p = mk_http_method_check_str(sr->method);

    /* Request URI */
    uri_init = (index(sr->body.data, ' ') - sr->body.data) + 1;
    fh_limit = (index(sr->body.data, '\n') - sr->body.data);

    uri_end = mk_string_search_r(sr->body.data, ' ', fh_limit) - 1;

    if (uri_end <= 0) {
        return -1;
    }

    prot_init = uri_end + 2;

    if (uri_end < uri_init) {
        return -1;
    }

    /* Query String */
    query_init = index(sr->body.data + uri_init, '?');
    if (query_init) {
        int init, end;

        init = (int) (query_init - (sr->body.data + uri_init)) + uri_init;
        if (init <= uri_end) {
            end = uri_end;
            uri_end = init - 1;

            sr->query_string = mk_pointer_create(sr->body.data,
                                                 init + 1, end + 1);
        }
    }

    /* Request URI Part 2 */
    sr->uri = sr->log->uri = mk_pointer_create(sr->body.data,
                                               uri_init, uri_end + 1);

    if (sr->uri.len < 1) {
        return -1;
    }


    /* HTTP Version */
    prot_end = fh_limit - 1;
    if (prot_end != prot_init && prot_end > 0) {
        sr->protocol = sr->log->protocol =
            mk_http_protocol_check(sr->body.data + prot_init,
                                   prot_end - prot_init);
    }

    headers = sr->body.data + prot_end + mk_crlf.len;

    /* URI processed */
    sr->uri_processed = mk_utils_hexuri_to_ascii(sr->uri);

    if (!sr->uri_processed) {
        sr->uri_processed = mk_pointer_to_buf(sr->uri);
        sr->uri_twin = VAR_ON;
    }

    /* Creating table of content (index) for request headers */
    int toc_len = MK_KNOWN_HEADERS;
    int headers_len = sr->body.len - (prot_end + mk_crlf.len);

    struct header_toc *toc = mk_request_header_toc_create(toc_len);
    mk_request_header_toc_parse(toc, toc_len, headers, headers_len);

    /* Host */
    host = mk_request_header_find(toc, toc_len, headers, mk_rh_host);

    if (host.data) {
        if ((pos_sep = mk_string_char_search(host.data, ':', host.len)) >= 0) {
            sr->host.data = host.data;
            sr->host.len = pos_sep;

            port = mk_string_copy_substr(host.data, pos_sep + 1, host.len);
            sr->port = atoi(port);
            mk_mem_free(port);
        }
        else {
            sr->host = host;    /* maybe null */
            sr->port = config->standard_port;
        }
    }
    else {
        sr->host.data = NULL;
    }

    /* Looking for headers */
    sr->accept = mk_request_header_find(toc, toc_len, headers, mk_rh_accept);
    sr->accept_charset = mk_request_header_find(toc, toc_len, headers,
                                                mk_rh_accept_charset);
    sr->accept_encoding = mk_request_header_find(toc, toc_len, headers,
                                                 mk_rh_accept_encoding);


    sr->accept_language = mk_request_header_find(toc, toc_len, headers,
                                                 mk_rh_accept_language);
    sr->cookies = mk_request_header_find(toc, toc_len, headers, mk_rh_cookie);
    sr->connection = mk_request_header_find(toc, toc_len, headers,
                                            mk_rh_connection);
    sr->referer = mk_request_header_find(toc, toc_len, headers,
                                         mk_rh_referer);
    sr->user_agent = mk_request_header_find(toc, toc_len, headers,
                                            mk_rh_user_agent);
    sr->range = mk_request_header_find(toc, toc_len, headers, mk_rh_range);
    sr->if_modified_since = mk_request_header_find(toc, toc_len, headers,
                                                   mk_rh_if_modified_since);

    /* Default Keepalive is off */
    if (sr->protocol == HTTP_PROTOCOL_10) {
        sr->keep_alive = VAR_OFF;
        sr->close_now = VAR_ON;
    }
    else if(sr->protocol == HTTP_PROTOCOL_11) {
        sr->keep_alive = VAR_ON;
        sr->close_now = VAR_OFF;
    }

    if (sr->connection.data) {
        if (mk_string_casestr(sr->connection.data, "Keep-Alive")) {
            sr->keep_alive = VAR_ON;
            sr->close_now = VAR_OFF;
        }
        else if(mk_string_casestr(sr->connection.data, "Close")) {
            sr->keep_alive = VAR_OFF;
            sr->close_now = VAR_ON;
        }
        else {
            /* Set as a non-valid connection header value */
            sr->connection.len = 0;
        }
    }
    sr->log->final_response = M_HTTP_OK;

    return 0;
}

/* Return value of some variable sent in request */
mk_pointer mk_request_header_find(struct header_toc * toc, int toc_len,
                                  char *request_body, mk_pointer header)
{
    int i;
    mk_pointer var;

    var.data = NULL;
    var.len = 0;

    /* new code */
    if (toc) {
        for (i = 0; i < toc_len; i++) {
            /* status = 1 means that the toc entry was already
             * checked by monkey 
             */
            if (toc[i].status == 1) {
                continue;
            }

            if (!toc[i].init)
                break;

            if (strncasecmp(toc[i].init, header.data, header.len) == 0) {
                var.data = toc[i].init + header.len + 1;
                var.len = toc[i].end - var.data;
                toc[i].status = 1;
                return var;
            }
        }
    }

    return var;
}

/* FIXME: IMPROVE access */
/* Look for some  index.xxx in pathfile */
mk_pointer mk_request_index(char *pathfile)
{
    unsigned long len;
    char *file_aux = 0;
    mk_pointer f;
    struct indexfile *aux_index;

    mk_pointer_reset(&f);

    aux_index = first_index;

    while (aux_index) {
        m_build_buffer(&file_aux, &len, "%s%s",
                       pathfile, aux_index->indexname);

        if (access(file_aux, F_OK) == 0) {
            f.data = file_aux;
            f.len = len;
            return f;
        }
        mk_mem_free(file_aux);
        aux_index = aux_index->next;
    }

    return f;
}

/* Send error responses */
void mk_request_error(int num_error, struct client_request *cr,
                      struct request *s_request, int debug,
                      struct log_info *s_log)
{
    char *aux_message = 0;
    mk_pointer message, *page = 0;
    long n;

    s_log->error_details.data = NULL;

    switch (num_error) {
    case M_CLIENT_BAD_REQUEST:
        page = mk_request_set_default_page("Bad Request",
                                           s_request->uri,
                                           s_request->host_conf->
                                           host_signature);
        s_log->error_msg = request_error_msg_400;
        break;

    case M_CLIENT_FORBIDDEN:
        page = mk_request_set_default_page("Forbidden",
                                           s_request->uri,
                                           s_request->host_conf->
                                           host_signature);
        s_log->error_msg = request_error_msg_403;
        s_log->error_details = s_request->uri;
        break;

    case M_CLIENT_NOT_FOUND:
        m_build_buffer(&message.data, &message.len,
                       "The requested URL was not found on this server.");
        page = mk_request_set_default_page("Not Found",
                                           message,
                                           s_request->host_conf->
                                           host_signature);
        s_log->error_msg = request_error_msg_404;
        s_log->error_details = s_request->uri;

        mk_pointer_free(&message);
        break;

    case M_CLIENT_METHOD_NOT_ALLOWED:
        page = mk_request_set_default_page("Method Not Allowed",
                                           s_request->uri,
                                           s_request->host_conf->
                                           host_signature);

        s_log->final_response = M_CLIENT_METHOD_NOT_ALLOWED;
        s_log->error_msg = request_error_msg_405;
        s_log->error_details = s_request->method_p;
        break;

    case M_CLIENT_REQUEST_TIMEOUT:
        s_log->status = S_LOG_OFF;
        s_log->error_msg = request_error_msg_408;
        break;

    case M_CLIENT_LENGTH_REQUIRED:
        s_log->error_msg = request_error_msg_411;
        break;

    case M_SERVER_NOT_IMPLEMENTED:
        page = mk_request_set_default_page("Method Not Implemented",
                                           s_request->uri,
                                           s_request->host_conf->
                                           host_signature);
        s_log->final_response = M_SERVER_NOT_IMPLEMENTED;
        s_log->error_msg = request_error_msg_501;
        s_log->error_details = s_request->method_p;
        break;

    case M_SERVER_INTERNAL_ERROR:
        m_build_buffer(&message.data, &message.len,
                       "Problems found running %s ", s_request->uri);
        page = mk_request_set_default_page("Internal Server Error",
                                           message,
                                           s_request->host_conf->
                                           host_signature);
        s_log->error_msg = request_error_msg_500;

        mk_pointer_free(&message);
        break;

    case M_SERVER_HTTP_VERSION_UNSUP:
        mk_pointer_reset(&message);
        page = mk_request_set_default_page("HTTP Version Not Supported",
                                           message,
                                           s_request->host_conf->
                                           host_signature);
        s_log->error_msg = request_error_msg_505;
        break;
    }

    s_log->final_response = num_error;

    s_request->headers->status = num_error;
    if (page) {
        s_request->headers->content_length = page->len;
        s_request->headers->content_length_p = mk_utils_int2mkp(page->len);
    }

    s_request->headers->location = NULL;
    s_request->headers->cgi = SH_NOCGI;
    s_request->headers->pconnections_left = 0;
    mk_pointer_reset(&s_request->headers->last_modified);

    if (aux_message)
        mk_mem_free(aux_message);

    if (!page) {
        mk_pointer_reset(&s_request->headers->content_type);
    }
    else {
        mk_pointer_set(&s_request->headers->content_type, "text/html\r\n");
    }

    mk_header_send(cr->socket, cr, s_request, s_log);

    if (debug == 1) {
        n = write(cr->socket, page->data, page->len);
        mk_pointer_free(page);
        mk_mem_free(page);
    }
}

/* Build error page */
mk_pointer *mk_request_set_default_page(char *title, mk_pointer message,
                                        char *signature)
{
    char *temp;
    mk_pointer *p;

    p = mk_mem_malloc(sizeof(mk_pointer));

    temp = mk_pointer_to_buf(message);
    m_build_buffer(&p->data, &p->len,
                   MK_REQUEST_DEFAULT_PAGE, title, temp, signature);
    mk_mem_free(temp);

    return p;
}

/* Create a memory allocation in order to handle the request data */
struct request *mk_request_alloc()
{
    struct request *request = 0;

    request = mk_mem_malloc(sizeof(struct request));
    request->log = mk_mem_malloc(sizeof(struct log_info));

    request->status = VAR_OFF;  /* Request not processed yet */
    request->make_log = VAR_ON; /* build log file of this request ? */
    request->close_now = VAR_OFF;

    mk_pointer_reset(&request->body);

    request->log->final_response = M_HTTP_OK;
    request->log->status = S_LOG_ON;
    mk_pointer_reset(&request->log->size_p);
    mk_pointer_reset(&request->log->error_msg);

    request->status = VAR_ON;
    request->method = METHOD_NOT_FOUND;

    mk_pointer_reset(&request->uri);
    request->uri_processed = NULL;
    request->uri_twin = VAR_OFF;

    request->accept.data = NULL;
    request->accept_language.data = NULL;
    request->accept_encoding.data = NULL;
    request->accept_charset.data = NULL;
    request->content_length = 0;
    request->content_type.data = NULL;
    request->connection.data = NULL;
    request->cookies.data = NULL;
    request->host.data = NULL;
    request->if_modified_since.data = NULL;
    request->last_modified_since.data = NULL;
    request->range.data = NULL;
    request->referer.data = NULL;
    request->resume.data = NULL;
    request->user_agent.data = NULL;

    request->post_variables.data = NULL;

    request->user_uri = NULL;
    mk_pointer_reset(&request->query_string);

    request->file_info = NULL;
    request->virtual_user = NULL;
    request->script_filename = NULL;
    mk_pointer_reset(&request->real_path);
    request->host_conf = config->hosts;

    request->loop = 0;
    request->bytes_to_send = -1;
    request->bytes_offset = 0;
    request->fd_file = -1;

    /* Response Headers */
    request->headers = mk_header_create();

    request->handled_by = NULL;
    return request;
}

void mk_request_free_list(struct client_request *cr)
{
    struct request *sr = 0, *before = 0;

    /* sr = last node */

    while (cr->request) {
        sr = before = cr->request;

        while (sr->next) {
            sr = sr->next;
        }

        if (sr != cr->request) {
            while (before->next != sr) {
                before = before->next;
            }
            before->next = NULL;
        }
        else {
            cr->request = NULL;
        }
        mk_request_free(sr);
    }
    cr->request = NULL;
}

void mk_request_free(struct request *sr)
{
    /* I hate it, but I don't know another light way :( */
    if (sr->fd_file > 0) {
        close(sr->fd_file);
    }
    if (sr->headers) {
        mk_mem_free(sr->headers->location);
        mk_pointer_free(&sr->headers->content_length_p);
        mk_pointer_free(&sr->headers->last_modified);
        /*
           mk_mem_free(sr->headers->content_type);
           headers->content_type never it's allocated 
           with malloc or something, so we don't need 
           to free it, the value has been freed before 
           in M_METHOD_Get_and_Head(struct request *sr)

           this BUG was reported by gentoo team.. thanks guys XD
         */

        mk_mem_free(sr->headers);
    }


    if (sr->log) {
        /*
         * We do not free log->size_p, as if it was
         * used due to an error, it points to the 
         * same memory block than header->content_length_p
         * points to, we just reset it.
         */
        mk_pointer_reset(&sr->log->size_p);

        /*
         * sr->log->error_msg just point to
         * local data on request.c, no 
         * dynamic allocation is made
         */

        mk_mem_free(sr->log);
    }

    mk_pointer_reset(&sr->body);
    mk_pointer_reset(&sr->uri);

    if (sr->uri_twin == VAR_ON) {
        mk_mem_free(sr->uri_processed);
    }

    mk_pointer_free(&sr->post_variables);
    mk_mem_free(sr->user_uri);
    mk_pointer_reset(&sr->query_string);

    mk_mem_free(sr->file_info);
    mk_mem_free(sr->virtual_user);
    mk_mem_free(sr->script_filename);
    mk_pointer_free(&sr->real_path);
    mk_mem_free(sr);
}

/* Create a client request struct and put it on the
 * main list
 */
struct client_request *mk_request_client_create(int socket)
{
    struct request_idx *request_index;
    struct client_request *cr;
    struct sched_connection *sc;

    sc = mk_sched_get_connection(NULL, socket);
    cr = mk_mem_malloc(sizeof(struct client_request));

    /* IPv4 Address */
    cr->ipv4 = &sc->ipv4;

    cr->pipelined = FALSE;
    cr->counter_connections = 0;
    cr->socket = socket;
    cr->status = MK_REQUEST_STATUS_INCOMPLETE;
    cr->request = NULL;

    /* creation time in unix time */
    cr->init_time = sc->arrive_time;

    cr->next = NULL;
    cr->body = mk_mem_malloc(MAX_REQUEST_BODY);
    cr->body_length = 0;
    cr->body_pos_end = -1;
    cr->first_method = HTTP_METHOD_UNKNOWN;

    request_index = mk_sched_get_request_index();
    if (!request_index->first) {
        request_index->first = request_index->last = cr;
    }
    else {
        request_index->last->next = cr;
        request_index->last = cr;
    }
    mk_sched_set_request_index(request_index);

    return cr;
}

struct client_request *mk_request_client_get(int socket)
{
    struct request_idx *request_index;
    struct client_request *cr = NULL;

    request_index = mk_sched_get_request_index();
    cr = request_index->first;
    while (cr != NULL) {
        if (cr->socket == socket) {
            break;
        }
        cr = cr->next;
    }

    return cr;
}

/*
 * From thread sched_list_node "list", remove the client_request
 * struct information 
 */
struct client_request *mk_request_client_remove(int socket)
{
    struct request_idx *request_index;
    struct client_request *cr, *aux;

    request_index = mk_sched_get_request_index();
    cr = request_index->first;

    while (cr) {
        if (cr->socket == socket) {
            if (cr == request_index->first) {
                request_index->first = cr->next;
            }
            else {
                aux = request_index->first;
                while (aux->next != cr) {
                    aux = aux->next;
                }
                aux->next = cr->next;
                if (!aux->next) {
                    request_index->last = aux;
                }
            }
            break;
        }
        cr = cr->next;
    }

    //mk_pointer_free(&cr->ip);
    mk_mem_free(cr->body);
    mk_mem_free(cr);

    return NULL;
}

struct header_toc *mk_request_header_toc_create(int len)
{
    int i;
    struct header_toc *p;

    p = (struct header_toc *) pthread_getspecific(mk_cache_header_toc);

    for (i = 0; i < len; i++) {
        p[i].init = NULL;
        p[i].end = NULL;
        p[i].status = 0;
    }
    return p;
}

void mk_request_header_toc_parse(struct header_toc *toc, int toc_len, char *data, int len)
{
    char *p, *l = 0;
    int i;

    p = data;
    for (i = 0; i < toc_len && p && l < data + len; i++) {
        l = strstr(p, MK_CRLF);
        if (l) {
            toc[i].init = p;
            toc[i].end = l;
            p = l + mk_crlf.len;
        }
        else {
            break;
        }
    }
}

void mk_request_ka_next(struct client_request *cr)
{
    bzero(cr->body, sizeof(cr->body));
    cr->first_method = -1;
    cr->body_pos_end = -1;
    cr->body_length = 0;
    cr->counter_connections++;

    /* Update data for scheduler */
    cr->init_time = log_current_utime;
    cr->status = MK_REQUEST_STATUS_INCOMPLETE;
}
