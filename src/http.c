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
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "monkey.h"
#include "memory.h"
#include "http.h"
#include "http_status.h"
#include "file.h"
#include "utils.h"
#include "config.h"
#include "str.h"
#include "method.h"
#include "socket.h"
#include "mimetype.h"
#include "logfile.h"
#include "header.h"
#include "epoll.h"
#include "plugin.h"

int mk_http_method_check(mk_pointer method)
{
    if (strncmp(method.data, HTTP_METHOD_GET_STR, method.len) == 0) {
        return HTTP_METHOD_GET;
    }

    if (strncmp(method.data, HTTP_METHOD_POST_STR, method.len) == 0) {
        return HTTP_METHOD_POST;
    }

    if (strncmp(method.data, HTTP_METHOD_HEAD_STR, method.len) == 0) {
        return HTTP_METHOD_HEAD;
    }

    return METHOD_NOT_FOUND;
}

mk_pointer mk_http_method_check_str(int method)
{
    switch (method) {
    case HTTP_METHOD_GET:
        return mk_http_method_get_p;

    case HTTP_METHOD_POST:
        return mk_http_method_post_p;

    case HTTP_METHOD_HEAD:
        return mk_http_method_head_p;
    }
    return mk_http_method_null_p;
}

int mk_http_method_get(char *body)
{
    int int_method, pos = 0;
    int max_len_method = 5;
    mk_pointer method;

    /* Max method length is 4 (POST/HEAD) */
    pos = mk_string_char_search(body, ' ', 5);
    if (pos <= 2 || pos >= max_len_method) {
        return METHOD_NOT_FOUND;
    }

    method.data = body;
    method.len = (unsigned long) pos;

    int_method = mk_http_method_check(method);

    return int_method;
}

int mk_http_protocol_check(char *protocol, int len)
{
    if (strncmp(protocol, HTTP_PROTOCOL_11_STR, len) == 0) {
        return HTTP_PROTOCOL_11;
    }
    if (strncmp(protocol, HTTP_PROTOCOL_10_STR, len) == 0) {
        return HTTP_PROTOCOL_10;
    }
    if (strncmp(protocol, HTTP_PROTOCOL_09_STR, len) == 0) {
        return HTTP_PROTOCOL_09;
    }

    return HTTP_PROTOCOL_UNKNOWN;
}

mk_pointer mk_http_protocol_check_str(int protocol)
{
    if (protocol == HTTP_PROTOCOL_11) {
        return mk_http_protocol_11_p;
    }
    if (protocol == HTTP_PROTOCOL_10) {
        return mk_http_protocol_10_p;
    }
    if (protocol == HTTP_PROTOCOL_09) {
        return mk_http_protocol_09_p;
    }

    return mk_http_protocol_null_p;
}

int mk_http_init(struct client_request *cr, struct request *sr)
{
    int ret;
    int debug_error = 0, bytes = 0;
    struct mimetype *mime;
    char *uri_data = NULL;
    char uri_len = 0;
    mk_pointer gmt_file_unix_time;      // gmt time of server file (unix time)

#ifdef TRACE
    MK_TRACE("HTTP Protocol Init");
#endif

    /* Normal request default site */
    if ((strcmp(sr->uri_processed, "/")) == 0) {
        sr->real_path.data = mk_string_dup(sr->host_conf->documentroot.data);
        sr->real_path.len = sr->host_conf->documentroot.len;
    }

    /* Map URI */
    if (sr->uri_processed) {
        uri_data = sr->uri_processed;
        uri_len = strlen(sr->uri_processed);
    }
    else{
        uri_data = sr->uri.data;
        uri_len = sr->uri.len;
    }

    /* Compose real path */
    if (sr->user_home == VAR_OFF) {
        mk_buffer_cat(&sr->real_path, 
                      sr->host_conf->documentroot.data,
                      sr->host_conf->documentroot.len,
                      uri_data,
                      uri_len);
    }

    if (sr->method != HTTP_METHOD_HEAD) {
        debug_error = 1;
    }

    /* Check backward directory request */
    if (mk_string_search_n(uri_data, 
                           HTTP_DIRECTORY_BACKWARD,
                           uri_len) >= 0) {
        sr->log->final_response = M_CLIENT_FORBIDDEN;
        mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, debug_error, sr->log);
        return EXIT_ERROR;
    }

    sr->file_info = mk_file_get_info(sr->real_path.data);

    if (!sr->file_info) {
        /* if the resource requested doesn't exists, let's 
         * check if some plugin would like to handle it
         */
#ifdef TRACE
        MK_TRACE("No file, look for handler plugin");
#endif
        ret = mk_plugin_stage_run(MK_PLUGIN_STAGE_30, cr->socket, NULL, cr, sr);
        if (ret == MK_PLUGIN_RET_CLOSE_CONX) {
            sr->log->final_response = M_CLIENT_FORBIDDEN;
            mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, debug_error, sr->log);
            return EXIT_ERROR;
        }
        else if (ret == MK_PLUGIN_RET_CONTINUE) {
            return MK_PLUGIN_RET_CONTINUE;
        } 
        else if (ret == MK_PLUGIN_RET_END) {
            return EXIT_NORMAL;
        }

        mk_request_error(M_CLIENT_NOT_FOUND, cr, sr, debug_error, sr->log);
        return -1;
    }

    /* is it a valid directory ? */
    if (sr->file_info->is_directory == MK_FILE_TRUE) {
        /* Send redirect header if end slash is not found */
        if (mk_http_directory_redirect_check(cr, sr) == -1) {
#ifdef TRACE
            MK_TRACE("Directory Redirect");
#endif
            /* Redirect has been sent */
            return -1;
        }

        /* looking for a index file */
        mk_pointer index_file;
        index_file = mk_request_index(sr->real_path.data);

        if (index_file.data) {
            mk_mem_free(sr->file_info);
            mk_pointer_free(&sr->real_path);

            sr->real_path = index_file;
            sr->file_info = mk_file_get_info(sr->real_path.data);
        }
    }

    /* Check symbolic link file */
    if (sr->file_info->is_link == MK_FILE_TRUE) {
        if (config->symlink == VAR_OFF) {
            sr->log->final_response = M_CLIENT_FORBIDDEN;
            mk_request_error(M_CLIENT_FORBIDDEN, cr, sr,
                             debug_error, sr->log);
            return EXIT_ERROR;
        }
        else {
            int n;
            char linked_file[MAX_PATH];
            n = readlink(sr->real_path.data, linked_file, MAX_PATH);
        }
    }

    /* Plugin Stage 30: look for handlers for this request */
    ret  = mk_plugin_stage_run(MK_PLUGIN_STAGE_30, 0, NULL, cr, sr);
#ifdef TRACE
    MK_TRACE("STAGE_30 returned %i", ret);
#endif
    if (ret == MK_PLUGIN_RET_CLOSE_CONX) {
        sr->log->final_response = M_CLIENT_FORBIDDEN;
        mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, debug_error, sr->log);
        return EXIT_ERROR;
    }
    else if (ret == MK_PLUGIN_RET_CONTINUE) {
        return MK_PLUGIN_RET_CONTINUE;
    } 
    else if (ret == MK_PLUGIN_RET_END) {
        return EXIT_NORMAL;
    }

    /* read permissions and check file */
    if (sr->file_info->read_access == MK_FILE_FALSE) {
        mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, 1, sr->log);
        return EXIT_ERROR;
    }

    /* Matching MimeType  */
    mime = mk_mimetype_find(&sr->real_path);
    if (!mime) {
        mime = mimetype_default;
    }

    if (sr->file_info->is_directory == MK_FILE_TRUE) {
        mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, 1, sr->log);
        return EXIT_ERROR;
    }

    /* get file size */
    if (sr->file_info->size < 0) {
        mk_request_error(M_CLIENT_NOT_FOUND, cr, sr, 1, sr->log);
        return EXIT_ERROR;
    }

    /* counter connections */
    sr->headers->pconnections_left = (int)
        (config->max_keep_alive_request - cr->counter_connections);


    gmt_file_unix_time =
        PutDate_string((time_t) sr->file_info->last_modification);

    if (sr->if_modified_since.data && sr->method == HTTP_METHOD_GET) {
        time_t date_client;       /* Date sent by client */
        time_t date_file_server;  /* Date server file */
        
        date_client = PutDate_unix(sr->if_modified_since.data);
        date_file_server = sr->file_info->last_modification;

        if ((date_file_server <= date_client) && (date_client > 0)) {
            sr->headers->status = M_NOT_MODIFIED;
            mk_header_send(cr->socket, cr, sr, sr->log);
            mk_pointer_free(&gmt_file_unix_time);
            return EXIT_NORMAL;
        }
    }
    sr->headers->status = M_HTTP_OK;
    sr->headers->cgi = SH_NOCGI;
    sr->headers->last_modified = gmt_file_unix_time;
    sr->headers->location = NULL;

    /* Object size for log and response headers */
    sr->headers->content_length = sr->file_info->size;

    if (sr->method == HTTP_METHOD_HEAD) {
        sr->log->size = 0;
        sr->log->size_p = mk_utils_int2mkp(0);
    }
    else {
        sr->log->size = sr->file_info->size;
        sr->log->size_p = sr->headers->content_length_p;
    }

    if (sr->method == HTTP_METHOD_GET || sr->method == HTTP_METHOD_POST) {
        sr->headers->content_type = mime->type;
        /* Range */
        if (sr->range.data != NULL && config->resume == VAR_ON) {
            if (mk_http_range_parse(sr) < 0) {
                mk_request_error(M_CLIENT_BAD_REQUEST, cr, sr, 1, sr->log);
                mk_pointer_free(&gmt_file_unix_time);
                return EXIT_ERROR;
            }
            if (sr->headers->ranges[0] >= 0 || sr->headers->ranges[1] >= 0)
                sr->headers->status = M_HTTP_PARTIAL;
        }
    }
    else {                      
        /* without content-type */
        mk_pointer_reset(&sr->headers->content_type);
    }
 
    /* Open file */
    if (sr->file_info->size > 0) {
        sr->fd_file = open(sr->real_path.data, config->open_flags);
        if (sr->fd_file == -1) {
#ifdef TRACE
            MK_TRACE("open() failed");
#endif
            sr->log->final_response = M_CLIENT_FORBIDDEN;
            mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, debug_error, sr->log);
            return EXIT_ERROR;
        }
    }

    /* Send headers */
    mk_header_send(cr->socket, cr, sr, sr->log);

    if (sr->headers->content_length == 0) {
        return 0;
    }

    /* Send file content*/
    if (sr->method == HTTP_METHOD_GET || sr->method == HTTP_METHOD_POST) {
        /* Calc bytes to send & offset */
        if (mk_http_range_set(sr, sr->file_info->size) != 0) {
            mk_request_error(M_CLIENT_BAD_REQUEST, cr, sr, 1, sr->log);
            return EXIT_ERROR;
        }

        bytes = mk_http_send_file(cr, sr);
    }

    return bytes;
}

int mk_http_send_file(struct client_request *cr, struct request *sr)
{
    long int nbytes = 0;

    nbytes = mk_socket_send_file(cr->socket, sr->fd_file,
                                 &sr->bytes_offset, sr->bytes_to_send);

    if (nbytes > 0) {
        if (sr->loop == 0) {
            mk_socket_set_cork_flag(cr->socket, TCP_CORK_OFF);
        }
        sr->bytes_to_send -= nbytes;
    }

    sr->loop++;
    return sr->bytes_to_send;    
}

int mk_http_directory_redirect_check(struct client_request *cr,
                                     struct request *sr)
{
    char *host;
    char *location = 0;
    char *real_location = 0;
    unsigned long len;

    /* 
     * We have to check if exist an slash to the end of
     * this string, if doesn't exist we send a redirection header
     */
    if (sr->uri_processed[strlen(sr->uri_processed) - 1] == '/') {
        return 0;
    }

    host = mk_pointer_to_buf(sr->host);

    mk_string_build(&location, &len, "%s/", sr->uri_processed);
    if (config->serverport == config->standard_port) {
        mk_string_build(&real_location, &len, "http://%s%s", host, location);
    }
    else {
        mk_string_build(&real_location, &len, "http://%s:%i%s",
                        host, config->serverport, location);
    }

#ifdef TRACE
    MK_TRACE("Redirecting to '%s'", real_location);
#endif

    mk_mem_free(host);

    sr->headers->status = M_REDIR_MOVED;
    sr->headers->content_length = 0;
    
    mk_pointer_reset(&sr->headers->content_type);
    sr->headers->location = real_location;
    sr->headers->cgi = SH_NOCGI;
    sr->headers->pconnections_left =
        (config->max_keep_alive_request - cr->counter_connections);

    mk_header_send(cr->socket, cr, sr, sr->log);
    mk_socket_set_cork_flag(cr->socket, TCP_CORK_OFF);

    /* 
     *  we do not free() real_location 
     *  as it's freed by iov 
     */
    mk_mem_free(location);
    sr->headers->location = NULL;
    return -1;
}

/* 
 * Check if a connection can continue open using as criteria
 * the keepalive headers vars and Monkey configuration
 */
int mk_http_keepalive_check(int socket, struct client_request *cr)
{
    if (!cr->request) {
        return -1;
    }

    if (config->keep_alive == VAR_OFF || cr->request->keep_alive == VAR_OFF) {
        return -1;
    }

    if (cr->counter_connections >= config->max_keep_alive_request) {
        return -1;
    }

    return 0;
}

int mk_http_range_set(struct request *sr, long file_size)
{
    struct header_values *sh = sr->headers;

    sr->bytes_to_send = file_size;
    sr->bytes_offset = 0;

    if (config->resume == VAR_ON && sr->range.data) {
        /* yyy- */
        if (sh->ranges[0] >= 0 && sh->ranges[1] == -1) {
            sr->bytes_offset = sh->ranges[0];
            sr->bytes_to_send = file_size - sr->bytes_offset;
        }

        /* yyy-xxx */
        if (sh->ranges[0] >= 0 && sh->ranges[1] >= 0) {
            sr->bytes_offset = sh->ranges[0];
            sr->bytes_to_send = labs(sh->ranges[1] - sh->ranges[0]) + 1;
        }

        /* -xxx */
        if (sh->ranges[0] == -1 && sh->ranges[1] > 0) {
            sr->bytes_to_send = sh->ranges[1];
            sr->bytes_offset = file_size - sh->ranges[1];
        }

        if (sr->bytes_offset > file_size || sr->bytes_to_send > file_size) {
            return -1;
        }

        lseek(sr->fd_file, sr->bytes_offset, SEEK_SET);
    }
    return 0;


}

int mk_http_range_parse(struct request *sr)
{
    int eq_pos, sep_pos, len;
    char *buffer = 0;

    if (!sr->range.data)
        return -1;

    if ((eq_pos = mk_string_search_n(sr->range.data, "=", sr->range.len)) < 0)
        return -1;

    if (strncasecmp(sr->range.data, "Bytes", eq_pos) != 0)
        return -1;

    if ((sep_pos = mk_string_search_n(sr->range.data, "-",
                                      sr->range.len)) < 0)
        return -1;

    len = sr->range.len;

    /* =-xxx */
    if (eq_pos + 1 == sep_pos) {
        sr->headers->ranges[0] = -1;
        sr->headers->ranges[1] =
            (unsigned long) atol(sr->range.data + sep_pos + 1);

        if (sr->headers->ranges[1] <= 0) {
            return -1;
        }

        return 0;
    }

    /* =yyy-xxx */
    if ((eq_pos + 1 != sep_pos) && (len > sep_pos + 1)) {
        buffer = mk_string_copy_substr(sr->range.data, eq_pos + 1, sep_pos);
        sr->headers->ranges[0] = (unsigned long) atol(buffer);
        mk_mem_free(buffer);

        buffer = mk_string_copy_substr(sr->range.data, sep_pos + 1, len);
        sr->headers->ranges[1] = (unsigned long) atol(buffer);
        mk_mem_free(buffer);

        if (sr->headers->ranges[1] <= 0 ||
            sr->headers->ranges[0] > sr->headers->ranges[1]) {
            return -1;
        }
        return 0;
    }
    /* =yyy- */
    if ((eq_pos + 1 != sep_pos) && (len == sep_pos + 1)) {
        buffer = mk_string_copy_substr(sr->range.data, eq_pos + 1, len);
        sr->headers->ranges[0] = (unsigned long) atol(buffer);
        mk_mem_free(buffer);
        return 0;
    }

    return -1;
}

/* 
 * Check if client request still has pending data 
 * 
 * Return 0 when all expected data has arrived or -1 when
 * the connection is on a pending status due to HTTP spec 
 *
 * This function is called from request.c :: mk_handler_read(..)
 */
int mk_http_pending_request(struct client_request *cr)
{
    int n;
    char *end;

    if (cr->body_length >= mk_endblock.len) {
        end = (cr->body + cr->body_length) - mk_endblock.len;
    }
    else {
        return -1;
    }

    /* try to match CRLF at the end of the request */
    if (cr->body_pos_end < 0) { 
        if (strncmp(end, mk_endblock.data, mk_endblock.len) == 0) {
            cr->body_pos_end = cr->body_length - mk_endblock.len;
        }
        else if ((n = mk_string_search(cr->body, mk_endblock.data)) >= 0 ){

            cr->body_pos_end = n;
        }
        else {
            return -1;
        }
    }

    if (cr->first_method == HTTP_METHOD_UNKNOWN) {
        cr->first_method = mk_http_method_get(cr->body);
    }

    if (cr->first_method == HTTP_METHOD_POST) {
        if (cr->body_pos_end > 0) {
            /* if first block has ended, we need to verify if exists 
             * a previous block end, that will means that the POST 
             * method has sent the whole information. 
             * just for ref: pipelining is not allowed with POST
             */
            if (cr->body_pos_end == cr->body_length - mk_endblock.len) {
                /* Content-length is required, if is it not found, 
                 * we pass as successfull in order to raise the error
                 * later
                 */
                if (mk_method_post_content_length(cr->body) < 0) {
                    cr->status = MK_REQUEST_STATUS_COMPLETED;
                    return 0;
                }
            }
            else {
                cr->status = MK_REQUEST_STATUS_COMPLETED;
                return 0;
            }
        }
        else {
            return -1;
        }
    }

    cr->status = MK_REQUEST_STATUS_COMPLETED;
    return 0;
}

mk_pointer *mk_http_status_get(short int code)
{
    mk_list_sint_t *l;

    l = mk_http_status_list;
    while (l) {
        if (l->index == code) {
            return &l->value;
        }
        else {
            l = l->next;
        }
    }

    return NULL;
}

void mk_http_status_add(short int val[2])
{
    short i, len = 6;
    char *str_val;
    mk_list_sint_t *list, *new;

    for (i = val[0]; i <= val[1]; i++) {

        new = mk_mem_malloc(sizeof(mk_list_sint_t));
        new->index = i;
        new->next = NULL;

        str_val = mk_mem_malloc(6);
        snprintf(str_val, len - 1, "%i", i);

        new->value.data = str_val;
        new->value.len = 3;

        if (!mk_http_status_list) {
            mk_http_status_list = new;
        }
        else {
            list = mk_http_status_list;
            while (list->next)
                list = list->next;

            list->next = new;
            list = new;
        }
    }
}

void mk_http_status_list_init()
{
    /* Status type */
    short int success[2] = { 200, 206 };
    short int redirections[2] = { 300, 305 };
    short int client_errors[2] = { 400, 415 };
    short int server_errors[2] = { 500, 505 };

    mk_http_status_add(success);
    mk_http_status_add(redirections);
    mk_http_status_add(client_errors);
    mk_http_status_add(server_errors);
}

int mk_http_request_end(int socket)
{
    int ka;
    struct client_request *cr;
    struct sched_list_node *sched;

    sched = mk_sched_get_thread_conf();
    cr = mk_request_client_get(socket);
    
    if (!cr) {
        return -1;
    }

    if (!sched) {
#ifdef TRACE
        MK_TRACE("Could not find sched list node :/");
#endif
        return -1;
    }

    /* We need to ask to http_keepalive if this 
     * connection can continue working or we must 
     * close it.
     */
    ka = mk_http_keepalive_check(socket, cr);
    mk_request_free_list(cr);

    if (ka < 0) {
        mk_request_client_remove(socket);
    }
    else {
        mk_request_ka_next(cr);
        mk_epoll_change_mode(sched->epoll_fd,
                             socket, MK_EPOLL_READ);
        return 0;
    }

    return -1;
}
