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
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "MKPlugin.h"

#include "cgi.h"
#include "palm.h"
#include "request.h"
#include "protocol.h"

MONKEY_PLUGIN("palm",              /* shortname */
              "Palm Client",       /* name */
              VERSION,            /* version */
              MK_PLUGIN_CORE_THCTX | MK_PLUGIN_STAGE_30); /* hooks */

/* Read database configuration parameters */
int mk_palm_conf(char *confdir)
{
    int ret = 0;
    unsigned long len;
    char *conf_path = NULL;
    struct mk_palm *new, *r;
    struct mk_config_section *section;
    struct mk_list *head;

    /* Read palm configuration file */
    mk_api->str_build(&conf_path, &len, "%s/palm.conf", confdir);
    conf = mk_api->config_create(conf_path);

    mk_list_foreach(head, &conf->sections) {
        section = mk_list_entry(head, struct mk_config_section, _head);
        /* Just read PALM sections */
        if (strcasecmp(section->name, "PALM") != 0) {
            continue;
        }

        /* Alloc node */
        new = mk_api->mem_alloc(sizeof(struct mk_palm));

        /* Palm file extensions */
        new->extension = mk_api->config_section_getval(section, "Extension",
                                                       MK_CONFIG_VAL_STR);
        /* Palm mime type */
        new->mimetype = mk_api->config_section_getval(section, "Mimetype",
                                                      MK_CONFIG_VAL_STR);
        /* Palm server address */
        new->server_addr = mk_api->config_section_getval(section, "ServerAddr",
                                                         MK_CONFIG_VAL_STR);
        /* Palm server TCP port */
        new->server_port = (size_t) mk_api->config_section_getval(section, "ServerPort",
                                                                  MK_CONFIG_VAL_NUM);

        PLUGIN_TRACE("RegPalm '%s|%s|%s|%i'", new->extension, new->mimetype,
                     new->server_addr, new->server_port);
        new->next = NULL;

        /* Linking node */
        if (!palms) {
            palms = new;
        }
        else {
            r = palms;
            while (r->next) {
                r = r->next;
            }
            r->next = new;
        }
    }

    mk_api->mem_free(conf_path);
    return ret;
}

struct mk_palm *mk_palm_get_handler(mk_pointer * file)
{
    struct mk_palm *p;
    int j, len, extlen;

    j = len = file->len;

    /* looking for extension */
    while (file->data[j] != '.' && j >= 0) {
        j--;
    }

    extlen = file->len - j - 1;
    if (j == 0) {
        return NULL;
    }

    p = palms;
    while (p) {
        if (strncasecmp(file->data + j + 1, p->extension, extlen) == 0) {
            return p;
        }
        p = p->next;
    }

    return NULL;
}

int mk_palm_send_headers(struct mk_palm_request *pr)
{
    int n;
    struct client_session *cs = pr->cs;
    struct session_request *sr = pr->sr;

    if (sr->headers.status == 0) {
        sr->headers.status = MK_HTTP_OK;
    }

    sr->headers.cgi = SH_CGI;

    /*
     * Chunked transfer encoding: just on HTTP/1.1 and when there's no
     * redirection
     */
    if (sr->protocol >= HTTP_PROTOCOL_11 &&
        (sr->headers.status < MK_REDIR_MULTIPLE ||
         sr->headers.status > MK_REDIR_USE_PROXY))
        {
            sr->headers.transfer_encoding = MK_HEADER_TE_TYPE_CHUNKED;
            pr->is_te_chunked = MK_TRUE;
        }

    /* Send just headers from buffer */
    PLUGIN_TRACE("[CLIENT_FD %i] Sending headers", cs->socket);

    n = (int) mk_api->header_send(cs->socket, cs, sr);

    /*
     * Monkey core send_headers set TCP_CORK_ON, we need to get
     * back the status to OFF
     */
    mk_api->socket_cork_flag(cs->socket, TCP_CORK_OFF);

    PLUGIN_TRACE("[CLIENT_FD %i] Send headers returned %i", cs->socket, n);
    return n;
}

void _mkp_core_prctx(struct server_config *config)
{
    /*
     * Server Address Lookup
     * ---------------------
     *
     * this variable specify the server IP address ,this lookup needs to be
     * performed in the process context hook as is at this point where the
     * server socket is already binded. We do not trust in the Listen configuration
     * key so we do our own lookup.
     */
    int len;
	struct sockaddr_in sin;
	struct in_addr in;

	len = sizeof(sin);
	if (getsockname(mk_api->config->server_fd,
                    (struct sockaddr *)&sin, (socklen_t *)&len) == -1) {
        mk_err("Palm: Could not determinate local address");
        exit(EXIT_FAILURE);
    }
	memset(&in,0,sizeof(in));
	in.s_addr = sin.sin_addr.s_addr;

    mk_server_address.data = inet_ntoa(in);
    mk_server_address.len = strlen(mk_server_address.data);

    PLUGIN_TRACE("Server Address Lookup '%s'", mk_server_address.data);
}

void _mkp_core_thctx()
{
    /* Init request list */
    mk_palm_request_init();

    /* Init prototol template */
    mk_palm_protocol_thread_init();
}

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;
    palms = 0;

    /* init thread keys */
    pthread_key_create(&iov_protocol_request, NULL);
    pthread_key_create(&iov_protocol_request_idx, NULL);
    pthread_key_create(&cache_ip_str, NULL);

    /* set pointers */
    mk_api->pointer_set(&mk_server_protocol, HTTP_PROTOCOL_11_STR);

    /* server port */
    mk_server_port.data = mk_api->mem_alloc(6);
    mk_api->str_itop(mk_api->config->serverport, &mk_server_port);
    mk_server_port.len -= 2;

    /* iov separators */
    mk_api->pointer_set(&mk_iov_empty, MK_IOV_NONE);
    mk_api->pointer_set(&mk_iov_crlf, MK_IOV_CRLF);
    mk_api->pointer_set(&mk_iov_crlfcrlf, MK_IOV_CRLFCRLF);
    mk_api->pointer_set(&mk_iov_equal, MK_IOV_EQUAL);

    /* Read configuration */
    mk_palm_conf(confdir);

    /* Init CGI memory buffers */
    mk_cgi_env();

    return 0;
}

void _mkp_exit()
{
}

/*
 * Request handler: when the request arrives, this hook is invoked so Palm plugin
 * start it's job checking if it should handle or not this request
 */
int _mkp_stage_30(struct plugin *plugin, struct client_session *cs,
                  struct session_request *sr)
{
    struct mk_palm *palm;
    struct mk_palm_request *pr;

    /* Check if this connection already have a palm_request */
    pr = mk_palm_request_get_by_http(cs->socket);
    if (pr) {
        PLUGIN_TRACE("[FD %i] Palm request already exists, RET_CONTINUE", cs->socket);
        return MK_PLUGIN_RET_CONTINUE;
    }

    PLUGIN_TRACE("PALM STAGE 30, requesting '%s'", sr->real_path.data);

    /* Get Palm handler */
    palm = mk_palm_get_handler(&sr->real_path);
    if (!palm || sr->file_info.size == -1) {
        PLUGIN_TRACE("[FD %i] Not handled by me", cs->socket);
        return MK_PLUGIN_RET_NOT_ME;
    }

    /* Connect to Palm server */
    pr = mk_palm_connect(palm, cs, sr);
    if (!pr) {
        PLUGIN_TRACE("return %i (MK_PLUGIN_RET_CLOSE_CONX)", MK_PLUGIN_RET_CLOSE_CONX);
        return MK_PLUGIN_RET_CLOSE_CONX;
    }

    /* Register palm_request object with the thread list */
    mk_palm_request_add(pr);

    /*
     * Register socket with thread Epoll interface
     * -------------------------------------------
     * For each Monkey worker thread exists a epoll() loop used to handle
     * events on sockets, plugins can use the same epoll loop and register
     * events. Here we register the connected FD to palm server and wait for
     * such events.
     */
    mk_api->event_add(pr->palm_fd, MK_EPOLL_READ, plugin, cs, sr, MK_EPOLL_LEVEL_TRIGGERED);
    PLUGIN_TRACE("[PALM_FD %i] Socket registered in epoll events", pr->palm_fd);

    /* Send request to Palm server */
    mk_palm_send_request(cs, sr);

    PLUGIN_TRACE("[PALM_FD %i] return MK_PLUGIN_RET_CONTINUE (%i)",
                 pr->palm_fd, MK_PLUGIN_RET_CONTINUE);

    /*
     * We need to set the remote client socket event to READ, right now the socket
     * is in write mode and it will be joining this function every time until some
     * data is send.

    mk_api->event_socket_change_mode(cs->socket, MK_EPOLL_READ, MK_EPOLL_LEVEL_TRIGGERED);
    */
    return MK_PLUGIN_RET_CONTINUE;
}

/*
 * Establish a TCP connection to the Palm Server
 */
struct mk_palm_request *mk_palm_connect(struct mk_palm *palm,
                                        struct client_session *cs,
                                        struct session_request *sr)
{
    int palm_socket;

    /* Connecting to Palm Server */
    palm_socket = mk_api->socket_connect(palm->server_addr, palm->server_port);

    if (palm_socket < 0) {
        mk_warn("Palm: Could not connect to %s:%i", palm->server_addr, palm->server_port);
        mk_api->header_set_http_status(sr, MK_SERVER_INTERNAL_ERROR);
        return NULL;
    }

    /* Return instance */
    return mk_palm_request_create(cs->socket, palm_socket, cs, sr, palm);
}

int mk_palm_send_request(struct client_session *cs, struct session_request *sr)
{

    ssize_t bytes_iov=-1;
    struct mk_iov *iov;
    struct mk_palm_request *pr;

    pr = mk_palm_request_get_by_http(cs->socket);
    PLUGIN_TRACE("[FD %i] Sending request to Palm Server", pr->palm_fd);

    if (pr && pr->bytes_sent == 0) {
        PLUGIN_TRACE("Palm request: '%s'", sr->real_path.data);

        /* Create protocol request  */
        iov = mk_palm_protocol_request_new(cs, sr);

        /* Write protocol request to palm server */
        bytes_iov = (ssize_t ) mk_api->iov_send(pr->palm_fd, iov);
        PLUGIN_TRACE("[PALM_FD %i] written: %i", pr->palm_fd, bytes_iov);

        if (bytes_iov >= 0){
            pr->bytes_sent += bytes_iov;
        }
    }

    PLUGIN_TRACE("Bytes sent to PALM SERVER: %i", pr->bytes_sent);
    return pr->bytes_sent;
}

int mk_palm_write(int socket, char *buffer, int len, int is_chunked)
{
    int n;
    int chunk_len;
    int chunk_size = 16;
    char chunk_header[chunk_size];

    if  (len <=0){
        return 0;
    }


    mk_bug(len <= 0);

    if (is_chunked == MK_TRUE) {
        mk_api->socket_cork_flag(socket, TCP_CORK_ON);
        chunk_len = snprintf(chunk_header, chunk_size - 1, "%x%s", len, MK_CRLF);
        mk_api->socket_send(socket, chunk_header, chunk_len);
    }

    n = mk_api->socket_send(socket, buffer, len);

    if (is_chunked == MK_TRUE) {
        mk_api->socket_send(socket, MK_CRLF, 2);
        mk_api->socket_cork_flag(socket, TCP_CORK_OFF);
    }

    return n;
}

int mk_palm_send_end_chunk(int socket, struct mk_palm_request *pr)
{
    int n=0;

    if (pr->is_te_chunked == MK_TRUE) {
        n = mk_api->socket_send(socket, "0\r\n\r\n", 5);
    }
    return n;
}

/* Check if the CGI field 'Status: XYZ Some message' is
 * present, if so, it modifies the header struct response
 * and return the offset position
 */
int mk_palm_cgi_status(char *data, struct session_request *sr)
{
    int status;
    int status_len = 3;
    int offset = 0;
    int field_len = 8;
    char buffer[4];
    char field[] = "Status: ";

    if (strlen(data) <= (field_len + status_len)) {
        return 0;
    }

    if (strncmp(data, field, field_len) == 0) {
        /* Read HTTP status string */
        strncpy(buffer, data + field_len, status_len);
        buffer[3] = '\0';

        /* Convert string status to int */
        status = atoi(buffer);
        if (status == 0) {
            return 0;
        }

        /* Search breakline */
        offset = mk_api->str_search(data, MK_IOV_CRLF, MK_STR_SENSITIVE);
        if (offset > 0) {
            offset += 2;
        }
        else {
            offset = mk_api->str_search(data, MK_IOV_LF, MK_STR_SENSITIVE);
            if (offset > 0) {
                offset += 1;
            }
            else {
                return 0;
            }
        }

        sr->headers.status = status;
        return offset;
    }

    return 0;
}

/* sockfd = palm_fd */
int hangup(int sockfd)
{
    struct mk_palm_request *pr;

    PLUGIN_TRACE("[FD %i] hangup", sockfd);

    /* Detect who owns this FD, client or palm */
    pr = mk_palm_request_get(sockfd);
    if (pr) { /* palm */
        PLUGIN_TRACE(" cleaning up palm node | request_end (%i)", pr->client_fd);

        mk_api->event_del(pr->palm_fd);

        /*
         * We must be careful when invoking http_request_end(), as this
         * function can raise an event close and this same function
         * hangup() can be invoked before continue, in the second loop
         * can get into the client condition (else {..}) so the palm_request
         * object can not be longer valid.
         */
        mk_api->http_request_end(pr->client_fd);

        mk_api->socket_close(sockfd);
        mk_palm_request_delete(sockfd);
    }
    else { /* client */
        PLUGIN_TRACE("[FD %i] this FD is not a Palm Request", sockfd);

        /* Check if the FD belongs to the client */
        pr = mk_palm_request_get_by_http(sockfd);
        if (pr) {
            PLUGIN_TRACE("[FD %i] but the client is associated to FD %i",
                         sockfd, pr->palm_fd);
            mk_api->socket_close(pr->palm_fd);
            mk_palm_request_delete(pr->palm_fd);
        }
    }
    return MK_PLUGIN_RET_EVENT_CONTINUE;
}

/* _MKP_EVENTs */
int _mkp_event_write(int sockfd)
{
    int n;
    struct mk_palm_request *pr;

    pr = mk_palm_request_get_by_http(sockfd);
    if (!pr) {
        PLUGIN_TRACE("[FD %i] Not an involved Palm event", sockfd);
        return MK_PLUGIN_RET_EVENT_CONTINUE;
    }

    /*
     * Write when data exists and the plugin already processed the
     * response HTTP headers
     */
    PLUGIN_TRACE("pr->in_len: %i", pr->in_len);

    if (pr->in_len > 0 && pr->headers_sent == MK_TRUE) {
        n = mk_palm_write(sockfd, pr->in_buffer + pr->in_offset,
                          pr->in_len - pr->in_offset, pr->is_te_chunked);

        PLUGIN_TRACE("WRITTEN TO CLIENT: %i/%i", n, pr->in_len);

        if (n >= 0 && n < (pr->in_len - pr->in_offset)) {
            PLUGIN_TRACE("SAVING TO OUT_BUFFER!!!!!!!!!!!!!!!!");
            strncpy(pr->out_buffer, pr->in_buffer, pr->in_len - n);
            pr->out_len = pr->in_len - n;
        }
        pr->in_len = 0;
        pr->in_offset = 0;
    }

    PLUGIN_TRACE("EVENT WRITE!!!!!!!!!!!!!!!!!!!!");
    return MK_PLUGIN_RET_EVENT_OWNED;
}

/* _MKP_EVENTs */
int _mkp_event_read(int sockfd)
{
    int n;
    int headers_end = -1;
    int offset;
    struct mk_palm_request *pr;

    pr = mk_palm_request_get(sockfd);

    if (!pr){
        PLUGIN_TRACE("[FD %i] this FD is not a Palm Request", sockfd);
        return MK_PLUGIN_RET_EVENT_NEXT;
    }

    /* Read incoming data from Palm socket */
    n = mk_api->socket_read(pr->palm_fd, pr->in_buffer + pr->in_len,
                            (MK_PALM_BUFFER_SIZE - pr->in_len));

#ifdef TRACE
    PLUGIN_TRACE("[FD %i | CLIENT_FD %i | PALM_FD %i]", sockfd, pr->client_fd, pr->palm_fd);
    PLUGIN_TRACE(" just readed  : %i", n);
    if (pr->headers_sent == MK_TRUE) {
        PLUGIN_TRACE(" headers sent : YES");
    }
    else {
        PLUGIN_TRACE(" headers sent : NO");
    }
#endif

    if (n <= 0) {
        PLUGIN_TRACE(" ending connection: read() = %i", n);

        if (pr->sr->protocol >= HTTP_PROTOCOL_11) {
            mk_palm_send_end_chunk(pr->client_fd, pr);
        }

        return MK_PLUGIN_RET_EVENT_CLOSE;
    }

    /* Increase buffer data length counter */
    pr->in_len += n;

    /* If response headers + PHP headers has NOT been sent back to client... */
    if (pr->headers_sent == MK_FALSE) {
        PLUGIN_TRACE("No headers sent, searching CRLFCRLF...");

        headers_end = mk_api->str_search(pr->in_buffer,
                                         MK_IOV_CRLFCRLF, MK_STR_SENSITIVE);

        //mk_info("headers_end: %i", headers_end);

        if (headers_end <= 0)  {
            headers_end = mk_api->str_search(pr->in_buffer,
                                             MK_IOV_LFLFLFLF, MK_STR_SENSITIVE);
        }

        if (headers_end <= 0) {
            PLUGIN_TRACE("No headers found, returning until next loop");
            return MK_PLUGIN_RET_EVENT_OWNED;
        }

        PLUGIN_TRACE("Palm header ends in buffer pos %i", headers_end);

        /* Add bytes length for two break lines */
        headers_end += 4;

        /*
         * Check if some 'Status:' field was sent in the first line, update the
         * response HTTP status and return the offset of the content
         */
        offset = mk_palm_cgi_status(pr->in_buffer, pr->sr);

        /* Send HTTP response headers */
        mk_palm_send_headers(pr);

        /*
         * Send remaining Palm HTTP headers, we cannot send all in the same block
         * as the response body can need a chunked transfer encoding type for the
         * next reads from Palm server
         */
        n = mk_palm_write(pr->client_fd, pr->in_buffer + offset,
                          headers_end - offset, MK_FALSE);

        PLUGIN_TRACE("[CLIENT_FD %i] Headers sent to HTTP client: %i", pr->client_fd, n);

        if (n < 0) {
            return MK_PLUGIN_RET_EVENT_CLOSE;
        }

        /* Enable headers flag */
        pr->headers_sent = MK_TRUE;
        pr->in_offset = headers_end + offset;
        //mk_info("off: %i, len: %i", pr->in_offset, pr->in_len);
    }

    /* Update thread node info */
    mk_palm_request_update(sockfd, pr);

    return MK_PLUGIN_RET_EVENT_OWNED;
}

int _mkp_event_close(int sockfd)
{
    PLUGIN_TRACE("[FD %i] event close", sockfd);
    return hangup(sockfd);
}

int _mkp_event_error(int sockfd)
{
    PLUGIN_TRACE("[FD %i] event error", sockfd);
    return hangup(sockfd);
}
