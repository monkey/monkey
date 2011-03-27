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
#include <sys/stat.h>
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
    char *conf_path;
    struct mk_palm *new, *r;
    struct mk_config_section *section;

    /* Read palm configuration file */
    mk_api->str_build(&conf_path, &len, "%s/palm.conf", confdir);
    conf = mk_api->config_create(conf_path);
    section = conf->section;

    r = palms;
    while (section) {
        /* Just read PALM sections */
        if (strcasecmp(section->name, "PALM") != 0) {
            section = section->next;
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
        section = section->next;
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

int mk_palm_send_headers(struct client_session *cs, struct session_request *sr)
{
    int n;

    if (sr->headers->status == 0) {
        sr->headers->status = MK_HTTP_OK;
    }

    sr->headers->cgi = SH_CGI;

    /* Chunked transfer encoding */
    if (sr->protocol >= HTTP_PROTOCOL_11) {
        sr->headers->transfer_encoding = MK_HEADER_TE_TYPE_CHUNKED;
    }

    /* Send just headers from buffer */
    PLUGIN_TRACE("[CLIENT_FD %i] Sending headers", cs->socket);

    n = (int) mk_api->header_send(cs->socket, cs, sr);

    /* Monkey core send_headers set TCP_CORK_ON, we need to get
     * back the status to OFF
     */
    mk_api->socket_cork_flag(cs->socket, TCP_CORK_OFF);

    PLUGIN_TRACE("[CLIENT_FD %i] Send headers returned %i", cs->socket, n);
    return n;
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

    /* set pointers */
    mk_api->pointer_set(&mk_monkey_protocol, HTTP_PROTOCOL_11_STR);
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

int _mkp_stage_30(struct plugin *plugin, struct client_session *cs, 
                  struct session_request *sr)
{
    struct mk_palm *palm;
    struct mk_palm_request *pr;

    PLUGIN_TRACE("PALM STAGE 30, requesting '%s'", sr->real_path.data);

    palm = mk_palm_get_handler(&sr->real_path);
    if (!palm || !sr->file_info) {
        PLUGIN_TRACE("[FD %i] Not handled by me", cs->socket);
        return MK_PLUGIN_RET_NOT_ME;
    }

    /* Connect to server */
    pr = mk_palm_do_instance(palm, cs, sr);

    if (!pr) {
        PLUGIN_TRACE("return %i (MK_PLUGIN_RET_CLOSE_CONX)", MK_PLUGIN_RET_CLOSE_CONX);
        return MK_PLUGIN_RET_CLOSE_CONX;
    }

    /* Register Palm instance */
    mk_palm_request_add(pr);

    /* Register socket with thread Epoll interface */
    mk_api->event_add(pr->palm_fd, MK_EPOLL_READ, plugin, cs, sr);
    PLUGIN_TRACE("Palm: Event registered for palm_socket=%i", pr->palm_fd);

    /* Send request */
    mk_palm_send_request(cs, sr);

    PLUGIN_TRACE("[PALM_FD %i] return %i (MK_PLUGIN_RET_CONTINUE)", 
                 pr->palm_fd, MK_PLUGIN_RET_CONTINUE);
    return MK_PLUGIN_RET_CONTINUE;
}


struct mk_palm_request *mk_palm_do_instance(struct mk_palm *palm,
                                            struct client_session *cs,
                                            struct session_request *sr)
{
    int ret;
    int palm_socket;

    /* Connecting to Palm Server */
    palm_socket = mk_api->socket_create();
    ret = mk_api->socket_connect(palm_socket,
                                       palm->server_addr,
                                       palm->server_port);

    if (ret < 0) {
        mk_warn("Palm: Could not connect to %s:%i", palm->server_addr, palm->server_port);
        mk_api->header_set_http_status(sr, MK_SERVER_INTERNAL_ERROR);
        return NULL;
    }

    /* Return instance */
    return mk_palm_request_create(cs->socket, palm_socket, cs, sr, palm);
}

void mk_palm_send_request(struct client_session *cs, struct session_request *sr)
{
    int n;
    ssize_t bytes_iov=-1;
    struct mk_iov *iov;
    struct mk_palm_request *pr;

    PLUGIN_TRACE("Sending request to Palm Server");

    pr = mk_palm_request_get_by_http(cs->socket);
    if (pr) {
        if (pr->bytes_sent == 0) {
            PLUGIN_TRACE("Palm request: '%s'", sr->real_path.data);

            /* Palm environment vars */
            iov = mk_palm_protocol_request_new(cs, sr);

            /* Write request to palm server */
            bytes_iov = (ssize_t )mk_api->iov_send(pr->palm_fd, iov);

            if (bytes_iov >= 0){
                pr->bytes_sent += bytes_iov;
                n = (long) bytes_iov;
            }
        }
    }

    PLUGIN_TRACE("Bytes sent to PALM SERVER: %i", pr->bytes_sent);
}

int mk_palm_send_chunk(int socket, char *buffer, int len)
{
    int n;
    char *chunk_size=0;
    unsigned long chunk_len=0;

    mk_api->socket_cork_flag(socket, TCP_CORK_ON);
    mk_api->str_build(&chunk_size, &chunk_len, "%x%s", len, MK_CRLF);
    n = mk_api->socket_send(socket, chunk_size, chunk_len);
    mk_api->mem_free(chunk_size);

    if (n < 0) {
        PLUGIN_TRACE("Error sending chunked header, socket_send() returned %i", n);
        perror("socket_send");
        return -1;
    }

    n = mk_api->socket_send(socket, buffer, len);

    PLUGIN_TRACE("SEND CHUNK: requested %i, sent %i", len, n);

    if (n < 0) {
        PLUGIN_TRACE("Error sending chunked body, socket_send() returned %i", n);
        perror("socket_send");
        return -1;
    }

    mk_api->socket_send(socket, MK_CRLF, 2);
    mk_api->socket_cork_flag(socket, TCP_CORK_OFF);
    return n;
}

int mk_palm_send_end_chunk(int socket)
{
    int n;

    n = mk_api->socket_send(socket, "0\r\n\r\n", 5);
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

        sr->headers->status = status;
        return offset;
    }
    
    return 0;
}
int _mkp_event_read(int sockfd)
{
    int n;
    int headers_end = -1;
    int offset;
    int read_offset = 0;
    struct mk_palm_request *pr;

    pr = mk_palm_request_get(sockfd);

    if (!pr){
        PLUGIN_TRACE("[FD %i] this FD is not a Palm Request", sockfd);
        return MK_PLUGIN_RET_EVENT_NEXT;
    }
    
    /* Read incoming data from Palm socket */
    n = mk_api->socket_read(pr->palm_fd, pr->buffer + pr->buffer_len,
                            (MK_PALM_BUFFER_SIZE - pr->buffer_len));

#ifdef TRACE
    PLUGIN_TRACE("[FD %i | CLIENT_FD %i | PALM_FD %i]", sockfd, pr->client_fd, pr->palm_fd);
    PLUGIN_TRACE(" just readed  : %i", n);
    if (pr->headers_sent == VAR_ON) {
        PLUGIN_TRACE(" headers sent : YES", pr->headers_sent);
    }
    else {
        PLUGIN_TRACE(" headers sent : NO");
    }
#endif

    if (n <= 0) {
        PLUGIN_TRACE(" ending connection: read() = %i", n);

        if (pr->sr->protocol >= HTTP_PROTOCOL_11) {
            n = mk_palm_send_end_chunk(pr->client_fd);
        }

        return MK_PLUGIN_RET_EVENT_CLOSE;
    }

    /* Increase buffer data length counter */
    pr->buffer_len += n;

    /* If response headers + PHP headers has NOT been sent back to client... */
    if (pr->headers_sent == MK_FALSE) {
        PLUGIN_TRACE("No headers sent, searching CRLFCRLF...");

        headers_end = mk_api->str_search(pr->buffer,
                                         MK_IOV_CRLFCRLF, MK_STR_SENSITIVE);
        
        if (headers_end <= 0)  {
            headers_end = mk_api->str_search(pr->buffer,
                                             MK_IOV_LFLFLFLF, MK_STR_SENSITIVE);
        }

        if (headers_end <= 0) {
            PLUGIN_TRACE("No headers found, returning until next loop");
            return MK_PLUGIN_RET_EVENT_OWNED;
        }

        PLUGIN_TRACE("Palm header ends in buffer pos %i", headers_end);

        if (headers_end > 0) {
            headers_end += 4;
        }
        
        /* Check if some 'Status:' field was sent in the first line */
        offset = mk_palm_cgi_status(pr->buffer, pr->sr);
        
        /* Send headers */
        mk_palm_send_headers(pr->cs, pr->sr);
        n = mk_api->socket_send(pr->client_fd, 
                                pr->buffer + offset, 
                                headers_end - offset);
        
        PLUGIN_TRACE("[CLIENT_FD %i] Headers sent to HTTP client: %i", pr->client_fd, n);

        if (n < 0) {
            return MK_PLUGIN_RET_EVENT_CLOSE;
        }
        
        /* Enable headers flag */
        pr->headers_sent = MK_TRUE;
        pr->buffer_offset = n + offset;
        read_offset = headers_end;
    }

    /* Send to client the palm data buffer in pending status */
    while (pr->buffer_offset < pr->buffer_len) {
            if (pr->sr->protocol >= HTTP_PROTOCOL_11) {
                n = mk_palm_send_chunk(pr->client_fd,
                                       pr->buffer + pr->buffer_offset,
                                       (unsigned int)(pr->buffer_len - pr->buffer_offset));
            }
            else {
                n = mk_api->socket_send(pr->client_fd,
                                        pr->buffer + pr->buffer_offset,
                                        (unsigned int) (pr->buffer_len - pr->buffer_offset));
            }
            
            if (n <= 0) {
                PLUGIN_TRACE("[CLIENT_FD %i] WRITE ERROR", pr->client_fd);
                return MK_PLUGIN_RET_EVENT_CLOSE;
            }

            PLUGIN_TRACE("[CLIENT_FD %i] Bytes sent: %i", pr->client_fd, n);
            pr->buffer_offset += n;
    }
    
    pr->buffer_offset = 0;
    pr->buffer_len = 0;

    /* Update thread node info */
    mk_palm_request_update(sockfd, pr);

    return MK_PLUGIN_RET_EVENT_OWNED;
}

/* sockfd = palm_fd */
int hangup(int sockfd)
{
    struct mk_palm_request *pr;

    PLUGIN_TRACE("[FD %i] hangup", sockfd);

    pr = mk_palm_request_get(sockfd)     ;
    if (!pr) {
        PLUGIN_TRACE("[FD %i] this FD is not a Palm Request", sockfd);

        pr = mk_palm_request_get_by_http(sockfd);
        if (pr) {
            PLUGIN_TRACE("[FD %i] but the client is associated to FD %i",
                         sockfd, pr->palm_fd);
            mk_api->socket_close(pr->palm_fd);
            mk_palm_request_delete(pr->palm_fd);
        }

        return MK_PLUGIN_RET_EVENT_CONTINUE;
    }

    PLUGIN_TRACE(" cleaning up palm node | request_end(%i)", pr->client_fd);

    mk_api->event_del(pr->palm_fd);
    mk_api->http_request_end(pr->client_fd);
    mk_api->socket_close(pr->palm_fd);
    mk_palm_request_delete(pr->palm_fd);
    
    return MK_PLUGIN_RET_EVENT_CONTINUE;
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

