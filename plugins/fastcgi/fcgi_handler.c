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

#include <monkey/mk_api.h>

#include "fcgi_handler.h"

/* FIXME, static server info for now */
#define FASTCGI_HOST    "127.0.0.1"
#define FASTCGI_PORT    8000

#define FCGI_PARAM_DYN(str)   str, strlen(str)
#define FCGI_PARAM_CONST(str) str, sizeof(str) -1
#define FCGI_PARAM_PTR(ptr)   ptr.data, ptr.len
#define FCGI_PARAM_DUP(str)   strdup(str), strlen(str)
#define FCGI_PARAM_INET_ADDR(sock)  "", 0
#define FCGI_PARAM_NUM(n)     "", 0
#define FCGI_PARAM_BUF(h)     h->buf_data + h->buf_len

static inline size_t fcgi_write_length(char *p, size_t len)
{
	if (len > 127) {
		p[0]  = 1 << 7;
		p[0] += (len >> 24) & 0x7f;
		p[1]  = (len >> 16) & 0xff;
		p[2]  = (len >>  8) & 0xff;
		p[3]  = (len)       & 0xff;

		return 4;
	} else {
		p[0] = len & 0x7f;

		return 1;
	}
}

static inline int fcgi_add_param(struct fcgi_handler *handler,
                                 char *key, int key_len, char *val, int val_len)
{
    char *init;

    init = handler->buf_data + handler->buf_len;
    handler->buf_len += fcgi_write_length(FCGI_PARAM_BUF(handler), key_len);
    handler->buf_len += fcgi_write_length(FCGI_PARAM_BUF(handler), val_len);

    mk_api->iov_add(handler->iov, init,
                    FCGI_PARAM_BUF(handler) - init, MK_FALSE);
    mk_api->iov_add(handler->iov, key, key_len, MK_FALSE);
    mk_api->iov_add(handler->iov, val, val_len, MK_FALSE);

    return 0;
}

static inline int fcgi_add_param_net(struct fcgi_handler *handler, int sock)
{
    int ret;
    char *p;
    char buffer[256];
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);

    ret = getsockname(handler->cs->socket, (struct sockaddr *)&addr, &addr_len);
    if (ret == -1) {
        perror("getsockname");
        return -1;
    }

    p = inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer));
    if (!p) {
        perror("inet_ntop");
        return -1;
    }

    /* Server Address */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SERVER_ADDR"),
                   FCGI_PARAM_DUP(buffer));

    /* Server Port */
    snprintf(buffer, 256, "%d", ntohs(addr.sin_port));
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SERVER_PORT"),
                   FCGI_PARAM_DUP(buffer));


    ret = getpeername(handler->cs->socket, (struct sockaddr *)&addr, &addr_len);
    if (ret == -1) {
        perror("getpeername");
        return -1;
    }

    p = inet_ntop(AF_INET, &addr.sin_addr, buffer, sizeof(buffer));
    if (!p) {
        perror("inet_ntop");
        return -1;
    }

    /* Remote Addr */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("REMOTE_ADDR"),
                   FCGI_PARAM_DUP(buffer));

    /* Remote Port */
    snprintf(buffer, 256, "%d", ntohs(addr.sin_port));
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("REMOTE_PORT"),
                   FCGI_PARAM_DUP(buffer));

    return 0;
}

static int fcgi_encode_header(struct fcgi_record_header *rec,
                              uint8_t type, uint16_t request_id,
                              uint16_t content_length)
{
    rec->version        = FCGI_VERSION_1;
    rec->type           = type;
    fcgi_encode16(&rec->request_id, request_id);
    fcgi_encode16(&rec->content_length, content_length);
    rec->padding_length = 0;
    rec->reserved       = 0;

    return 0;
}

static int fcgi_encode_request(struct fcgi_handler *handler)
{
    int entries;
    struct fcgi_record_header *header;
    struct fcgi_begin_request_body *body;

    /* Allocate enough space for our data */
    entries =  40 + (handler->cs->parser.header_count * 3);
    handler->iov = mk_api->iov_create(entries, 0);

    header = (struct fcgi_record_header *) &handler->fcgi_begin_record;
    fcgi_encode_header(header, FCGI_BEGIN_REQUEST, 1,
                       FCGI_RECORD_HEADER_SIZE +
                       FCGI_BEGIN_REQUEST_BODY_SIZE);

    body   = (struct fcgi_begin_request_body *) (&header + FCGI_RECORD_HEADER_SIZE);
    fcgi_encode16(&body->role, FCGI_RESPONDER);
    body->flags = 1;

    //memset(&body->reserved, '\0', sizeof(body->reserved));

    /* BEGIN_REQUEST */
    mk_api->iov_add(handler->iov,
                    &handler->fcgi_begin_record,
                    FCGI_RECORD_HEADER_SIZE +
                    FCGI_BEGIN_REQUEST_BODY_SIZE,
                    MK_FALSE);

    return 0;

    /* Push record for Params
    mk_api->iov_add(handler->iov,
                    &handler->fcgi_rec_header,
                    sizeof(struct fcgi_record_header), MK_FALSE);
    */

    //FCGI_RECORD_HEADER_SIZE, MK_FALSE);

    /* Server Software */
    //fcgi_add_param(handler,
    //               FCGI_PARAM_CONST("SERVER_SOFTWARE"),
    //               FCGI_PARAM_DYN(mk_api->config->server_signature));

    /* Server Name */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SERVER_NAME"),
                   handler->sr->host_alias->name,
                   handler->sr->host_alias->len);

    /* Document Root */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("DOCUMENT_ROOT"),
                   FCGI_PARAM_PTR(handler->sr->host_conf->documentroot));

    /* Network params: SERVER_ADDR, SERVER_PORT, REMOTE_ADDR & REMOTE_PORT */
    //fcgi_add_param_net(handler, handler->cs->socket);

    /* Script Filename */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SCRIPT_FILENAME"),
                   FCGI_PARAM_PTR(handler->sr->real_path));

    /* Script Filename */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("SCRIPT_NAME"),
                   FCGI_PARAM_PTR(handler->sr->uri_processed));

    /* Request Method */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("REQUEST_METHOD"),
                   FCGI_PARAM_PTR(handler->sr->method_p));


    /* Request URI */
    //    fcgi_add_param(handler,
    //               FCGI_PARAM_CONST("REQUEST_URI"),
    //               FCGI_PARAM_PTR(handler->sr->uri));

    /* Query String */
    fcgi_add_param(handler,
                   FCGI_PARAM_CONST("QUERY_STRING"),
                   FCGI_PARAM_PTR(handler->sr->uri));

    /* FIXME: IF SSL, SET HTTPS=on */

    /* Complete our header, we already know the data length */
    /*
    header = &handler->fcgi_rec_header;
    fcgi_encode_header(header, FCGI_PARAMS, 1,
                       handler->iov->total_len);
*/
    return 0;
}

/* Callback: on connect to the backend server */
int cb_fastcgi_on_connect(void *data)
{
    int ret;
    int s_err;
    socklen_t s_len = sizeof(s_err);
    struct fcgi_handler *handler = data;

    /* We connect in async mode, we need to check if the connection was OK */
    ret = getsockopt(handler->server_fd, SOL_SOCKET, SO_ERROR, &s_err, &s_len);
    if (ret == -1) {
        goto error;
    }

    if (s_err) {
        /* FastCGI server unavailable */
        goto error;
    }

    /*ret = write(handler->server_fd,
                "\x01\x01\x00\x01" "\x00\x08\x00\x00" "\x00\x01\x00\x00" "\x00\x00\x00\x00",
                16);
    printf("wrote: %i bytes\n", ret);
*/
    /* Take the incoming HTTP request data and encode it on FastCGI */
    ret = fcgi_encode_request(handler);
    if (ret == -1) {
        goto error;
    }

    //printf("IOV TOTA: %lu bytes\n", handler->iov->total_len);
    ret = mk_api->iov_send(handler->server_fd, handler->iov);
    printf("IOV SENT: %i bytes\n", ret);
    sleep(3);
    int n;
    char bu[2056];
    int times = 0;
    while (1) {
        usleep((unsigned int) 0.5000);
        n = read(handler->server_fd, bu, sizeof(bu) -1);
        if (n == -1) {
            perror("read");
        }

        printf("got :%i\n", n);
        usleep((unsigned int) 0.5000);
        if (times > 100) {
            exit(1);
        }
        times++;
    }

    //exit(0);
 error:
    return -1;
}

struct fcgi_handler *fcgi_handler_new(struct mk_http_session *cs,
                                      struct mk_http_request *sr)
{
    int ret;
    struct fcgi_handler *h;

    /* Allocate handler instance and set fields */
    h = mk_api->mem_alloc_z(sizeof(struct fcgi_handler));
    if (!h) {
        return NULL;
    }
    h->cs = cs;
    h->sr = sr;

    /* Params buffer set an offset to include the header */
    h->buf_len = FCGI_RECORD_HEADER_SIZE;

    /* Request and async connection to the server */
    h->server_fd = mk_api->socket_connect(FASTCGI_HOST, FASTCGI_PORT, MK_TRUE);
    if (h->server_fd == -1) {
        mk_api->mem_free(h);
        return NULL;
    }

    /* Prepare the built-in event structure */
    MK_EVENT_INIT(&h->event, h->server_fd, h, cb_fastcgi_on_connect);

    /*
     * Let the event loop notify us when we can flush data to
     * the FastCGI server.
     */
    ret = mk_api->ev_add(mk_sched_loop(),
                         h->server_fd,
                         MK_EVENT_CUSTOM, MK_EVENT_WRITE, h);
    if (ret == -1) {
        close(h->server_fd);
        mk_api->mem_free(h);
        return NULL;
    }

    return h;
}
