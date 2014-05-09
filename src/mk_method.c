/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "monkey.h"

#include "mk_string.h"
#include "mk_memory.h"
#include "mk_http.h"
#include "mk_http_status.h"
#include "mk_socket.h"
#include "mk_config.h"
#include "mk_utils.h"
#include "mk_file.h"
#include "mk_cache.h"
#include "mk_request.h"

long int mk_method_validate_content_length(const char *body, int body_len)
{
    int crlf;
    struct headers_toc toc;
    long int len;
    mk_ptr_t tmp;

    crlf = mk_string_search(body, MK_CRLF, MK_STR_INSENSITIVE);
    if (crlf < 0) {
        return -1;
    }

    /*
     * obs: Table of Content (toc) is created when the full
     * request has arrived, this function cannot be used from
     * mk_http_pending_request().
     */
    if (mk_request_header_toc_parse(&toc, body + crlf + mk_crlf.len,
                                    body_len - mk_crlf.len - crlf) < 0) {
        return -1;
    }
    tmp = mk_request_header_get(&toc,
                                mk_rh_content_length.data,
                                mk_rh_content_length.len);

    if (!tmp.data) {
        int pos_header;
        int pos_crlf;
        char *str_cl;

        /* Pre-parsing mode: Check if content-length was sent */
        pos_header = mk_string_search(body, RH_CONTENT_LENGTH, MK_STR_INSENSITIVE);
        if (pos_header <= 0) {
            return -1;
        }

        pos_crlf = mk_string_search(body + pos_header, MK_IOV_CRLF, MK_STR_SENSITIVE);
        if (pos_crlf <= 0) {
            return -1;
        }

        str_cl = mk_string_copy_substr(body + pos_header + mk_rh_content_length.len + 1,
                                       0, pos_header + pos_crlf);
        len = strtol(str_cl, (char **) NULL, 10);
        mk_mem_free(str_cl);

        return len;
    }

    len = strtol(tmp.data, (char **) NULL, 10);

    return len;
}

/* It parse data sent by POST or PUT methods */
int mk_method_parse_data(struct client_session *cs, struct session_request *sr)
{
    mk_ptr_t tmp;
    long content_length_post = 0;

    content_length_post = mk_method_validate_content_length(cs->body, cs->body_length);

    /* Length Required */
    if (content_length_post == -1) {
        mk_request_error(MK_CLIENT_LENGTH_REQUIRED, cs, sr);
        return -1;
    }

    /* Bad request */
    if (content_length_post <= 0) {
        mk_request_error(MK_CLIENT_BAD_REQUEST, cs, sr);
        return -1;
    }

    /* Content length too large */
    if (content_length_post >= cs->body_size) {
        mk_request_error(MK_CLIENT_REQUEST_ENTITY_TOO_LARGE, cs, sr);
        return -1;
    }

    /*
     * RFC2616: 7.2.1 Type:
     * --------------------
     * Note: according to the RFC we should not force the content-type.
     *
     * .....
     * Any HTTP/1.1 message containing an entity-body SHOULD include a
     * Content-Type header field defining the media type of that body. If
     * and only if the media type is not given by a Content-Type field, the
     * recipient MAY attempt to guess the media type via inspection of its
     * content and/or the name extension(s) of the URI used to identify the
     * resource. If the media type remains unknown, the recipient SHOULD
     * treat it as type "application/octet-stream".
     */
    tmp = mk_request_header_get(&sr->headers_toc,
                                mk_rh_content_type.data,
                                mk_rh_content_type.len);
    if (tmp.data) {
        sr->content_type = tmp;
    }

    /* Set the content-length */
    sr->content_length = content_length_post;
    return 0;
}

/* Return POST variables sent in request */
mk_ptr_t mk_method_get_data(void *data, int size)
{
    mk_ptr_t p;

    p.data = data;
    p.len = size;

    return p;
}
