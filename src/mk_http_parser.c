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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>

#include <monkey/mk_http_parser.h>

#define mark_end()                              \
    req->end = req->i;                          \
    req->chars = -1;

#define parse_next()                            \
    req->start = req->i + 1;                    \
    continue

#define field_len()   (req->end - req->start)
#define header_scope_eq(req, x) req->header_min = req->header_max = x

struct row_entry {
    int len;
    const char name[32];
};

struct row_entry mk_methods_table[] = {
    { 3, "GET"     },
    { 4, "POST"    },
    { 4, "HEAD"    },
    { 3, "PUT"     },
    { 6, "DELETE"  },
    { 7, "OPTIONS" }
};

struct row_entry mk_headers_table[] = {
    {  6, "Accept"              },
    { 14, "Accept-Charset"      },
    { 15, "Accept-Encoding"     },
    { 15, "Accept-Language"     },
    { 13, "Authorization"       },
    {  6, "Cookie"              },
    { 10, "Connection"          },
    { 14, "Content-Length"      },
    { 13, "Content-Range"       },
    { 12, "Content-Type"        },
    { 17, "If-Modified-Since"   },
    {  4, "Host"                },
    { 13, "Last-Modified"       },
    { 19, "Last-Modified-Since" },
    {  7, "Referer"             },
    {  5, "Range"               },
    { 10, "User-Agent"          }
};

/* Macro just for testing the parser on specific locations */
#define remaining()                                                     \
    {                                                                   \
        printf("%s** Line: %i / Chars: %i%s / remaining:\n",            \
               ANSI_BOLD, __LINE__, req->chars, ANSI_RESET);            \
        int x = 0;                                                      \
        for (x = i; x < len; x++) {                                     \
            if (buffer[x] == '\n') {                                    \
                printf("\\ n\n");                                       \
            }                                                           \
            else if (buffer[x] == '\r') {                               \
        printf("\\ r\n");                                               \
            }                                                           \
            else {                                                      \
                printf(" %c\n", buffer[x]);                             \
            }                                                           \
                                                                        \
        }                                                               \
    }

static inline int method_lookup(struct mk_http_parser *req, char *buffer)
{
    int i;
    int len;

    len = field_len();
    for (i = 0; i < MK_METHOD_SIZEOF; i++) {
        if (len != mk_methods_table[i].len) {
            continue;
        }

        if (strncmp(buffer + req->start, mk_methods_table[i].name, len) == 0) {
            return i;
        }
    }

    return MK_METHOD_UNKNOWN;
}

static inline int header_lookup(struct mk_http_parser *req, char *buffer)
{
    int i;
    int len;
    struct mk_http_header *header;
    struct row_entry *h;

    len = (req->header_sep - req->header_key);

    for (i = req->header_min; i <= req->header_max; i++) {
        h = &mk_headers_table[i];

        /* Check string length first */
        if (h->len != len) {
            continue;
        }

        if (strncmp(buffer + req->header_key + 1,
                    h->name + 1,
                    len - 1) == 0) {

            /* We got a header match, register the header index */
            header = &req->headers[i];
            header->type = i;
            header->key.data = buffer + req->header_key;
            header->key.len  = len;
            header->val.data = buffer + req->header_val;
            header->val.len  = req->end - req->header_val;

            if (i == MK_HEADER_CONTENT_LENGTH) {
                long val;
                char *endptr;

                val = strtol(header->val.data, &endptr, 10);
                if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
                    || (errno != 0 && val == 0)) {
                    return -1;
                }
                if (endptr == header->val.data) {
                    return -1;
                }
                if (val < 0) {
                    return -1;
                }

                req->header_content_length = val;
            }
            return 0;
        }
    }
    return 0;
}

/*
 * Parse the protocol and point relevant fields, don't take logic decisions
 * based on this, just parse to locate things.
 */
int mk_http_parser(struct mk_http_parser *req, char *buffer, int len)
{
    int i;
    int ret;
    int limit;

    limit = len + req->i;
    for (i = req->i; i < limit; req->i++, req->chars++, i++) {
        /* FIRST LINE LEVEL: Method, URI & Protocol */
        if (req->level == REQ_LEVEL_FIRST) {
            switch (req->status) {
            case MK_ST_REQ_METHOD:                      /* HTTP Method */
                if (buffer[i] == ' ') {
                    mark_end();
                    method_lookup(req, buffer);
                    req->status = MK_ST_REQ_URI;
                    if (req->end < 2) {
                        return MK_HTTP_ERROR;
                    }
                    parse_next();
                }
                break;
            case MK_ST_REQ_URI:                         /* URI */
                if (buffer[i] == ' ') {
                    mark_end();
                    req->status = MK_ST_REQ_PROT_VERSION;
                    if (field_len() < 1) {
                        return MK_HTTP_ERROR;
                    }
                    parse_next();
                }
                else if (buffer[i] == '?') {
                    mark_end();
                    req->status = MK_ST_REQ_QUERY_STRING;
                    parse_next();
                }
                break;
            case MK_ST_REQ_QUERY_STRING:                /* Query string */
                if (buffer[i] == ' ') {
                    mark_end();
                    req->status = MK_ST_REQ_PROT_VERSION;
                    parse_next();
                }
                break;
            case MK_ST_REQ_PROT_VERSION:                /* Protocol Version */
                if (buffer[i] == '\r') {
                    mark_end();
                    if (field_len() != 8) {
                        return MK_HTTP_ERROR;
                    }
                    req->status = MK_ST_FIRST_FINALIZING;
                    continue;
                }
                break;
            case MK_ST_FIRST_FINALIZING:                  /* New Line */
                if (buffer[i] == '\n') {
                    req->level = REQ_LEVEL_CONTINUE;
                    parse_next();
                }
                else {
                    return MK_HTTP_ERROR;
                }
                break;
            case MK_ST_BLOCK_END:
                if (buffer[i] == '\n') {
                    return MK_HTTP_OK;
                }
                else {
                    return MK_HTTP_ERROR;
                }
                break;
            };
        }
        else if (req->level == REQ_LEVEL_CONTINUE) {
            if (buffer[i] == '\r') {
                req->level = REQ_LEVEL_FIRST;
                req->status = MK_ST_BLOCK_END;
                continue;
            }
            else {
                req->level  = REQ_LEVEL_HEADERS;
                req->status = MK_ST_HEADER_KEY;
                req->chars  = 0;
            }
        }
        /* HEADERS: all headers stuff */
        if (req->level == REQ_LEVEL_HEADERS) {
            /* Expect a Header key */
            if (req->status == MK_ST_HEADER_KEY) {
                if (buffer[i] == '\r') {
                    if (req->chars == 0) {
                        req->level = REQ_LEVEL_END;
                        parse_next();
                    }
                    else {
                        return MK_HTTP_ERROR;
                    }
                }

                if (req->chars == 0) {
                    /*
                     * We reach the start of a Header row, lets catch the most
                     * probable header. Note that we don't accept headers starting
                     * in lowercase.
                     *
                     * The goal of this 'first row character lookup', is to define a
                     * small range set of probable headers comparison once we catch
                     * a header end.
                     */
                    switch (buffer[i]) {
                    case 'A':
                        req->header_min = MK_HEADER_ACCEPT;
                        req->header_max = MK_HEADER_AUTHORIZATION;
                        break;
                    case 'C':
                        req->header_min = MK_HEADER_COOKIE;
                        req->header_max = MK_HEADER_CONTENT_TYPE;
                        break;
                    case 'I':
                        header_scope_eq(req, MK_HEADER_IF_MODIFIED_SINCE);
                        break;
                    case 'H':
                        header_scope_eq(req, MK_HEADER_HOST);
                        break;
                    case 'L':
                        req->header_min = MK_HEADER_LAST_MODIFIED;
                        req->header_max = MK_HEADER_LAST_MODIFIED_SINCE;
                        break;
                    case 'R':
                        req->header_min = MK_HEADER_REFERER;
                        req->header_max = MK_HEADER_RANGE;
                        break;
                    case 'U':
                        header_scope_eq(req, MK_HEADER_USER_AGENT);
                        break;
                    default:
                        req->header_key = -1;
                        req->header_sep = -1;
                        req->header_min = -1;
                        req->header_max = -1;
                    };
                    req->header_key = i;
                }

                /* Found key/value separator */
                if (buffer[i] == ':') {

                    /* Set the key/value middle point */
                    req->header_sep = i;

                    /* validate length */
                    mark_end();
                    if (field_len() < 1) {
                        return MK_HTTP_ERROR;
                    }

                    /* Wait for a value */
                    req->status = MK_ST_HEADER_VALUE;
                    parse_next();
                }
            }
            /* Parsing the header value */
            else if (req->status == MK_ST_HEADER_VALUE) {
                /* Trim left, set starts only when found something != ' ' */
                if (buffer[i] == '\r' || buffer[i] == '\n') {
                    return MK_HTTP_ERROR;
                }
                else if (buffer[i] != ' ') {
                    req->status = MK_ST_HEADER_VAL_STARTS;
                    req->start = req->header_val = i;
                }
                continue;
            }
            /* New header row starts */
            else if (req->status == MK_ST_HEADER_VAL_STARTS) {
                /* Maybe there is no more headers and we reach the end ? */
                if (buffer[i] == '\r') {
                    mark_end();
                    if (field_len() <= 0) {
                        return MK_HTTP_ERROR;
                    }
                    req->status = MK_ST_HEADER_END;

                    /*
                     * A header row has ended, lets lookup the header and populate
                     * our headers table index.
                     */
                    ret = header_lookup(req, buffer);
                    if (ret != 0) {
                        return MK_HTTP_ERROR;
                    }
                    parse_next();
                }
                else if (buffer[i] == '\n' && buffer[i - 1] != '\r') {
                    return MK_HTTP_ERROR;
                }
                continue;
            }
            else if (req->status == MK_ST_HEADER_END) {
                if (buffer[i] == '\n') {
                    req->status = MK_ST_HEADER_KEY;
                    req->chars = -1;
                    parse_next();
                }
                else {
                    return MK_HTTP_ERROR;
                }
            }
        }
        else if (req->level == REQ_LEVEL_END) {
            if (buffer[i] == '\n') {
                req->level = REQ_LEVEL_BODY;
                req->chars = -1;
                parse_next();
            }
            else {
                return MK_HTTP_ERROR;
            }
        }
        else if (req->level == REQ_LEVEL_BODY) {
            /*
             * Reaching this level can means two things:
             *
             * - A Pipeline Request
             * - A Body content (POST/PUT methods
             */
            if (req->header_content_length > 0) {
                req->body_received += (limit - i);

                if (req->body_received == req->header_content_length) {
                    return MK_HTTP_OK;
                }
                else {
                    return MK_HTTP_PENDING;
                }
            }
            return MK_HTTP_OK;
        }
    }

    /*
     * FIXME: the code above needs to be handled in a different way
     */

    if (req->level == REQ_LEVEL_FIRST) {
        if (req->status == MK_ST_REQ_METHOD) {
            if (req->i > 10) {
                return MK_HTTP_ERROR;
            }
            else {
                return MK_HTTP_PENDING;
            }
        }

    }
    else if (req->level == REQ_LEVEL_HEADERS) {
        if (req->status == MK_ST_HEADER_KEY) {
            return MK_HTTP_PENDING;
        }
        else if (req->status == MK_ST_HEADER_VALUE) {
            if (field_len() < 0) {
                return MK_HTTP_PENDING;
            }
        }
    }
    else if (req->level == REQ_LEVEL_BODY) {
        if (req->header_content_length > 0) {
            req->body_received += (limit - i);
            if (req->header_content_length == req->body_received) {
                return MK_HTTP_OK;
            }
            else {
                return MK_HTTP_PENDING;
            }
        }
        if (req->header_content_length > 0 &&
            req->body_received <= req->header_content_length) {
            return MK_HTTP_PENDING;
        }
        else if (req->chars == 0) {
            return MK_HTTP_OK;
        }
        else {
        }

    }
    return MK_HTTP_PENDING;
}

struct mk_http_parser *mk_http_parser_new()
{
    struct mk_http_parser *req;

    req = malloc(sizeof(struct mk_http_parser));
    req->i      = 0;
    req->level  = REQ_LEVEL_FIRST;
    req->status = MK_ST_REQ_METHOD;
    req->length = 0;
    req->start  = 0;
    req->end    = 0;
    req->chars  = -1;

    /* init headers */
    req->header_min = -1;
    req->header_max = -1;
    req->header_sep = -1;
    req->body_received  = 0;
    req->header_content_length = -1;

    return req;
}
