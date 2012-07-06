/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2012, Lauri Kasanen
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

#ifndef CGI_H
#define CGI_H

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>

#include "MKPlugin.h"

enum {
    PATHLEN = 1024,
    SHORTLEN = 36
};

struct cgi_request {

    char in_buf[PATHLEN];

    struct mk_list _head;

    struct session_request *sr;
    struct client_session *cs;

    unsigned int in_len;

    int fd;			/* From the CGI app */
    int socket;

    unsigned char status_done;
    unsigned char all_headers_done;
    unsigned char chunked;
};

extern struct cgi_request **requests_by_socket;

int swrite(const int fd, const void *buf, const size_t count);

struct cgi_request *cgi_req_create(int fd, int socket, struct session_request *sr,
					struct client_session *cs);
void cgi_req_add(struct cgi_request *r);
int cgi_req_del(struct cgi_request *r);

static inline struct cgi_request *cgi_req_get(int socket)
{
    struct cgi_request *r = requests_by_socket[socket];

    return r;
}

static inline struct cgi_request *cgi_req_get_by_fd(int fd)
{
    struct mk_list *list, *node;
    struct cgi_request *r;

    list = pthread_getspecific(_mkp_data);
    if (mk_list_is_empty(list) == 0)
        return NULL;

    mk_list_foreach(node, list) {
        r = mk_list_entry(node, struct cgi_request, _head);
        if (r->fd == fd)
            return r;
    }

    return NULL;
}

#endif
