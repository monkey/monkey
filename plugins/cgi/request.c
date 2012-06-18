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

#include "cgi.h"

struct cgi_request *cgi_req_create(int fd, int socket)
{
    struct cgi_request *newcgi = mk_api->mem_alloc_z(sizeof(struct cgi_request));
    if (!newcgi) return NULL;

    newcgi->fd = fd;
    newcgi->socket = socket;

    return newcgi;
}

void cgi_req_add(struct cgi_request *r)
{
    struct mk_list *list = pthread_getspecific(_mkp_data);

    mk_list_add(&r->_head, list);
}

int cgi_req_del(struct cgi_request *r)
{
    if (!r) return 1;

    mk_list_del(&r->_head);
    free(r);

    return 0;
}
