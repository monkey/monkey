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

static int hangup(int socket)
{
    struct cgi_request *r = cgi_req_get_by_fd(socket);

    if (r) {
        /* If the CGI app is fast, we might get a hangup event before
         * a write event. Try to write things out first. */
        _mkp_event_write(r->socket);

        mk_api->event_del(r->fd);

        mk_api->http_request_end(r->socket);
        mk_api->socket_close(r->fd);

        /* XXX Fixme: this needs to be atomic */
        requests_by_socket[r->socket] = NULL;

        cgi_req_del(r);
        return MK_PLUGIN_RET_EVENT_OWNED;
    }

    return MK_PLUGIN_RET_EVENT_CONTINUE;
}

int _mkp_event_write(int socket)
{
    struct cgi_request *r = cgi_req_get(socket);
    if (!r) return MK_PLUGIN_RET_EVENT_CONTINUE;

    if (r->in_len > 0) {

        mk_api->socket_cork_flag(socket, TCP_CORK_ON);

        const char *buf = r->in_buf, *outptr = r->in_buf;

        if (!r->headers_done) {
            if (r->in_len >= 8 && memcmp(buf, "Status: ", 8) == 0) {
                swrite(socket, "HTTP/1.0 ", 9);
                outptr += 8;
                r->in_len -= 8;
                r->headers_done = 1;
            }
            else if (r->in_len >= 4) {
                if (memcmp(buf, "HTTP", 4) != 0) {
                    swrite(socket, "HTTP/1.0 200 OK\r\n", sizeof("HTTP/1.0 200 OK\r\n") - 1);
                }
                r->headers_done = 1;
            }
        }

        swrite(socket, outptr, r->in_len);
        r->in_len = 0;
        mk_api->event_socket_change_mode(socket, MK_EPOLL_READ, MK_EPOLL_LEVEL_TRIGGERED);

        mk_api->socket_cork_flag(socket, TCP_CORK_OFF);
    }

    return MK_PLUGIN_RET_EVENT_OWNED;
}

int _mkp_event_read(int fd)
{
    struct cgi_request *r = cgi_req_get_by_fd(fd);
    if (!r) return MK_PLUGIN_RET_EVENT_NEXT;

    size_t count = PATHLEN - r->in_len;

    /* Too much to read? Start writing. */
    if (count < 1)
        goto out;

    int n = read(r->fd, r->in_buf + r->in_len, count);

    if (n <=0)
        return MK_PLUGIN_RET_EVENT_CLOSE;

    r->in_len += n;

out:
    /* Now we do have something to write */
    mk_api->event_socket_change_mode(r->socket, MK_EPOLL_WRITE, MK_EPOLL_LEVEL_TRIGGERED);

    return MK_PLUGIN_RET_EVENT_OWNED;
}

int _mkp_event_close(int socket)
{
    return hangup(socket);
}

int _mkp_event_error(int socket)
{
    return hangup(socket);
}
