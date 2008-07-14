/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2008, Eduardo Silva P.
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

#ifndef MK_HEADER_H
#define MK_HEADER_H

#include <sys/uio.h>

/* 
 * Response headers: We handle this as static global data in order
 * to save some process time when building the response header.
 */
#define MK_IOV_BREAK_LINE 0
#define _MK_IOV_BREAK_LINE "\r\n"
#define LEN_MK_IOV_BREAK_LINE 2

#define MK_IOV_SPACE 1
#define _MK_IOV_SPACE " "
#define LEN_MK_IOV_SPACE 1

#define MK_IOV_NONE 2
#define _MK_IOV_NONE ""
#define LEN_MK_IOV_NONE 0

#define RESP_HTTP_OK "HTTP/1.1 200 OK"
#define LEN_RESP_HTTP_OK 15

#define RESP_HTTP_PARTIAL "HTTP/1.1 206 Partial Content"
#define LEN_RESP_HTTP_PARTIAL 28

#define RESP_REDIR_MOVED "HTTP/1.1 301 Moved Permanently"
#define LEN_RESP_REDIR_MOVED 30

#define RESP_REDIR_MOVED_T "HTTP/1.1 302 Found"
#define LEN_RESP_REDIR_MOVED_T 18

#define RESP_NOT_MODIFIED "HTTP/1.1 304 Not Modified"
#define LEN_RESP_NOT_MODIFIED 25

#define RESP_CLIENT_BAD_REQUEST "HTTP/1.1 400 Bad Request"
#define LEN_RESP_CLIENT_BAD_REQUEST 24

#define RESP_CLIENT_FORBIDDEN "HTTP/1.1 403 Forbidden"
#define LEN_RESP_CLIENT_FORBIDDEN 22

#define RESP_CLIENT_NOT_FOUND "HTTP/1.1 404 Not Found"
#define LEN_RESP_CLIENT_NOT_FOUND 22

#define RESP_CLIENT_METHOD_NOT_ALLOWED "HTTP/1.1 405 Method Not Allowed"
#define LEN_RESP_CLIENT_METHOD_NOT_ALLOWED 31

#define RESP_CLIENT_REQUEST_TIMEOUT "HTTP/1.1 408 Request Timeout"
#define LEN_RESP_CLIENT_REQUEST_TIMEOUT 28

#define RESP_CLIENT_LENGTH_REQUIRED "HTTP/1.1 411 Length Required"
#define LEN_RESP_CLIENT_LENGTH_REQUIRED 28

#define RESP_SERVER_INTERNAL_ERROR "HTTP/1.1 500 Internal Server Error"
#define LEN_RESP_SERVER_INTERNAL_ERROR 34

#define RESP_SERVER_HTTP_VERSION_UNSUP "HTTP/1.1 505 HTTP Version Not Supported"
#define LEN_RESP_SERVER_HTTP_VERSION_UNSUP 39


#define MK_IOV_FREE_BUF 1
#define MK_IOV_NOT_FREE_BUF 0

struct mk_iov 
{
	struct iovec *io;
	char **buf_to_free;
	int iov_idx;
	int buf_idx;
};

struct mk_iov *mk_iov_create(int n);
int mk_iov_add_entry(struct mk_iov *mk_io, char *buf, int len, int sep, int free);
int mk_iov_add_separator(struct mk_iov *mk_io, int sep);
ssize_t mk_iov_send(int fd, struct mk_iov *mk_io);
void mk_iov_free(struct mk_iov *mk_io);

#endif

