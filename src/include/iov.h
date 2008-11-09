/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

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

#ifndef MK_IOV_H
#define MK_IOV_H

#include <sys/uio.h>

#define MK_IOV_FREE_BUF 1
#define MK_IOV_NOT_FREE_BUF 0

/* iov separators */

/* break line */
#define MK_IOV_BREAK_LINE 0
#define _MK_IOV_BREAK_LINE "\r\n"
#define LEN_MK_IOV_BREAK_LINE 2

/* blank space */
#define MK_IOV_SPACE 1
#define _MK_IOV_SPACE " "
#define LEN_MK_IOV_SPACE 1

/* header value */
#define MK_IOV_HEADER_VALUE 2
#define _MK_IOV_HEADER_VALUE ": "
#define LEN_MK_IOV_HEADER_VALUE 2

#define MK_IOV_SLASH 3
#define _MK_IOV_SLASH "/"
#define LEN_MK_IOV_SLASH 1

/* avoid */
#define MK_IOV_NONE 4

struct mk_iov 
{
	struct iovec *io;
	char **buf_to_free;
	int iov_idx;
	int buf_idx;
        int size;
        unsigned long total_len;
};

struct mk_iov *mk_iov_create(int n);
int mk_iov_add_entry(struct mk_iov *mk_io, char *buf, int len, int sep, int free);
int mk_iov_add_separator(struct mk_iov *mk_io, int sep);
ssize_t mk_iov_send(int fd, struct mk_iov *mk_io);
void mk_iov_free(struct mk_iov *mk_io);
struct mk_iov *mk_iov_create_offset(int n, int offset);
int _mk_iov_add(struct mk_iov *mk_io, char *buf, int len, 
                int sep, int free, int idx);
void _mk_iov_set_free(struct mk_iov *mk_io, char *buf, int free);
int mk_iov_set_entry(struct mk_iov *mk_io, char *buf, int len, 
                     int free, int idx);
#endif

