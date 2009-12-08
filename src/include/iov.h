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
#define MK_IOV_CRLF "\r\n"
#define MK_IOV_LF "\n"
#define MK_IOV_SPACE " "
#define MK_IOV_HEADER_VALUE ": "
#define MK_IOV_SLASH "/"
#define MK_IOV_NONE ""
#define MK_IOV_EQUAL "="

#define MK_IOV_SEND_TO_SOCKET 0
#define MK_IOV_SEND_TO_PIPE 1

#include "memory.h"

mk_pointer mk_iov_crlf;
mk_pointer mk_iov_lf;
mk_pointer mk_iov_space;
mk_pointer mk_iov_header_value;
mk_pointer mk_iov_slash;
mk_pointer mk_iov_none;
mk_pointer mk_iov_equal;

struct mk_iov 
{
	struct iovec *io;
	char **buf_to_free;
	int iov_idx;
	int buf_idx;
        int size;
        unsigned long total_len;
};

struct mk_iov *mk_iov_create(int n, int offset);
int mk_iov_add_entry(struct mk_iov *mk_io, char *buf, 
                     int len, mk_pointer sep, int free);

int mk_iov_add_separator(struct mk_iov *mk_io, mk_pointer sep);

ssize_t mk_iov_send(int fd, struct mk_iov *mk_io, int to);

void mk_iov_free(struct mk_iov *mk_io);

int _mk_iov_add(struct mk_iov *mk_io, char *buf, int len, 
                mk_pointer sep, int free, int idx);

void _mk_iov_set_free(struct mk_iov *mk_io, char *buf);

int mk_iov_set_entry(struct mk_iov *mk_io, char *buf, int len, 
                     int free, int idx);

void mk_iov_separators_init();
void mk_iov_free_marked(struct mk_iov *mk_io);
void mk_iov_print(struct mk_iov *mk_io);

#endif

