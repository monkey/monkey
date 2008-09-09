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

#include <stdio.h>
#include "monkey.h"

#include "header.h"
#include "memory.h"
#include "iov.h"

struct mk_iov *mk_iov_create(int n)
{
	struct mk_iov *iov;

	iov = mk_mem_malloc(sizeof(struct mk_iov));
	iov->iov_idx = 0;
	iov->io = mk_mem_malloc(n*sizeof(struct iovec));
	iov->buf_to_free = mk_mem_malloc(n*sizeof(char));
	iov->buf_idx = 0;
	return iov;
}

int mk_iov_add_entry(struct mk_iov *mk_io, char *buf, int len, 
		int sep, int free)
{
	mk_io->io[mk_io->iov_idx].iov_base = buf;
	mk_io->io[mk_io->iov_idx].iov_len = len;
	mk_io->iov_idx++;

	mk_iov_add_separator(mk_io, sep);

	if(free==MK_IOV_FREE_BUF)
	{
		mk_io->buf_to_free[mk_io->buf_idx] = (char *)buf;
		mk_io->buf_idx++;
	}
	return mk_io->iov_idx;
}

int mk_iov_add_separator(struct mk_iov *mk_io, int sep)
{
	int len=0;
	char *_sep=0;

	switch(sep)
	{
		case MK_IOV_BREAK_LINE:
			_sep = _MK_IOV_BREAK_LINE;
			len = LEN_MK_IOV_BREAK_LINE;
			break;
		case MK_IOV_SPACE:
			_sep = _MK_IOV_SPACE;
			len = LEN_MK_IOV_SPACE;
			break;
		case MK_IOV_HEADER_VALUE:
			_sep = _MK_IOV_HEADER_VALUE;
			len = LEN_MK_IOV_HEADER_VALUE;
			break;
		case MK_IOV_NONE:
			return mk_io->iov_idx;
		default:
			printf("\nInvalid value");
			fflush(stdout);
			break;
	}

	mk_io->io[mk_io->iov_idx].iov_base = _sep;
	mk_io->io[mk_io->iov_idx].iov_len = len;
	mk_io->iov_idx++;

	return mk_io->iov_idx;
}

ssize_t mk_iov_send(int fd, struct mk_iov *mk_io)
{
	ssize_t n;

	n = writev(fd, mk_io->io, mk_io->iov_idx);
	return n;
}

void mk_iov_free(struct mk_iov *mk_io)
{
	int i, limit=0;

	limit = mk_io->buf_idx-1;
	for(i=0; i<limit; i++)
	{
		// printf("\ngoing free (idx: %i/%i): %s",i, limit, mk_io->buf_to_free[i]);
		// fflush(stdout);
		mk_mem_free(mk_io->buf_to_free[i]);
	}
	mk_mem_free(mk_io->io);
	mk_mem_free(mk_io);
}
