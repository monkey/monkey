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

#ifndef MK_IOV_H
#define MK_IOV_H

#include <stdio.h>
#include <sys/uio.h>
#include "mk_utils.h"
#include "mk_macros.h"

#define MK_IOV_FREE_BUF 1
#define MK_IOV_NOT_FREE_BUF 0

/* iov separators */
#define MK_IOV_CRLF "\r\n"
#define MK_IOV_CRLFCRLF "\r\n\r\n"
#define MK_IOV_LF "\n"
#define MK_IOV_LFLF "\n\n"
#define MK_IOV_LFLFLFLF "\n\n\n\n"
#define MK_IOV_SPACE " "
#define MK_IOV_SLASH "/"
#define MK_IOV_NONE ""
#define MK_IOV_EQUAL "="

#include "mk_memory.h"

extern const mk_ptr_t mk_iov_crlf;
extern const mk_ptr_t mk_iov_lf;
extern const mk_ptr_t mk_iov_space;
extern const mk_ptr_t mk_iov_slash;
extern const mk_ptr_t mk_iov_none;
extern const mk_ptr_t mk_iov_equal;

struct mk_iov
{
    struct iovec *io;
    void **buf_to_free;
    int iov_idx;
    int buf_idx;
    int size;
    unsigned long total_len;
};

struct mk_iov *mk_iov_create(int n, int offset);
int mk_iov_realloc(struct mk_iov *mk_io, int new_size);

int mk_iov_add_separator(struct mk_iov *mk_io, mk_ptr_t sep);

ssize_t mk_iov_send(int fd, struct mk_iov *mk_io);

void mk_iov_free(struct mk_iov *mk_io);

int _mk_iov_add(struct mk_iov *mk_io, void *buf, int len,
                mk_ptr_t sep, int free, int idx);

int mk_iov_set_entry(struct mk_iov *mk_io, void *buf, int len,
                     int free, int idx);

void mk_iov_separators_init(void);
void mk_iov_free_marked(struct mk_iov *mk_io);
void mk_iov_print(struct mk_iov *mk_io);

static inline void _mk_iov_set_free(struct mk_iov *mk_io, void *buf)
{
    mk_io->buf_to_free[mk_io->buf_idx] = (void *) buf;
    mk_io->buf_idx++;
}

static inline int mk_iov_add_entry(struct mk_iov *mk_io, void *buf, int len,
                                   mk_ptr_t sep, int free)
{
    mk_io->io[mk_io->iov_idx].iov_base = (unsigned char *) buf;
    mk_io->io[mk_io->iov_idx].iov_len = len;
    mk_io->iov_idx++;
    mk_io->total_len += len;

#ifdef DEBUG_IOV
    if (mk_io->iov_idx > mk_io->size) {
        printf("\nDEBUG IOV :: ERROR, Broken array size in:");
        printf("\n          '''%s'''", buf);
        fflush(stdout);
    }
#endif

    /* Add separator */
    if (sep.len > 0) {
        mk_io->io[mk_io->iov_idx].iov_base = sep.data;
        mk_io->io[mk_io->iov_idx].iov_len = sep.len;
        mk_io->iov_idx++;
        mk_io->total_len += sep.len;
    }

    if (free == MK_IOV_FREE_BUF) {
        _mk_iov_set_free(mk_io, buf);
    }

    mk_bug(mk_io->iov_idx > mk_io->size);

    return mk_io->iov_idx;
}


#endif
