/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
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

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "monkey.h"
#include "mk_config.h"
#include "mk_memory.h"
#include "mk_request.h"
#include "mk_header.h"
#include "mk_http.h"
#include "mk_iov.h"
#include "mk_user.h"

inline ALLOCSZ_ATTR(1)
void *mk_mem_malloc(const size_t size)
{
    void *aux = malloc(size);

    if (!aux && size) {
        perror("malloc");
        return NULL;
    }

    return aux;
}

inline ALLOCSZ_ATTR(1)
void *mk_mem_malloc_z(const size_t size)
{
    void *buf = calloc(1, size);
    if (!buf)
        return NULL;

    return buf;
}

inline ALLOCSZ_ATTR(2)
void *mk_mem_realloc(void *ptr, const size_t size)
{
    void *aux = realloc(ptr, size);

    if (!aux && size) {
        perror("realloc");
        return NULL;
    }

    return aux;
}

void mk_mem_free(void *ptr)
{
    free(ptr);
}

mk_pointer mk_pointer_create(char *buf, long init, long end)
{
    mk_pointer p;

    mk_pointer_reset(&p);
    p.data = buf + init;

    if (init != end) {
        p.len = (end - init);
    }
    else {
        p.len = 1;
    }

    return p;
}

void mk_pointer_reset(mk_pointer * p)
{
    p->data = NULL;
    p->len = 0;
}

void mk_pointer_free(mk_pointer * p)
{
    mk_mem_free(p->data);
    p->len = 0;
}

char *mk_pointer_to_buf(mk_pointer p)
{
    char *buf;

    buf = mk_mem_malloc(p.len + 1);
    if (!buf) return NULL;

    memcpy(buf, p.data, p.len);
    buf[p.len] = '\0';

    return (char *) buf;
}

void mk_pointer_print(mk_pointer p)
{
    unsigned int i;

    printf("\nDEBUG MK_POINTER: '");
    for (i = 0; i < p.len && p.data != NULL; i++) {
        printf("%c", p.data[i]);
    }
    printf("'");
    fflush(stdout);
}

void mk_pointer_set(mk_pointer *p, char *data)
{
    p->data = data;
    p->len = strlen(data);
}

void mk_mem_pointers_init()
{
    mk_iov_separators_init();
}

