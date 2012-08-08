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

#ifndef MK_MEM_H
#define MK_MEM_H

typedef struct
{
    char *data;
    unsigned long len;
} mk_pointer;

#if ((__GNUC__ * 100 + __GNUC__MINOR__) > 430)  /* gcc version > 4.3 */
# define ALLOCSZ_ATTR(x,...) __attribute__ ((alloc_size(x, ##__VA_ARGS__)))
#else
# define ALLOCSZ_ATTR(x,...)
#endif

inline void *mk_mem_malloc(const size_t size);
inline void *mk_mem_malloc_z(const size_t size);
inline void *mk_mem_realloc(void *ptr, const size_t size);
void mk_mem_free(void *ptr);
void mk_mem_pointers_init(void);

/* mk_pointer_* */
mk_pointer mk_pointer_create(char *buf, long init, long end);
void mk_pointer_free(mk_pointer * p);
void mk_pointer_print(mk_pointer p);
char *mk_pointer_to_buf(mk_pointer p);
void mk_pointer_set(mk_pointer * p, char *data);

static inline void mk_pointer_reset(mk_pointer * p)
{
    p->data = NULL;
    p->len = 0;
}


#define mk_pointer_init(a) {a, sizeof(a) - 1}

#endif
