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

#ifndef MK_MEM_H
#define MK_MEM_H

typedef struct
{
	char *data;
	unsigned long len;
} mk_pointer;

void *mk_mem_malloc(size_t size);
void *mk_mem_malloc_z(size_t size);

void *mk_mem_realloc(void* ptr, size_t size);
void mk_mem_free(void *ptr);
void mk_mem_pointers_init();

/* mk_pointer_* */
mk_pointer mk_pointer_create(char *buf, long init, long end);
void mk_pointer_free(mk_pointer p);
void mk_pointer_reset(mk_pointer p);
char *mk_pointer_to_buf(mk_pointer p);
void mk_pointer_set(mk_pointer *p, char *data);

#endif

