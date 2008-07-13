/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2008, Eduardo Silva P.
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

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "memory.h"

void *mk_mem_malloc(size_t size)
{
	char *aux=0;

	if((aux=malloc(size))==NULL){
		perror("malloc");
		return NULL;						
	}
	return (void *) aux;
}

void *mk_mem_malloc_z(size_t size)
{
	char *buf=0;

	buf = mk_mem_malloc(size);
	if(!buf)
	{
		return NULL;
	}

	memset(buf, '\0', sizeof(size));
	return buf;
}

void *mk_mem_realloc(void* ptr, size_t size)
{
	char *aux=0;

	if((aux=realloc(ptr, size))==NULL){
		perror("realloc");
		return NULL;						
	}

	return (void *) aux;
}
	
void mk_mem_free(void *ptr)
{
	if(ptr!=NULL){
		free(ptr);
	}
}

mk_pointer mk_pointer_create(char *buf, long init, long end)
{
	mk_pointer p;

	p.data = buf+init;
	p.len = (end - init);

	return p;
}

void mk_pointer_reset(mk_pointer p)
{
	p.data = NULL;
	p.len = 0;
}

void mk_pointer_free(mk_pointer p)
{
	mk_mem_free(p.data);
	p.len = 0;
}

char *mk_pointer_to_buf(mk_pointer p)
{
	char *buf;

	buf = strndup(p.data, p.len);
	return (char *) buf;
}

