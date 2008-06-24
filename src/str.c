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

#include <ctype.h>
#include <stdlib.h>

#include "request.h"
#include "utils.h"
#include "memory.h"

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>

/* Return a buffer with a new string from string */
char *mk_string_copy_substr(const char *string, int pos_init, int pos_end)
{
	unsigned int size, bytes;
	char *buffer=0;

	size = (unsigned int) (pos_end - pos_init ) + 1;
	if(size<=2) size=4;

	buffer = malloc(size);
	
	if(!buffer){
		return NULL;
	}
	
	if(pos_init > pos_end)
	{
		return NULL;
	}
	
	bytes =  pos_end - pos_init;
	strncpy(buffer, string+pos_init, bytes);
	buffer[bytes]='\0';
	return (char *) buffer;	
}

/* Get position of a substring.
 * Original version taken from google, modified in order
 * to send the position instead the substring.
 */
int mk_string_search(char *string, char *search)
{
	char *p, *startn = 0, *np = 0;
	int idx=-1, loop=0;

	for (p = string; *p; p++) {
		if (np) {
			if (toupper(*p) == toupper(*np)) {
				if (!*++np)
				{	
					return idx;
				}
			} else
			{
				np = 0;
				idx = -1;
			}
		} else if (toupper(*p) == toupper(*search)) {
			np = search + 1;
			startn = p;
			idx = loop;
			if(!*np)
			{
				return idx;
			}
		}

		loop++;
	}
	return idx;
}
char *mk_string_remove_space(char *buf)
{
    size_t bufsize;
    int new_i=0, i, len, spaces=0;
    char *new_buf=0;

    len = strlen(buf);
    for(i=0; i<len; i++)
    {
        if(buf[i] == ' '){
            spaces++;
        }
    }

    bufsize = len+1-spaces;
    if(bufsize <= 1){
        return NULL;
    }

    new_buf = mk_mem_malloc(bufsize);

    for(i=0; i<len; i++)
    {
        if(buf[i] != ' '){
            new_buf[new_i] = buf[i];
            new_i++;
        }
    }

    return new_buf;
}

char *mk_string_casestr(char *heystack, char *needle)
{
	if(!heystack || !needle)
	{
		return NULL;
	}

	return strcasestr(heystack, needle);
}

char *mk_string_dup(const char *s)
{
	char *aux=0;
	size_t size;
 	
	if(!s)
		return NULL;

	size = strlen(s)+1;	
	if((aux=malloc(size))==NULL){
		perror("strdup");
		return NULL;						
	}

	memcpy(aux, s, size);
	return (char *) aux;
}

