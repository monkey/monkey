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

#define _GNU_SOURCE
#include <string.h>

#include <ctype.h>
#include <stdlib.h>

#include "request.h"
#include "utils.h"
#include "memory.h"


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
                mk_mem_free(buffer);
		return NULL;
	}
	
	bytes =  pos_end - pos_init;
        memcpy(buffer, string+pos_init, bytes);
        buffer[bytes]='\0';

	return (char *) buffer;	
}

int mk_string_char_search(char *string, int c, int n)
{
        int i;

        if(n<0)
        {
                n = strlen(string);
        }

        for(i=0; i<n; i++)
        {
                if(string[i]==c)
                        return i;
        }

        return -1;
}
/* Get position of a substring.
 * Original version taken from google, modified in order
 * to send the position instead the substring.
 */

int _mk_string_search(char *string, char *search, int n)
{
	char *np;
        int res;

        np = strcasestr(string, search);
        if(!np)
        {
                return -1;
        }

        res = np-string;
        if(res>n && n>=0)
        {
                return -1;
        }
        return (np-string);
}

int mk_string_search(char *string, char *search)
{
	return _mk_string_search(string, search, -1);
}

/* lookup char in reverse order */
int mk_string_search_r(char *string, char search, int n)
{
        int i,j;

        if(n>=0){
                j = n;
        }
        else{
                j = strlen(string);
        }

        for(i=j;i>=0;i--)
        {
                if(string[i]==search){
                        return i;
                }
        }

        return -1;
}

int mk_string_search_n(char *string, char *search, int n)
{
	return _mk_string_search(string, search, n);

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
	if(!s)
		return NULL;

	return strdup(s);
}

int mk_string_array_count(char *arr[])
{
        int i=0;

        for(i=0; arr[i]; i++){}
        return i;
}
