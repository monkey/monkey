/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P. <edsiper@gmail.com>
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

#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>

#include "request.h"
#include "utils.h"
#include "memory.h"
#include "str.h"

#include <stdio.h>

/* Get position of a substring.
 * Original version taken from google, modified in order
 * to send the position instead the substring.
 */
int _mk_string_search(const char *string, const char *search, int sensitive, int len)
{
    char *np = 0;
    int res;

    if (sensitive == MK_STR_INSENSITIVE) {
        np = strcasestr(string, search);
    }
    else if (sensitive == MK_STR_SENSITIVE) {
        np = strstr(string, search);
    }

    if (!np) {
        return -1;
    }

    res = np - string;
    if (res > len && len >= 0) {
        return -1;
    }
    return (np - string);
}

/* Lookup char into string, return position */
int mk_string_char_search(const char *string, int c, int len)
{
    int i;

    if (len < 0) {
        len = strlen(string);
    }

    for (i = 0; i < len; i++) {
        if (string[i] == c)
            return i;
    }

    return -1;
}

/* Find char into string searching in reverse order, returns position */
int mk_string_char_search_r(const char *string, int c, int len)
{
    int i, j;

    if (len >= 0) {
        j = len;
    }
    else {
        j = strlen(string);
    }

    for (i = j; i >= 0; i--) {
        if (string[i] == c) {
            return i;
        }
    }

    return -1;
}

int mk_string_search(const char *haystack, const char *needle, int sensitive)
{
    return _mk_string_search(haystack, needle, sensitive, -1);
}

int mk_string_search_n(const char *haystack, const char *needle, int sensitive, int len)
{
    return _mk_string_search(haystack, needle, sensitive, len);
}

char *mk_string_remove_space(char *buf)
{
    size_t bufsize;
    int new_i = 0, i, len, spaces = 0;
    char *new_buf = 0;

    len = strlen(buf);
    for (i = 0; i < len; i++) {
        if (buf[i] == ' ') {
            spaces++;
        }
    }

    bufsize = len + 1 - spaces;
    if (bufsize <= 1) {
        return NULL;
    }

    new_buf = mk_mem_malloc(bufsize);

    for (i = 0; i < len; i++) {
        if (buf[i] != ' ') {
            new_buf[new_i] = buf[i];
            new_i++;
        }
    }

    return new_buf;
}

char *mk_string_casestr(char *heystack, char *needle)
{
    if (!heystack || !needle) {
        return NULL;
    }

    return strcasestr(heystack, needle);
}

char *mk_string_dup(const char *s)
{
    if (!s)
        return NULL;

    return strdup(s);
}

int mk_string_array_count(char *arr[])
{
    int i = 0;

    for (i = 0; arr[i]; i++) {
    }
    return i;
}

struct mk_string_line *mk_string_split_line(char *line)
{
    unsigned int i = 0, len, val_len;
    int end;
    char *val;
    struct mk_string_line *sl = 0, *new, *p;

    if (!line) {
        return NULL;
    }

    len = strlen(line);

    while (i < len) {
        end = mk_string_char_search(line + i, ' ', len - i);

        if (end >= 0 && end + i < len) {
            end += i;

            if (i == end) {
                i++;
                continue;
            }

            val = mk_string_copy_substr(line, i, end);
            val_len = end - i;
        }
        else {
            val = mk_string_copy_substr(line, i, len);
            val_len = len - i;
            end = len;

        }

        /* Alloc node */
        new = mk_mem_malloc(sizeof(struct mk_string_line));
        new->val = val;
        new->len = val_len;
        new->next = NULL;

        /* Link node */
        if (!sl) {
            sl = new;
        }
        else {
            p = sl;
            while (p->next) {
                p = p->next;
            }

            p->next = new;
        }
        i = end + 1;
    }

    return sl;
}

char *mk_string_build(char **buffer, unsigned long *len, 
                      const char *format, ...)
{
    va_list ap;
    int length;
    char *ptr;
    static size_t _mem_alloc = 64;
    size_t alloc = 0;

    /* *buffer *must* be an empty/NULL buffer */

    *buffer = (char *) mk_mem_malloc(_mem_alloc);
    if (!*buffer) {
        return NULL;
    }
    alloc = _mem_alloc;

    va_start(ap, format);
    length = vsnprintf(*buffer, alloc, format, ap);
    va_end(ap);

    if (length >= alloc) {
        ptr = realloc(*buffer, length + 1);
        if (!ptr) {
            return NULL;
        }
        *buffer = ptr;
        alloc = length + 1;

        va_start(ap, format);
        length = vsnprintf(*buffer, alloc, format, ap);
        va_end(ap);
    }

    if (length < 0) {
        return NULL;
    }

    ptr = *buffer;
    ptr[length] = '\0';
    *len = length;

    return *buffer;
}

int mk_string_trim(char **str)
{
    int i;
    unsigned int len;
    char *left = 0, *right = 0;
    char *buf;

    buf = *str;
    if (!buf) {
        return -1;
    }

    len = strlen(buf);
    left = buf;

    /* left spaces */
    while (left) {
        if (isspace(*left)) {
            left++;
        }
        else {
            break;
        }
    }

    right = buf + (len - 1);
    /* Validate right v/s left */
    if (right < left) {
        buf[0] = '\0';
        return -1;
    }

    /* Move back */
    while (right != buf){
        if (isspace(*right)) {
            right--;
        }
        else {
            break;
        }
    }

    len = (right - left) + 1;
    for(i=0; i<len; i++){
        buf[i] = (char) left[i];
    }
    buf[i] = '\0';

    return 0;
}

int mk_string_itop(int n, mk_pointer *p)
{
    /*
      Code taken from some forum...
    */
    int i = 0;
    int length = 0;
    int temp = 0;
    char *str;

    str = p->data;

    if (!str) {
        return -1;
    }

    /* Generate digit characters in reverse order */
    do {
        str[i++] = ('0' + (n % 10));
        n /= 10;
    } while (n>0);
    
    /* Add CRLF and NULL byte */
    str[i] = '\0';

    p->len = length = i;
    
    for (i=0; i < (length/2); i++) {
        temp = str[i];
        str[i] = str[length-i-1];
        str[length-i-1] = temp;
    }

    i = length;
    str[i++] = '\r';
    str[i++] = '\n';
    str[i++] = '\0';

    p->len+=2;

    return 0;
}

/* Return a buffer with a new string from string */
char *mk_string_copy_substr(const char *string, int pos_init, int pos_end)
{
    unsigned int size, bytes;
    char *buffer = 0;

    size = (unsigned int) (pos_end - pos_init) + 1;
    if (size <= 2)
        size = 4;

    buffer = malloc(size);

    if (!buffer) {
        return NULL;
    }

    if (pos_init > pos_end) {
        mk_mem_free(buffer);
        return NULL;
    }

    bytes = pos_end - pos_init;
    memcpy(buffer, string + pos_init, bytes);
    buffer[bytes] = '\0';

    return (char *) buffer;
}

