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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <unistd.h>
#include <signal.h>
#include <sys/sendfile.h>

#include <time.h>

#include "monkey.h"
#include "memory.h"
#include "utils.h"
#include "str.h"
#include "config.h"
#include "chars.h"
#include "socket.h"
#include "clock.h"

int SendFile(int socket, struct client_request *cr, struct request *sr)
{
    long int nbytes = 0;

    nbytes = sendfile(socket, sr->fd_file, &sr->bytes_offset,
                      sr->bytes_to_send);

    if (nbytes > 0 && sr->loop == 0) {
        mk_socket_set_cork_flag(socket, TCP_CORK_OFF);
    }

    if (nbytes == -1) {
        fprintf(stderr, "error from sendfile: %s\n", strerror(errno));
        return -1;
    }
    else {
        sr->bytes_to_send -= nbytes;
    }

    sr->loop++;
    return sr->bytes_to_send;
}

/* Return data as mk_pointer to be sent
 * in response header 
 */
mk_pointer PutDate_string(time_t date)
{
    int n, size = 32;
    mk_pointer date_gmt;
    struct tm *gmt_tm;

    mk_pointer_reset(&date_gmt);

    if (date == 0) {
        if ((date = time(NULL)) == -1) {
            return date_gmt;
        }
    }

    date_gmt.data = mk_mem_malloc(size);
    gmt_tm = (struct tm *) gmtime(&date);
    n = strftime(date_gmt.data, size - 1, GMT_DATEFORMAT, gmt_tm);
    date_gmt.data[n] = '\0';
    date_gmt.len = n;

    return date_gmt;
}

time_t PutDate_unix(char *date)
{
    time_t new_unix_time;
    struct tm t_data;

    if (!strptime(date, GMT_DATEFORMAT, (struct tm *) &t_data)) {
        return -1;
    }

    new_unix_time = mktime((struct tm *) &t_data);

    return (new_unix_time);
}

int mk_buffer_cat(mk_pointer * p, char *buf1, int len1, char *buf2, int len2)
{
    /* alloc space */
    p->data = (char *) mk_mem_malloc(len1 + len2 + 1);

    /* copy data */
    memcpy(p->data, buf1, len1);
    memcpy(p->data + len1, buf2, len2);
    p->data[len1 + len2] = '\0';

    /* assign len */
    p->len = len1 + len2;

    return 0;
}

char *m_build_buffer(char **buffer, unsigned long *len, const char *format,
                     ...)
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

    if (length >= alloc) {
        ptr = realloc(*buffer, length + 1);
        if (!ptr) {
            va_end(ap);
            return NULL;
        }
        *buffer = ptr;
        alloc = length + 1;
        length = vsnprintf(*buffer, alloc, format, ap);
    }
    va_end(ap);

    if (length < 0) {
        return NULL;
    }

    ptr = *buffer;
    ptr[length] = '\0';
    *len = length;

    return *buffer;
}

/* Run current process in background mode (daemon, evil Monkey >:) */
int mk_utils_set_daemon()
{
    switch (fork()) {
    case 0:
        break;
    case -1:
        exit(1);
        break;                  /* Error */
    default:
        exit(0);                /* Success */
    };

    setsid();                   /* Create new session */
    fclose(stdin);              /* close screen outputs */
    fclose(stderr);
    fclose(stdout);

    return 0;
}

/* If the URI contains hexa format characters it will return 
 * convert the Hexa values to ASCII character 
 */
char *mk_utils_hexuri_to_ascii(mk_pointer uri)
{

    int i, hex_result, aux_char;
    int buf_idx = 0;
    char *buf;
    char hex[3];
    
    if ((i = mk_string_char_search(uri.data, '%', uri.len)) < 0) {
        return NULL;
    }

    buf = mk_mem_malloc_z(uri.len);


    if (i > 0) {
        strncpy(buf, uri.data, i);
        buf_idx = i;
    }

    while (i < uri.len) {
        if (uri.data[i] == '%' && i + 2 < uri.len) {
            memset(hex, '\0', sizeof(hex));
            strncpy(hex, uri.data + i + 1, 2);
            hex[2] = '\0';

            if ((hex_result = hex2int(hex)) <= 127) {
                buf[buf_idx] = toascii(hex_result);
            }
            else {
                if ((aux_char = get_char(hex_result)) != -1) {
                    buf[buf_idx] = aux_char;
                }
                else {
                    mk_mem_free(buf);
                    return NULL;
                }
            }
            i += 2;
        }
        else {
            buf[buf_idx] = uri.data[i];
        }
        i++;
        buf_idx++;
    }
    buf[buf_idx] = '\0';

    return buf;
}

mk_pointer mk_utils_int2mkp(int n)
{
    mk_pointer p;
    char *buf;
    unsigned long len;

    buf = mk_mem_malloc(MK_UTILS_INT2MKP_BUFFER_LEN);
    len = snprintf(buf, MK_UTILS_INT2MKP_BUFFER_LEN, "%i\r\n", n);

    p.data = buf;
    p.len = len;

    return p;
}

#ifdef TRACE
#include <sys/time.h>
void mk_utils_trace(const char *component, int color, const char *function, 
                    char *file, int line, const char* format, ...)
{
    va_list args;
    char *color_function = NULL;
    char *color_fileline = NULL;

    struct timeval tv;
    struct timezone tz;

    if (envtrace) {
        if (!strstr(envtrace, file)) {
            return;
        }
    }

    gettimeofday(&tv, &tz);
 
    /* Switch message color */
    switch(color) {
    case MK_TRACE_CORE:
        color_function = ANSI_YELLOW;
        color_fileline = ANSI_WHITE;
        break;
    case MK_TRACE_PLUGIN:
        color_function = ANSI_BLUE;
        color_fileline = ANSI_WHITE;
        break;
    }

    va_start( args, format );

    fprintf(stderr, "~ %s%2i.%i%s %s%s[%s%s%s%s%s|%s:%i%s] %s%s():%s ", 
            ANSI_CYAN, (int) (tv.tv_sec - monkey_init_time), (int) tv.tv_usec, ANSI_RESET,
            ANSI_MAGENTA, ANSI_BOLD, 
            ANSI_RESET, ANSI_BOLD, ANSI_GREEN, component, color_fileline, file,
            line, ANSI_MAGENTA, 
            color_function, function, ANSI_RED);
    vfprintf( stderr, format, args );
    va_end( args );
    fprintf( stderr, "%s\n", ANSI_RESET);
}
#endif

/* Get SOMAXCONN value. Based on sysctl manpage */
int mk_utils_get_somaxconn() {
	int size;
    int name[] = { CTL_NET, NET_CORE, NET_CORE_SOMAXCONN };
    int value;
    size_t value_len;
    
	size = sizeof(name) / sizeof(name[0]);
    value_len = sizeof(value);

    if (sysctl(name, size, &value, &value_len, NULL, 0)) {
        perror("sysctl");
        return MK_UTILS_SOMAXCONN_DEFAULT;
    }
 
    return value;
}
