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
#include "file.h"
#include "str.h"
#include "config.h"
#include "chars.h"
#include "socket.h"
#include "clock.h"
#include "user.h"
#include "cache.h"

/* Date helpers */
const char *mk_date_wd[7] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
const char *mk_date_ym[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
                              "Aug", "Sep", "Oct", "Nov", "Dec"};

/* This function given a unix time, set in a mk_pointer 
 * the date in the RFC1123 format like:
 *
 *    Wed, 23 Jun 2010 22:32:01 GMT
 *
 * it also adds a 'CRLF' at the end
 */
int mk_utils_utime2gmt(mk_pointer **p, time_t date)
{
    int size = 31;
    unsigned int year;
    char *buf=0;
    struct tm *gtm;

    if (date == 0) {
        if ((date = time(NULL)) == -1) {
            return -1;
        }
    }

    /* Convert unix time to struct tm */
    gtm = (struct tm *) gmtime(&date);
    if (!gtm) {
        return -1;
    }

    /* struct tm -> tm_year counts number of years after 1900 */
    year = gtm->tm_year + 1900;
    
    /* Compose template */
    buf = (*p)->data;

    /* Week day */
    *buf++ = mk_date_wd[gtm->tm_wday][0];
    *buf++ = mk_date_wd[gtm->tm_wday][1];
    *buf++ = mk_date_wd[gtm->tm_wday][2];
    *buf++ = ',';
    *buf++ = ' ';

    /* Day of the month */
    *buf++ = ('0' + (gtm->tm_mday / 10));
    *buf++ = ('0' + (gtm->tm_mday % 10));
    *buf++ = ' ';

    /* Year month */
    *buf++ = mk_date_ym[gtm->tm_mon][0];
    *buf++ = mk_date_ym[gtm->tm_mon][1];
    *buf++ = mk_date_ym[gtm->tm_mon][2];
    *buf++ = ' ';

    /* Year */
    *buf++ = ('0' + (year / 1000) % 10);
    *buf++ = ('0' + (year / 100) % 10);
    *buf++ = ('0' + (year / 10) % 10);
    *buf++ = ('0' + (year % 10));
    *buf++ = ' ';

    /* Hour */
    *buf++ = ('0' + (gtm->tm_hour / 10));
    *buf++ = ('0' + (gtm->tm_hour % 10));
    *buf++ = ':';

    /* Minutes */
    *buf++ = ('0' + (gtm->tm_min / 10));
    *buf++ = ('0' + (gtm->tm_min % 10));
    *buf++ = ':';

    /* Seconds */
    *buf++ = ('0' + (gtm->tm_sec / 10));
    *buf++ = ('0' + (gtm->tm_sec % 10));
    *buf++ = ' ';

    /* GMT Time zone + CRLF */
    *buf++ = 'G';
    *buf++ = 'M';
    *buf++ = 'T';
    *buf++ = '\r';
    *buf++ = '\n';
    *buf++ = '\0';
    
    /* Set mk_pointer data len */
    (*p)->len = size;

    return 0;
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

int mk_buffer_cat(mk_pointer *p, char *buf1, int len1, char *buf2, int len2)
{
    /* Validate lengths */
    if (len1 < 0 || len2 < 0) {
         return -1;
    }

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

    /* Mutex lock */
    pthread_mutex_lock(&mutex_trace);

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

    /* Mutex unlock */
    pthread_mutex_unlock(&mutex_trace);

}
#endif

/* Get SOMAXCONN value. Based on sysctl manpage */
int mk_utils_get_somaxconn()
{
    /* sysctl() is deprecated in some systems, you can notice that with some system 
     * messages as: 
     * 
     * '(warning: process `monkey' used the deprecated sysctl system call...'
     *
     * In order to avoid that problem, this function will check the proc filesystem,
     * if it still fails, we will use the default value defined for somaxconn for years...
     */
    int somaxconn = 128;
    char buf[16];
    FILE *f;

    f = fopen("/proc/sys/net/core/somaxconn", "r");
    if(f && fgets(buf, 16, f)) {
        somaxconn = atoi(buf);
        fclose(f);
    }

    return somaxconn;
}

/* Write Monkey's PID */
int mk_utils_register_pid()
{
    FILE *pid_file;

    remove(config->pid_file_path);
    config->pid_status = VAR_OFF;

    if ((pid_file = fopen(config->pid_file_path, "w")) == NULL) {
        mk_error(MK_ERROR_FATAL, "Error: I can't log pid of monkey");
    }

    fprintf(pid_file, "%i", getpid());
    fclose(pid_file);
    config->pid_status = VAR_ON;

    return 0;
}

/* Remove PID file */
int mk_utils_remove_pid()
{
    mk_user_undo_uidgid();
    return remove(config->pid_file_path);
}

void mk_error(int type, const char *format, ...)
{
    char *error_header;
    va_list args;

    va_start(args, format);

    if (type == MK_ERROR_WARNING) {
        error_header = "WARNING";
    }
    else {
        error_header = "Fatal";
    }

    fprintf(stderr, "\n%s[%s%s%s]%s ", 
            ANSI_BOLD, ANSI_RED, error_header, ANSI_WHITE, ANSI_RESET);

    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "%s", ANSI_RESET);
    
    if (type == MK_ERROR_FATAL) {
        fprintf(stderr, "\n");
        exit(1);
    }
}
