/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

#include "MKPlugin.h"
#include "duda.h"
#include "duda_api.h"

/* callback for /app/console/debug */
void duda_console_cb_debug(duda_request_t *dr)
{
    _http_status(dr, 200);
    _http_header(dr, "Content-Type: text/plain", 24);
    _sendfile_enqueue(dr, "/tmp/duda.console");
    _end_response(dr, NULL);
}

void duda_console_write(duda_request_t *dr, char *file, int line, char *format, ...)
{
    int fd;
    int buf_size = 1024;
    char buf[buf_size];
    mk_pointer *now;

    /* Guess we need no more than 100 bytes. */
    int n, size = 128;
    char *p, *np;
    va_list ap;

    if ((p = mk_api->mem_alloc(size)) == NULL) {
        return;
    }

    while (1) {
        /* Try to print in the allocated space. */
        va_start(ap, format);
        n = vsnprintf(p, size, format, ap);
        va_end(ap);
        /* If that worked, return the string. */
        if (n > -1 && n < size)
            break;

        size *= 2;  /* twice the old size */
        if ((np = realloc (p, size)) == NULL) {
            free(p);
            return;
        } else {
            p = np;
        }
    }


    fd = open("/tmp/duda.console", O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
    }

    now = mk_api->time_human();
    n = snprintf(buf, buf_size, "%s [fd=%i req=%p] [%s:%i] %s\n", now->data, dr->cs->socket,
                 dr, file, line, p);
    write(fd, buf, n);
    close(fd);

    mk_api->mem_free(p);
}
