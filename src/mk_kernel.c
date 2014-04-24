/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2014, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public  License as published
 *  by the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 *  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 *  License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <ctype.h>
#include <pthread.h>
#include <sys/utsname.h>

#include "mk_kernel.h"
#include "mk_string.h"
#include "mk_utils.h"

int mk_kernel_version()
{
    int a, b, c;
    int len;
    int pos;
    char *p, *t;
    char *tmp;
    struct utsname uts;

    if (uname(&uts) == -1) {
        mk_libc_error("uname");
    }

    len = strlen(uts.release);

    /* Fixme: this don't support Linux Kernel 10.x.x :P */
    a = (*uts.release - '0');

    /* Second number */
    p = (uts.release) + 2;
    pos = mk_string_char_search(p, '.', len - 2);
    if (pos <= 0) {
        return -1;
    }

    tmp = mk_string_copy_substr(p, 0, pos);
    if (!tmp) {
        return -1;
    }
    b = atoi(tmp);
    mk_mem_free(tmp);

    /* Last number (it needs filtering) */
    t = p = p + pos + 1;
    do {
        t++;
    } while (isdigit(*t));

    tmp = mk_string_copy_substr(p, 0, t - p);
    if (!tmp) {
        return -1;
    }
    c = atoi(tmp);
    mk_mem_free(tmp);

    return MK_KERNEL_VERSION(a, b, c);
}
