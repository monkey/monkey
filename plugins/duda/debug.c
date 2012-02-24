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

#include "MKPlugin.h"
#include "webservice.h"

#include "stdio.h"
#include "stdarg.h"
#include "time.h"

void _duda_debug_header(int type)
{
    time_t now;
    struct tm *current;

    char *header_color = NULL;
    char *header_title = NULL;

    switch (type) {
    case MK_INFO:
        header_title = "Info";
        header_color = ANSI_GREEN;
        break;
    case MK_ERR:
        header_title = "Error";
        header_color = ANSI_RED;
        break;
    case MK_WARN:
        header_title = "Warning";
        header_color = ANSI_YELLOW;
        break;
    case MK_BUG:
        header_title = " BUG !";
        header_color = ANSI_BOLD ANSI_RED;
    }

    now = time(NULL);
    current = localtime(&now);
    printf("%s[%s%i/%02i/%02i %02i:%02i:%02i%s]%s ",
           ANSI_BOLD, ANSI_RESET,
           current->tm_year + 1900,
           current->tm_mon + 1,
           current->tm_mday,
           current->tm_hour,
           current->tm_min,
           current->tm_sec,
           ANSI_BOLD, ANSI_RESET);

    printf("%s[%s%7s%s]%s ",
           ANSI_BOLD, header_color, header_title, ANSI_WHITE, ANSI_RESET);
}

void _duda_debug_footer()
{
    printf("%s\n", ANSI_RESET);
    fflush(stdout);
}

void duda_debug_info(const char *format, ...)
{
    va_list args;

    _duda_debug_header(MK_INFO);

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    _duda_debug_footer();
}

void duda_debug_warn(const char *format, ...)
{
    va_list args;

    _duda_debug_header(MK_WARN);

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    _duda_debug_footer();
}

void duda_debug_err(const char *format, ...)
{
    va_list args;

    _duda_debug_header(MK_ERR);

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    _duda_debug_footer();
}

void duda_debug_bug(const char *format, ...)
{
    va_list args;

    _duda_debug_header(MK_BUG);

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    _duda_debug_footer();
}

