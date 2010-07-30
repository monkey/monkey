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

#ifndef MK_UTILS_H
#define MK_UTILS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#define TRUE 1
#define FALSE 0

#define MK_UTILS_INT2MKP_BUFFER_LEN 16    /* Maximum buffer length when
                                           * converting an int to mk_pointer */

#define MK_UTILS_SOMAXCONN_DEFAULT 1024   /* Default for SOMAXCONN value */

#include "request.h"
#include "memory.h"
#include "list.h"

#define INTSIZE sizeof(int)

#ifdef TRACE

#define MK_TRACE_CORE 0
#define MK_TRACE_PLUGIN 1
#define MK_TRACE_COMP_CORE "core"

#define MK_TRACE(...) mk_utils_trace(MK_TRACE_COMP_CORE, MK_TRACE_CORE, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#include "plugin.h"
#define PLUGIN_TRACE(...) mk_api->trace("FIXME", MK_TRACE_PLUGIN, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define ANSI_BOLD "\033[1m"
#define ANSI_CYAN "\033[36m" 
#define ANSI_MAGENTA "\033[35m"
#define ANSI_RED "\033[31m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_BLUE "\033[34m"
#define ANSI_GREEN "\033[32m"
#define ANSI_WHITE "\033[37m"
#define ANSI_RESET "\033[0m"

char *envtrace;
pthread_mutex_t mutex_trace;

#endif

/* utils.c */
int hex2int(char *pChars);

int mk_utils_utime2gmt(mk_pointer **p, time_t date);
time_t PutDate_unix(char *date);

int mk_buffer_cat(mk_pointer * p, char *buf1, int len1, char *buf2, int len2);

int mk_utils_set_daemon();
char *mk_utils_hexuri_to_ascii(mk_pointer req_uri);

#ifdef TRACE
void mk_utils_trace(const char *component, int color, const char *function, 
                    char *file, int line, const char* format, ...);
#endif

int mk_utils_get_somaxconn();
int mk_utils_register_pid();
int mk_utils_remove_pid();

#endif
