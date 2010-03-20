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
#include <unistd.h>

#define TRUE 1
#define FALSE 0

#define MK_UTILS_INT2MKP_BUFFER_LEN 16    /* Maximum buffer length when
                                           * converting an int to mk_pointer */

#include "request.h"
#include "memory.h"

#ifdef TRACE

#define MK_TRACE_CORE 0
#define MK_TRACE_PLUGIN 1
#define MK_TRACE_COMP_CORE "core"

#define MK_TRACE(...) mk_utils_trace(MK_TRACE_COMP_CORE, MK_TRACE_CORE, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define PLUGIN_TRACE(...) mk_api->trace(_shortname, MK_TRACE_PLUGIN, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

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

#endif

/* utils.c */
int SendFile(int socket, struct client_request *cr, struct request *request);
int AccessFile(struct stat file);
int ExecFile(char *pathfile);
int hex2int(char *pChars);
char *strstr2(char *s, char *t);

mk_pointer PutDate_string(time_t date);

time_t PutDate_unix(char *date);

char *get_name_protocol(int remote_protocol);

char *m_build_buffer(char **buffer, unsigned long *len, const char *format,
                     ...);

int mk_buffer_cat(mk_pointer * p, char *buf1, int len1, char *buf2, int len2);

#define SYML_NOT -1
#define SYML_OK 0
#define SYML_VAR_OFF 1
#define SYML_ERR_NOTFOUND 2
#define SYML_ERR_FORBIDDEN 3

int Check_symlink(const char *path);
char *get_end_position(char *buf);

int mk_utils_set_daemon();
mk_pointer mk_utils_int2mkp(int n);
char *mk_utils_hexuri_to_ascii(mk_pointer req_uri);

#ifdef TRACE
void mk_utils_trace(const char *component, int color, const char *function, 
                    char *file, int line, const char* format, ...);
#endif

#endif
