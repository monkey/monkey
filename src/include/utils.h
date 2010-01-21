/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2007, Eduardo Silva P.
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

#ifndef MK_UTILS_H
#define MK_UTILS_H

/* Defining TRUE and FALSE */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define TRUE 1
#define FALSE 0

/* Tipo de envio de datos en fdprintf(...) */
#define CHUNKED 0
#define NO_CHUNKED 1

#include "request.h"
#include "memory.h"

/* utils.c */
int SendFile(int socket, struct client_request *cr, struct request *request);
int AccessFile(struct stat file);
int ExecFile(char *pathfile);
int hex2int(char *pChars);
char *strstr2(char *s, char *t);

mk_pointer PutDate_string(time_t date);

time_t PutDate_unix(char *date);

char *get_real_string(mk_pointer req_uri);

char *get_name_protocol(int remote_protocol);

char *m_build_buffer(char **buffer, unsigned long *len, const char *format,
                     ...);

int mk_buffer_cat(mk_pointer * p, char *buf1, char *buf2);

#define SYML_NOT -1
#define SYML_OK 0
#define SYML_VAR_OFF 1
#define SYML_ERR_NOTFOUND 2
#define SYML_ERR_FORBIDDEN 3

int Check_symlink(const char *path);
char *get_end_position(char *buf);

int mk_utils_set_daemon();
mk_pointer mk_utils_int2mkp(int n);

#endif
