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

/* Defining TRUE and FALSE */
#define TRUE 1
#define FALSE 0

/* Tipo de envio de datos en fdprintf(...) */
#define CHUNKED 0
#define NO_CHUNKED 1

#define DATEFORMAT "%a, %d %b %Y %H:%M:%S GMT"

/* utils.c */
int SendFile(int socket, struct request *request, 
        char *header_range, char *pathfile, int ranges[2]);
int	CheckDir(char *pathfile);
int	CheckFile(char *pathfile);
int	AccessFile(char *pathfile);
int	ExecFile(char *pathfile);
int	set_daemon();
int	fdprintf(int fd, int type, const char *format, ...);
int	fdchunked(int fd, char *data, int length);
int	str_search(char *string, char *search, int length_cmp);
int	hex2int(char *pChars);
char *strstr2(char *s, char *t);

char *PutDate_string(time_t date);
time_t PutDate_unix(char *date);

char *get_real_string(char *req_uri);

int	get_version_protocol(char *remote_protocol);
char  *get_name_protocol(int remote_protocol);

char *m_build_buffer(const char *format, ...);
char *m_build_buffer_from_buffer(char *buffer, const char *format, ...);
char *m_copy_string(const char *string, int pos_init, int pos_end);

void *M_malloc(size_t size);
char *M_strdup(const char *s);
void *M_realloc(void* ptr, size_t size);
void M_free(void *ptr);

#define SYML_NOT -1
#define SYML_OK 0
#define SYML_VAR_OFF 1
#define SYML_ERR_NOTFOUND 2
#define SYML_ERR_FORBIDDEN 3

int Check_symlink(const char *path);
char *get_end_position(char *buf);
char *remove_space(char *buf);

int setnonblocking(int sockfd);
char *mk_strcasestr(char *heystack, char *needle);

