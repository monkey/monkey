/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2003, Eduardo Silva P.
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

/* mimetype.c */

/* MIME Structs variables*/

#define MIMETYPE_DEFAULT "text/plain"

#define MAX_MIMETYPES_NOMBRE 15
#define MAX_MIMETYPES_TIPO 55
#define MAX_SCRIPT_BIN_PATH 255

struct mimetype {
	char *name;
	char *type;
	char *script_bin_path;
	struct mimetype *next;	 
} *first_mime;



void mk_mimetype_read_config();

int mk_mimetype_free(char **arr);
int mk_mimetype_add(char *name, char *type, char *bin_path);

struct mimetype *mk_mimetype_find(char *filename);
struct mimetype *mk_mimetype_cmp(char *name);


