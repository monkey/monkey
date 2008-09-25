/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2008, Eduardo Silva P.
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

/* dir_html.c */
#ifndef MK_DIRHTML_H
#define MK_DIRHTML_H

/* For every directory requested, don't send more than
 * this limit of entries.
 */
#define MK_DIRHTML_BUFFER_LIMIT 30

#define MK_HEADER_CHUNKED "Transfer-Encoding: Chunked\r\n\r\n"

struct dirhtml_config
{
        char *theme;
};

struct dirhtml_config *dirhtml_conf;

int  GetDir(struct client_request *cr, struct request *sr);
char   *check_string(char *str);
char   *read_header_footer_file(char *file_path);

int mk_dirhtml_conf();
int mk_dirhtml_init(struct client_request *cr, struct request *sr);
struct f_list *get_dir_content(struct request *sr, char *path);

#endif
