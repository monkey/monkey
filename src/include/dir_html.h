/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2009, Eduardo Silva P.
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

#define MK_DIRHTML_URL "/_mktheme"
#define MK_DIRHTML_DEFAULT_MIME "text/html"

/* For every directory requested, don't send more than
 * this limit of entries.
 */
#define MK_DIRHTML_BUFFER_LIMIT 30
#define MK_DIRHTML_BUFFER_GROW 5

#define MK_HEADER_CHUNKED "Transfer-Encoding: Chunked\r\n\r\n"

/* Theme files */
#define MK_DIRHTML_FILE_HEADER "header.theme"
#define MK_DIRHTML_FILE_ENTRY "entry.theme"
#define MK_DIRHTML_FILE_FOOTER "footer.theme"

/* Template tags */
#define MK_DIRHTML_TPL_GLOBAL {"%_html_title_%", "%_theme_path_%", NULL}

#define MK_DIRHTML_TPL_ENTRY {\
        "%_target_title_%",   \
        "%_target_url_%",\
        "%_target_name_%",\
        "%_target_time_%",\
        "%_target_size_%", NULL}

#define MK_DIRHTML_TAG_INIT "%_"
#define MK_DIRHTML_TAG_END "_%"
#define MK_DIRHTML_SIZE_DIR "-"

/* Main configuration of dirhtml module */
struct dirhtml_config
{
        char *theme;
        char *theme_path;
};

/* Global config */
struct dirhtml_config *dirhtml_conf;

/* Used to keep splitted content of every template */
struct dirhtml_template
{
        char *buf;
        int tag;
        int len;
        struct dirhtml_template *next;
        char **tpl; /* array of theme tags: [%_xaa__%, %_xyz_%] */

        //char *lov_tpl[]; /* template array values, eg: MK_DIRHTML_TPL_GLOBAL */
};

/* Templates for header, entries and footer */
struct dirhtml_template *mk_dirhtml_tpl_header;
struct dirhtml_template *mk_dirhtml_tpl_entry;
struct dirhtml_template *mk_dirhtml_tpl_footer;

struct dirhtml_value
{
        int tag;
        int len;
        mk_pointer sep; /* separator code after value */

        /* string data */
        int len;
        char *value;

        /* next node */
        struct dirhtml_value *next;
};

struct dirhtml_value *mk_dirhtml_value_global;

char   *check_string(char *str);
char   *read_header_footer_file(char *file_path);

int mk_dirhtml_conf();
char *mk_dirhtml_load_file(char *filename);
struct dirhtml_template *mk_dirhtml_theme_parse(char *content, char *extra[]);
struct dirhtml_template *mk_dirhtml_template_list_add(struct dirhtml_template **header, 
                                                      char *buf, int len, 
                                                      char *tpl[], int tag);

int mk_dirhtml_init(struct client_request *cr, struct request *sr);
int mk_dirhtml_read_config(char *path);
int mk_dirhtml_theme_load();
struct dirhtml_value *mk_dirhtml_tag_assign(struct dirhtml_value **values,
                                             int tag_id, mk_pointer sep, 
                                             char *value);

struct f_list *get_dir_content(struct request *sr, char *path);

#endif
