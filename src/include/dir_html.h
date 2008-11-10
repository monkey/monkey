/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

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
#define MK_DIRHTML_TPL_HEADER {"%_html_title_%"}
#define MK_DIRHTML_TPL_ENTRY {\
        "%_target_title_%",   \
        "%_target_url_%",\
        "%_target_name_%",\
        "%_target_time_%",\
        "%_target_size_%"}

#define MK_DIRHTML_TPL_FOOTER {}

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
};

struct dirhtml_template *mk_dirhtml_tpl_header;
struct dirhtml_template *mk_dirhtml_tpl_entry;
struct dirhtml_template *mk_dirhtml_tpl_footer;

/* length counters */
unsigned long mk_dirhtml_tpl_header_cnt;
unsigned long mk_dirhtml_tpl_entry_cnt;
unsigned long mk_dirhtml_tpl_footer_cnt;

struct dirhtml_tplval
{
        int tag;
        int len;
        int sep; /* separator code after value */
        char *value;
        struct dirhtml_tplval *next;
};

char   *check_string(char *str);
char   *read_header_footer_file(char *file_path);

int mk_dirhtml_conf();
char *mk_dirhtml_load_file(char *filename);
struct dirhtml_template *mk_dirhtml_theme_parse(char *content, char *tpl[]);
struct dirhtml_template *mk_dirhtml_template_list_add(struct dirhtml_template **header, 
                                                      char *buf, int len, int tag);

int mk_dirhtml_init(struct client_request *cr, struct request *sr);
int mk_dirhtml_read_config(char *path);
int mk_dirhtml_theme_load();

struct f_list *get_dir_content(struct request *sr, char *path);

#endif
