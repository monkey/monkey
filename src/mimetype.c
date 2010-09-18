/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "mimetype.h"
#include "memory.h"
#include "str.h"
#include "config.h"
#include "request.h"
#include "monkey.h"
#include "list.h"

/* Load mimetypes */
void mk_mimetype_read_config()
{
    char path[MAX_PATH];

    struct mk_config *cnf;
    struct mk_config_section *section;
    struct mk_config_entry *entry;

    /* Read mime types configuration file */
    snprintf(path, MAX_PATH, "%s/monkey.mime", config->serverconf);
    cnf = mk_config_create(path);

    /* Get MimeTypes tag */
    section = mk_config_section_get(cnf, "MIMETYPES");
    if (!section) {
        puts("Error: Invalid mime type file");
        exit(1);
    }

    /* Alloc and init mk_list header */
    mimetype_list = mk_mem_malloc(sizeof(struct mk_list));
    mk_list_init(mimetype_list);

    entry = section->entry;
    while (entry) {
        if (mk_mimetype_add(entry->key, entry->val) != 0) {
            puts("Error loading Mime Types");
        }
        entry = entry->next;
    }

    /* Set default mime type */
    mimetype_default = mk_mem_malloc_z(sizeof(struct mimetype));
    mimetype_default->name = MIMETYPE_DEFAULT_NAME;
    mk_pointer_set(&mimetype_default->type, MIMETYPE_DEFAULT_TYPE);
}

int mk_mimetype_add(char *name, char *type)
{
    int len;
    struct mimetype *new_mime;

    new_mime = mk_mem_malloc_z(sizeof(struct mimetype));

    new_mime->name = name;

    /* Alloc space */
    len = strlen(type) + 3;
    new_mime->type.data = mk_mem_malloc(len);
    new_mime->type.len = len - 1;

    /* Copy mime type and add CRLF */
    strcpy(new_mime->type.data, type);
    strcat(new_mime->type.data, MK_CRLF);
    new_mime->type.data[len-1] = '\0';

    /* Free incoming type, 'name' is not freed as it's used in 
     * the main mimetype list
     */
    mk_mem_free(type);

    /* Add node to main list */
    mk_list_add(&new_mime->_head, mimetype_list);

    return 0;
}

struct mimetype *mk_mimetype_find(mk_pointer * filename)
{
    int j, len;

    j = len = filename->len;

    /* looking for extension */
    while (filename->data[j] != '.' && j >= 0)
        j--;

    if (j == 0) {
        return NULL;
    }

    return mk_mimetype_cmp(filename->data + j + 1);
}

/* Match mime type for requested resource */
struct mimetype *mk_mimetype_cmp(char *name)
{
    struct mk_list *list_node;
    struct mimetype *aux;

    mk_list_foreach(list_node, mimetype_list) {
        aux = mk_list_entry(list_node, struct mimetype, _head);
        if (strcasecmp(aux->name, name) == 0) {
            return aux;
        }
    }

    return NULL;
}

int mk_mimetype_free(char **arr)
{
    mk_mem_free(arr);
    return 0;
}
