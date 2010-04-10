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

/* Load mimetypes */
void mk_mimetype_read_config()
{
    char path[MAX_PATH];
    struct mk_config *c;

    snprintf(path, MAX_PATH, "%s/monkey.mime", config->serverconf);
    c = mk_config_create(path);

    while (c) {
        if (mk_mimetype_add(c->key, c->val, NULL) != 0) {
            puts("Error loading Mime Types");
        }
        c = c->next;
    }

    mk_config_free(c);

    /* Set default mime type */
    mimetype_default = mk_mem_malloc_z(sizeof(struct mimetype));
    mimetype_default->name = MIMETYPE_DEFAULT_NAME;
    mk_pointer_set(&mimetype_default->type, MIMETYPE_DEFAULT_TYPE);
    mimetype_default->script_bin_path = NULL;
    mimetype_default->next = NULL;
}

int mk_mimetype_add(char *name, char *type, char *bin_path)
{
    int len;
    struct mimetype *new_mime, *aux_mime;

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
    new_mime->next = NULL;

    /* Free incoming type, 'name' is not freed as it's used in 
     * the main mimetype list
     */
    mk_mem_free(type);

    if (first_mime == NULL) {
        first_mime = new_mime;
    }
    else {
        aux_mime = first_mime;
        while (aux_mime->next != NULL) {
            aux_mime = aux_mime->next;
        }
        aux_mime->next = new_mime;
    }
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
    struct mimetype *aux_mime;

    aux_mime = first_mime;
    while (aux_mime != NULL) {
        if (strcasecmp(aux_mime->name, name) == 0) {
            return aux_mime;
        }
        else
            aux_mime = aux_mime->next;
    }

    return NULL;
}

int mk_mimetype_free(char **arr)
{
    mk_mem_free(arr);
    return 0;
}
