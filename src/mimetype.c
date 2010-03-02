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
#include "monkey.h"

/* Carga en estructura los mimetypes */
void mk_mimetype_read_config()
{
    char buffer[255], path[MAX_PATH];
    char *name = 0, *type = 0, *last = 0;
    FILE *mime_file;

    snprintf(path, MAX_PATH, "%s/monkey.mime", config->serverconf);

    if ((mime_file = fopen(path, "r")) == NULL) {
        puts("Error: I can't open monkey.mime file");
        exit(1);
    }

    /* Rutina que carga en memoria los mime types */
    while (fgets(buffer, 255, mime_file)) {
        int len;
        len = strlen(buffer);
        if (buffer[len - 1] == '\n') {
            buffer[--len] = 0;
            if (len && buffer[len - 1] == '\r')
                buffer[--len] = 0;
        }

        name = strtok_r(buffer, "\"\t ", &last);
        type = strtok_r(NULL, "\"\t ", &last);

        if (!name || !type)
            continue;
        if (buffer[0] == '#')
            continue;

        if (mk_mimetype_add(name, type, NULL) != 0)
            puts("Error loading Mime Types");
    }
    fclose(mime_file);

    /* Set default mime type */
    mimetype_default = mk_mem_malloc_z(sizeof(struct mimetype));
    mimetype_default->name = MIMETYPE_DEFAULT_NAME;
    mk_pointer_set(&mimetype_default->type, MIMETYPE_DEFAULT_TYPE);
    mimetype_default->script_bin_path = NULL;
    mimetype_default->next = NULL;
}

int mk_mimetype_add(char *name, char *type, char *bin_path)
{

    struct mimetype *new_mime, *aux_mime;

    new_mime = mk_mem_malloc_z(sizeof(struct mimetype));

    new_mime->name = mk_string_dup(name);
    mk_pointer_set(&new_mime->type, mk_string_dup(type));
    new_mime->script_bin_path = mk_string_dup(bin_path);

    new_mime->next = NULL;

    if (first_mime == NULL)
        first_mime = new_mime;
    else {
        aux_mime = first_mime;
        while (aux_mime->next != NULL)
            aux_mime = aux_mime->next;
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

/* Busca mime type segun Request */
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
