/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
 *  Copyright (C) 2011 Davidlohr Bueso <dave@gnu.org>
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
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "monkey.h"
#include "mk_mimetype.h"
#include "mk_memory.h"
#include "mk_string.h"
#include "mk_utils.h"
#include "mk_config.h"
#include "mk_request.h"
#include "mk_list.h"
#include "mk_macros.h"

/* amount of the top used mime types */
#define MIME_COMMON 10

static struct mimetype *mimecommon = NULL; /* old top used mime types */
static struct mimetype *mimearr = NULL; /* old the rest of the mime types */
static int nitem = 0; /* amount of available mime types */

/* add an item to the mimecommon or mimearr variables */
#define add_mime(item, m) ({                                            \
    m = (nitem==0) ? mk_mem_malloc(sizeof(struct mimetype)) :           \
        mk_mem_realloc(m, (nitem + 1) * (sizeof(struct mimetype)));     \
    m[nitem++] = item;                                                  \
})

static int mime_cmp(const void *m1, const void *m2)
{
    struct mimetype *mi1 = (struct mimetype *) m1;
    struct mimetype *mi2 = (struct mimetype *) m2;

    return strcmp(mi1->name, mi2->name);
}

/* Match mime type for requested resource */
static inline struct mimetype *mk_mimetype_lookup(char *name)
{
    int i;
    struct mimetype tmp;

    /*
     * Simple heuristic to guess which mime type to load,
     * based on the type, let's face it, most of the time you
     * are requesting html/css/ or images!
     *
     * First apply lineal search to the 10 most used mimes,
     * otherwise apply a binary search
     */
    for (i = 0; i < MIME_COMMON; i++) {
        if (!strcasecmp(name, mimecommon[i].name)) {
            return &mimecommon[i];
        }
    }

    tmp.name = name;
    return bsearch(&tmp, mimearr, nitem, sizeof(struct mimetype), mime_cmp);
}

static int mk_mimetype_add(char *name, char *type, int common)
{
    int len = strlen(type) + 3;
    struct mimetype new_mime;

    new_mime.name = mk_string_dup(name);
    new_mime.type.data = mk_mem_malloc(len);
    new_mime.type.len = len - 1;
    strcpy(new_mime.type.data, type);
    strcat(new_mime.type.data, MK_CRLF);
    new_mime.type.data[len-1] = '\0';

    /* add the newly created item to the end of the array */
    common ? add_mime(new_mime, mimecommon) : add_mime(new_mime, mimearr);

    return 0;
}

/* Load the two mime arrays into memory */
void mk_mimetype_read_config()
{
    char path[MAX_PATH];
    int i = 0;
    struct mk_config *cnf;
    struct mk_config_section *section;
    struct mk_config_entry *entry;
    struct mk_list *head;

    /* Read mime types configuration file */
    snprintf(path, MAX_PATH, "%s/monkey.mime", config->serverconf);
    cnf = mk_config_create(path);

    /* Get MimeTypes tag */
    section = mk_config_section_get(cnf, "MIMETYPES");
    if (!section) {
        mk_err("Error: Invalid mime type file");
    }

    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_config_entry, _head);

        if (i < MIME_COMMON) {
            if (mk_mimetype_add(entry->key, entry->val, 1) != 0) {
                mk_err("Error loading Mime Types");
            }
        }
        else {
            if (i == MIME_COMMON) {
                nitem = 0; /* reset counter */
            }
            if (mk_mimetype_add(entry->key, entry->val, 0) != 0) {
                mk_err("Error loading Mime Types");
            }
        }
        i++;
    }


    /* sort ascendingly for later binary search */
    qsort(mimearr, nitem, sizeof(struct mimetype), mime_cmp);

    /* Set default mime type */
    mimetype_default = mk_mem_malloc_z(sizeof(struct mimetype));
    mimetype_default->name = MIMETYPE_DEFAULT_TYPE;
    mk_pointer_set(&mimetype_default->type, config->default_mimetype);

    mk_config_free(cnf);
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

    return mk_mimetype_lookup(filename->data + j + 1);
}
