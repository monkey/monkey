/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "monkey.h"
#include "mk_mimetype.h"
#include "mk_memory.h"
#include "mk_string.h"
#include "mk_utils.h"
#include "mk_config.h"
#include "mk_request.h"
#include "mk_list.h"
#include "mk_macros.h"
#include "mk_file.h"

struct mimetype *mimetype_default;

/* Match mime type for requested resource */
inline struct mimetype *mk_mimetype_lookup(char *name)
{
    int cmp;
  	struct rb_node *node = mimetype_rb_head.rb_node;

  	while (node) {
  		struct mimetype *entry = container_of(node, struct mimetype, _rb_head);

        cmp = strcmp(name, entry->name);
		if (cmp < 0)
  			node = node->rb_left;
		else if (cmp > 0)
  			node = node->rb_right;
		else {
  			return entry;
        }
	}
	return NULL;
}

int mk_mimetype_add(char *name, const char *type)
{
    int cmp;
    int len = strlen(type) + 3;
    char *p;
    struct mimetype *new_mime;
    struct rb_node **new;
    struct rb_node *parent = NULL;

    /* make sure we register the extension in lower case */
    p = name;
    for ( ; *p; ++p) *p = tolower(*p);

    new_mime = mk_mem_malloc_z(sizeof(struct mimetype));
    new_mime->name = mk_string_dup(name);
    new_mime->type.data = mk_mem_malloc(len);
    new_mime->type.len = len - 1;
    strcpy(new_mime->type.data, type);
    strcat(new_mime->type.data, MK_CRLF);
    new_mime->type.data[len-1] = '\0';

    /* Red-Black tree insert routine */
    new = &(mimetype_rb_head.rb_node);

    /* Figure out where to put new node */
    while (*new) {
        struct mimetype *this = container_of(*new, struct mimetype, _rb_head);

        parent = *new;
        cmp = strcmp(new_mime->name, this->name);
        if (cmp < 0) {
            new = &((*new)->rb_left);
        }
        else if (cmp > 0) {
            new = &((*new)->rb_right);
        }
        else {
            return -1;
        }
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&new_mime->_rb_head, parent, new);
    rb_insert_color(&new_mime->_rb_head, &mimetype_rb_head);

    /* Add to linked list head */
    mk_list_add(&new_mime->_head, &mimetype_list);

    return 0;
}

/* Load the two mime arrays into memory */
void mk_mimetype_read_config()
{
    char path[MK_MAX_PATH];
    struct mk_config *cnf;
    struct mk_config_section *section;
    struct mk_config_entry *entry;
    struct mk_list *head;
    struct file_info f_info;
    int ret;

    /* Initialize the heads */
    mk_list_init(&mimetype_list);
    mimetype_rb_head = RB_ROOT;

    /* Read mime types configuration file */
    snprintf(path, MK_MAX_PATH, "%s/%s", config->serverconf, config->mimes_conf_file);
    ret = mk_file_get_info(path, &f_info);
    if (ret == -1 || f_info.is_file == MK_FALSE)
        snprintf(path, MK_MAX_PATH, "%s", config->mimes_conf_file);

    cnf = mk_config_create(path);
    if (!cnf) {
        exit(EXIT_FAILURE);
    }

    /* Get MimeTypes tag */
    section = mk_config_section_get(cnf, "MIMETYPES");
    if (!section) {
        mk_err("Error: Invalid mime type file");
        exit(EXIT_FAILURE);
    }

    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_config_entry, _head);
        if (!entry->key || !entry->val) {
            continue;
        }

        if (mk_mimetype_add(entry->key, entry->val) != 0) {
            mk_err("Error loading Mime Types");
            exit(EXIT_FAILURE);
        }
    }

    /* Set default mime type */
    mimetype_default = mk_mem_malloc_z(sizeof(struct mimetype));
    mimetype_default->name = MIMETYPE_DEFAULT_TYPE;
    mk_ptr_t_set(&mimetype_default->type, config->default_mimetype);

    mk_config_free(cnf);
}

struct mimetype *mk_mimetype_find(mk_ptr_t *filename)
{
    int j, len;

    j = len = filename->len;

    /* looking for extension */
    while (filename->data[j] != '.' && j >= 0) {
        j--;
    }

    if (j <= 0) {
        return NULL;
    }

    return mk_mimetype_lookup(filename->data + j + 1);
}
