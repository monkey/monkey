/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
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

#ifndef DUDA_PACKAGE_JSON_H
#define DUDA_PACKAGE_JSON_H

#include "cJSON.h"

typedef cJSON json_t;

struct duda_api_json {
    /* create item types */
    json_t *(*create_null) ();
    json_t *(*create_true) ();
    json_t *(*create_false) ();
    json_t *(*create_bool) ();
    json_t *(*create_number) ();
    json_t *(*create_string) ();
    json_t *(*create_array) ();
    json_t *(*create_object) ();

    /* add to */
    void (*add_to_array) (json_t *, json_t *);
    void (*add_to_object) (json_t *, const char *, json_t *);

    json_t *(*parse) (const char *);
    char   *(*print) (json_t *);
    char   *(*print_unformatted) (json_t *);
    void    (*delete) (json_t *);
    int     (*array_size) (json_t *);
    json_t *(*array_item) (json_t *, int);
    json_t *(*object_item) (json_t *, const char *);
    const char *(*get_error) (void);
};

typedef struct duda_api_json json_object_t;
json_object_t *json;

#endif
