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

#include "duda_package.h"
#include "json.h"

struct duda_api_json *get_json_api()
{
    struct duda_api_json *json;

    /* Alloc object */
    json = malloc(sizeof(struct duda_api_json));

    /* Map API calls */
    json->create_null       = cJSON_CreateNull;
    json->create_true       = cJSON_CreateTrue;
    json->create_false      = cJSON_CreateFalse;
    json->create_bool       = cJSON_CreateBool;
    json->create_number     = cJSON_CreateNumber;
    json->create_string     = cJSON_CreateString;
    json->create_array      = cJSON_CreateArray;
    json->create_object     = cJSON_CreateObject;

    json->add_to_array      = cJSON_AddItemToArray;
    json->add_to_object     = cJSON_AddItemToObject;

    json->parse             = cJSON_Parse;
    json->print             = cJSON_Print;
    json->print_unformatted = cJSON_PrintUnformatted;
    json->delete            = cJSON_Delete;
    json->array_size        = cJSON_GetArraySize;
    json->array_item        = cJSON_GetArrayItem;
    json->object_item       = cJSON_GetObjectItem;
    json->get_error         = cJSON_GetErrorPtr;

    return json;
}

duda_package_t *init_duda_package()
{
    duda_package_t *dpkg = malloc(sizeof(duda_package_t));

    dpkg->name = "json";
    dpkg->version = "0.1";
    dpkg->api = get_json_api();

    return dpkg;
}
