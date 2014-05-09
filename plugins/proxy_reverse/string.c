/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
 *  Copyright (C) 2013, Nikola Nikov
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

#include <stdlib.h>
#include <string.h>

#include "types.h"

struct string *string_alloc(const char *data, size_t length)
{
    struct string *result =
        mk_api->mem_alloc(sizeof(struct string) +
                          sizeof(char) * (length + 1));
    if (!result) {
        return 0;
    }
    result->data = (char *) (result + 1);
    result->length = length;
    if (data) {
        memcpy(result->data, data, length);
    }
    result->data[length] = 0;
    return result;
}
