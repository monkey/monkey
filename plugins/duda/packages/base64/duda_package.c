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

#include <stdlib.h>

#include "duda_package.h"
#include "base64.h"

struct duda_api_base64 *get_base64_api()
{
    struct duda_api_base64 *base64;

    /* Alloc object */
    base64 = malloc(sizeof(struct duda_api_base64));

    /* Map API calls */
    base64->encode = base64_encode;
    base64->decode = base64_decode;

    return base64;
}

duda_package_t *init_duda_package()
{
    duda_package_t *dpkg = malloc(sizeof(duda_package_t));

    dpkg->name = "base64";
    dpkg->version = "0.1";
    dpkg->api = get_base64_api();

    return dpkg;
}
