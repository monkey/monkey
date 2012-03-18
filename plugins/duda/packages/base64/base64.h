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

#ifndef DUDA_PACKAGE_BASE64_H
#define DUDA_PACKAGE_BASE64_H
#include <stddef.h>

struct duda_api_base64 {
    unsigned char *(*encode) (const unsigned char *, size_t, size_t *);
    unsigned char *(*decode) (const unsigned char *, size_t, size_t *);
};

typedef struct duda_api_base64 base64_object_t;
base64_object_t *base64;

unsigned char *base64_encode(const unsigned char *src, size_t len,
                             size_t *out_len);
unsigned char *base64_decode(const unsigned char *src, size_t len,
                           size_t *out_len);
#endif
