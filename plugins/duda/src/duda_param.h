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

#ifndef DUDA_PARAM_H
#define DUDA_PARAM_H

#include "duda.h"

struct duda_api_param {
    char *(*get)       (duda_request_t *, short int);
    int   (*get_number)(duda_request_t *, short int, long *);
    short int (*count) (duda_request_t *);
    short int (*len)   (duda_request_t *, short int);
};

struct duda_api_param *duda_param_object();
char *duda_param_get(duda_request_t *dr, short int i);
int duda_param_get_number(duda_request_t *dr, short int idx, long *res);
short int duda_param_count(duda_request_t *dr);
short int duda_param_len(duda_request_t *dr, short int idx);

#endif
