/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2010-2011, Jonathan Gonzalez V. <zeus@gnu.org>
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

#ifndef LIANA_SSL_H_
#define LIANA_SSL_H_

#include <matrixssl/matrixsslApi.h>
#include <matrixssl/version.h>

struct mk_liana_ssl
{
    ssl_t *ssl;
    int socket_fd;
    struct mk_list cons;
};

#define MK_MATRIX_REQUIRE_MAJOR 3
#define MK_MATRIX_REQUIRE_MINOR 2
#define MK_MATRIX_REQUIRE_PATCH 0

int liana_ssl_handshake(struct mk_liana_ssl *conn);

char *config_dir;

#endif /* !LIANA_SSL_H_ */
