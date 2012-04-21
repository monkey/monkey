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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "MKPlugin.h"
#include "duda_sendfile.h"

struct duda_sendfile *duda_sendfile_new(char *path)
{
    int ret;
    struct duda_sendfile *file;

    file = mk_api->mem_alloc(sizeof(struct duda_sendfile));
    file->fd = -1;

    ret = mk_api->file_get_info(path, &file->info);
    if (ret == -1) {
        mk_api->mem_free(file);
        return NULL;
    }

    if (file->info.read_access == MK_FALSE) {
        mk_warn("Cannot read %s", path);
        mk_api->mem_free(file);
        return NULL;
    }

    file->fd = open(path, O_RDONLY | O_NONBLOCK);
    file->offset = 0;
    file->pending_bytes = file->info.size;
    return file;
}

int duda_sendfile_flush(int socket, struct duda_sendfile *sf)
{
    int bytes;

    bytes = mk_api->socket_send_file(socket, sf->fd,
                                     &sf->offset, sf->pending_bytes);

    if (bytes > 0) {
        sf->pending_bytes -= bytes;
    }
    else if (bytes == -1) {
        return -1;
    }

    return sf->pending_bytes;
}
