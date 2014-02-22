/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2014, Eduardo Silva P. <edsiper@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public  License as published
 *  by the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 *  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 *  License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "mk_list.h"
#include "mk_memory.h"
#include "mk_stream.h"

/* Create a new stream instance */
mk_stream_t *mk_stream_new(int type, mk_channel_t *channel)
{
    mk_stream_t *stream;

    stream = mk_mem_malloc(sizeof(mk_stream_t));
    stream->type    = type;
    stream->channel = channel;

    return stream;
}

/* Create a new channel */
mk_channel_t *mk_channel_new(int type, int fd)
{
    mk_channel_t *channel;

    channel = mk_mem_malloc(sizeof(mk_channel_t));
    channel->type = type;
    channel->fd   = fd;
    mk_list_init(&channel->streams);

    return channel;
}

int mk_channel_write(mk_channel_t *channel)
{
    mk_stream_t *stream;

    if (mk_list_is_empty(&channel->streams) == 0) {
        return MK_FALSE;
    }

    stream = mk_list_entry_first(&channel->streams, mk_stream_t, _head);

}
