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
#include "mk_socket.h"
#include "mk_memory.h"
#include "mk_stream.h"

/* Create a new stream instance */
mk_stream_t *mk_stream_new(int type, mk_channel_t *channel, void *data,
                           void (*cb_finished) (mk_stream_t *),
                           void (*cb_bytes_consumed) (mk_stream_t *, long),
                           void (*cb_exception) (mk_stream_t *, int))
{
    mk_stream_t *stream;

    stream = mk_mem_malloc(sizeof(mk_stream_t));
    mk_stream_set(stream, type, channel, data, cb_finished, cb_bytes_consumed, cb_exception);

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
    size_t bytes = -1;
    struct mk_iov *iov;
    mk_stream_t *stream;

    if (mk_list_is_empty(&channel->streams) == 0) {
        return MK_CHANNEL_EMPTY;
    }

    /* Get the input source */
    stream = mk_list_entry_first(&channel->streams, mk_stream_t, _head);

    /*
     * Based on the Stream type we consume on that way, not all inputs
     * requires to read from buffer, e.g: Static File, Pipes.
     */
    if (channel->type == MK_CHANNEL_SOCKET) {
        if (stream->type == MK_STREAM_FILE) {
            /* Direct write */
            bytes = mk_socket_send_file(channel->fd,
                                        stream->fd,
                                        &stream->bytes_offset,
                                        stream->bytes_total
                                        );
        }
        else if (stream->type == MK_STREAM_IOV) {
            iov   = stream->data;
            bytes = mk_socket_sendv(channel->fd, iov);

            if (bytes > 0) {
                /* Perform the adjustment on mk_iov */
                mk_iov_consume(iov, bytes);
            }
        }

        if (bytes > 0) {
            mk_stream_bytes_consumed(stream, bytes);

            /* notification callback, optional */
            if (stream->cb_bytes_consumed) {
                stream->cb_bytes_consumed(stream, bytes);
            }

            if (stream->bytes_total == 0) {
                if (stream->cb_finished) {
                    stream->cb_finished(stream);
                }
                mk_stream_unlink(stream);
            }

            return MK_CHANNEL_FLUSH;
        }
        else if (bytes <= 0) {
            if (stream->cb_exception) {
                stream->cb_exception(stream, errno);
            }
            return MK_CHANNEL_ERROR;
        }
    }

    return MK_CHANNEL_UNKNOWN;
}
