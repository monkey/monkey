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

#ifndef MK_STREAM_H
#define MK_STREAM_H

/*
 * Stream types: each stream can have a different
 * source of information and for hence it handler
 * may need to be different for each cases.
 */
#define MK_STREAM_RAW     0  /* raw data from buffer */
#define MK_STREAM_IOV     1  /* mk_iov struct        */
#define MK_STREAM_FILE    2  /* opened file          */
#define MK_STREAM_SOCKET  3  /* socket, scared..     */


/* Channel return values for write event */
#define MK_CHANNEL_EMPTY   0  /* no streams available         */
#define MK_CHANNEL_FLUSH   1  /* channel flushed some data    */
#define MK_CHANNEL_DONE    2  /* channel consumed all streams */
#define MK_CHANNEL_ERROR   3  /* exception when flusing data  */
#define MK_CHANNEL_UNKNOWN 4  /* unhandled                    */

/*
 * Channel types: by default the only channel supported
 * is a direct write to the network layer.
 */
#define MK_CHANNEL_SOCKET 0

/*
 * A channel represents an end-point of a stream, for short
 * where the stream data consumed is send to.
 */
typedef struct {
    int type;
    int fd;
    struct mk_list streams;
} mk_channel_t;

/*
 * A stream represents an Input of data that can be consumed
 * from a specific resource given it's type.
 */
typedef struct mk_stream {
    int type;
    int fd;

    /* bytes info */
    unsigned long bytes_total;
    off_t         bytes_offset;

    /* the outgoing channel */
    mk_channel_t *channel;

    /* callbacks */
    void (*cb_finished) (struct mk_stream *);
    void (*cb_ok) (struct mk_stream *);
    void (*cb_bytes_consumed) (struct mk_stream *, long);
    void (*cb_exception) (struct mk_stream *, int);

    /* Link to the Channel parent */
    struct mk_list _head;
} mk_stream_t;

/* exported functions */
mk_stream_t *mk_stream_new(int type, mk_channel_t *channel,
                           void (*cb_finished) (mk_stream_t *),
                           void (*cb_bytes_consumed) (mk_stream_t *, long),
                           void (*cb_exception) (mk_stream_t *, int));
mk_channel_t *mk_channel_new(int type, int fd);
int mk_channel_write(mk_channel_t *channel);

#endif
