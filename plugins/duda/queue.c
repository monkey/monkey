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

#include "MKPlugin.h"

#include "duda.h"
#include "body_buffer.h"
#include "queue.h"

struct duda_queue_item *duda_queue_item_new(short int type)
{
    struct duda_queue_item *item;

    item = mk_api->mem_alloc(sizeof(struct duda_queue_item));
    if (!item) {
        return NULL;
    }

    item->type = type;
    item->status = DUDA_QSTATUS_ACTIVE;

    return item;
}

int duda_queue_add(struct duda_queue_item *item, struct mk_list *queue)
{
    mk_list_add(&item->_head, queue);
    return 0;
}

struct duda_queue_item *duda_queue_last(struct mk_list *queue)
{
    struct duda_queue_item *item;

    item = mk_list_entry_last(queue, struct duda_queue_item, _head);
    return item;
}

long int duda_queue_length(struct mk_list *queue)
{
    long int length = 0;
    struct mk_list *head;
    struct duda_queue_item *entry;
    struct duda_body_buffer *entry_bb;

    mk_list_foreach(head, queue) {
        entry = mk_list_entry(head, struct duda_queue_item, _head);
        if (entry->type == DUDA_QTYPE_BODY_BUFFER) {
            entry_bb = (struct duda_body_buffer *) entry->data;
            length += entry_bb->buf->total_len;
        }
    }

    return length;
}

int duda_queue_flush(duda_request_t *dr)
{
    int ret;
    int socket = dr->cs->socket;
    unsigned long bytes_sent = 0;
    struct mk_list *head;
    struct duda_queue_item *item;

    mk_list_foreach(head, &dr->queue_out) {
        item = mk_list_entry(head, struct duda_queue_item, _head);
        if (item->status == DUDA_QSTATUS_INACTIVE) {
            continue;
        }

        switch (item->type) {
        case DUDA_QTYPE_BODY_BUFFER:
            ret = duda_body_buffer_flush(socket, item->data);
            break;
        }

        if (ret == 0) {
            item->status = DUDA_QSTATUS_INACTIVE;
        }
        break;
    }

    return bytes_sent;
}
