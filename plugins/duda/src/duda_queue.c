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
#include "duda_event.h"
#include "duda_queue.h"
#include "duda_sendfile.h"
#include "duda_body_buffer.h"

struct duda_queue_item *duda_queue_item_new(short int type)
{
    struct duda_queue_item *item;

    item = mk_api->mem_alloc(sizeof(struct duda_queue_item));
    if (!item) {
        return NULL;
    }

    item->type   = type;
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

unsigned long duda_queue_length(struct mk_list *queue)
{
    long int length = 0;
    struct mk_list *head;
    struct duda_queue_item *entry;
    struct duda_sendfile *entry_sf;
    struct duda_body_buffer *entry_bb;

    mk_list_foreach(head, queue) {
        entry = mk_list_entry(head, struct duda_queue_item, _head);
        if (entry->type == DUDA_QTYPE_BODY_BUFFER) {
            entry_bb = (struct duda_body_buffer *) entry->data;
            length += entry_bb->buf->total_len;
        }
        else if(entry->type == DUDA_QTYPE_SENDFILE) {
            entry_sf = (struct duda_sendfile *) entry->data;
            length += entry_sf->pending_bytes;
        }
    }

    return length;
}

int duda_queue_flush(duda_request_t *dr)
{
    int ret = -1;
    int socket = dr->cs->socket;
    short int is_registered;
    unsigned long queue_len=0;
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
        case DUDA_QTYPE_SENDFILE:
            ret = duda_sendfile_flush(socket, item->data);
            break;
        }

        if (ret == 0) {
            item->status = DUDA_QSTATUS_INACTIVE;
        }

        is_registered = duda_event_is_registered_write(dr);
        queue_len = duda_queue_length(&dr->queue_out);

        if (queue_len > 0 && is_registered == MK_FALSE) {
            duda_event_register_write(dr);
        }
        else if (queue_len == 0 && is_registered == MK_TRUE) {
            duda_event_unregister_write(dr);
        }
        break;
    }

    return queue_len;
}

int duda_queue_free(struct mk_list *queue)
{
    struct mk_list *head, *temp;
    struct duda_queue_item *item;
    struct duda_sendfile *sf;
    struct duda_body_buffer *bb;

    mk_list_foreach_safe(head, temp, queue) {
        item = mk_list_entry(head, struct duda_queue_item, _head);
        if (item->type == DUDA_QTYPE_BODY_BUFFER) {
            bb = (struct duda_body_buffer *) item->data;
            mk_api->iov_free(bb->buf);
            mk_api->mem_free(bb);
        }
        else if(item->type == DUDA_QTYPE_SENDFILE) {
            sf = (struct duda_sendfile *) item->data;
            close(sf->fd);
            mk_api->mem_free(sf);
        }
        item->data = NULL;
        mk_list_del(head);
        mk_api->mem_free(item);
    }

    return 0;
}
