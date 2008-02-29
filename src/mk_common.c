/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2008 Felipe Astroza
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

#include <mk_common.h>

mk_queue *mk_common_queue()
{
	mk_queue *new;

	new = malloc(sizeof(mk_queue));
	if(!new)
		/* Here a message log */
		return NULL;

	new->head = NULL;
	new->tail = NULL;

	return new;
}

int mk_common_enqueue(mk_queue *q, void *d)
{
	mk_queue_node *n;

	if(!q || !d)
		return MK_ERROR;

	n = malloc(sizeof(mk_queue_node));
	if(n == NULL)
		/* Here a log message */
		return MK_ERROR;

	n->next = NULL;
	n->data = d;

	if(q->tail)
		q->tail->next = n;
	else
		q->head = n;
	q->tail = n;

	return MK_OK;
}

void *mk_common_dequeue(mk_queue *q)
{
	void *data;
	mk_queue_node *next;

	if(!q || !q->head)
		return NULL;

	next = q->head->next;
	data = q->head->data;
	free(q->head);

	if(q->tail == q->head)
		q->tail = NULL;

	q->head = next;

	return data;
}
