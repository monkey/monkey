/*  MonkeyD
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
#include <string.h>

#include <mk_common.h>

mk_queue *mk_common_queue()
{
	mk_queue *new;

	new = malloc(sizeof(mk_queue));
	if(!new)
		/* Here a log message */
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

inline void mk_common_list_init(mk_list *l)
{
	memset(l, 0, sizeof(mk_list));
}

/* For dynamically assigned list */
mk_list *mk_common_list()
{
	mk_list *new;

	new = malloc(sizeof(mk_list));
	if(!new)
		/* Here a log message */
		return NULL;

	mk_common_list_init(new);
	return new;
}

int mk_common_list_add(mk_list *l, void *data)
{
	mk_list_node *node;

	if(!l)
		return MK_ERROR;

	node = malloc(sizeof(mk_list_node));
	if(!node || !data)
		/* Here a log message */
		return MK_ERROR;

	node->data = data;
	node->next = NULL;
	node->prev = l->tail;

	if(l->tail)
		l->tail->next = node;
	else
		l->head = node;
	l->tail = node;

	return MK_OK;
}

void *mk_common_list_remove(mk_list *l, mk_list_node *node)
{
	void *data;

	if(!l || !node)
		return NULL;

	if(node->next)
		node->next->prev = node->prev;
	if(node->prev)
		node->prev->next = node->next;

	if(l->head == node)
		l->head = node->next;
	if(l->tail == node)
		l->tail = node->prev;

	data = node->data;
	free(node);

	return data;
}

void *mk_common_list_find(mk_list *l, int (*cmp)(void *a, void *b), void *a)
{
	mk_list_node *node;

	if(!l || !cmp || !a)
		return NULL;

	for(node = l->head; node != NULL; node = node->next)
		if(cmp(a, node->data))
			return node;

	return NULL;
}

mk_list_node *mk_common_list_rfind(mk_list *l, int (*cmp)(void *a, void *b), void *a)
{
	mk_list_node *node;

	if(!l || !cmp || !a)
		return NULL;

	for(node = l->tail; node != NULL; node = node->prev)
		if(cmp(a, node->data))
			return node;

	return NULL;
}
