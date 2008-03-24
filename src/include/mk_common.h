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

#ifndef MK_COMMON_H
#define MK_COMMON_H

#define MK_OK		0
#define MK_ERROR 	-1

typedef struct __mk_queue_node {
	void *data;
	struct __mk_queue_node *next;
} mk_queue_node;

typedef struct {
	mk_queue_node *head;
	mk_queue_node *tail;
} mk_queue;

typedef struct __mk_list_node {
	void *data;
	struct __mk_list_node *next;
	struct __mk_list_node *prev;
} mk_list_node;

typedef struct {
	mk_list_node *head;
	mk_list_node *tail;
} mk_list;

mk_queue *mk_common_queue();
int mk_common_enqueue(mk_queue *q, void *d);
void *mk_common_dequeue(mk_queue *q);

inline void mk_common_list_init(mk_list *l);
mk_list *mk_common_list();
int mk_common_list_add(mk_list *l, void *data);
void *mk_common_list_remove(mk_list *l, mk_list_node *node);
void *mk_common_list_find(mk_list *l, int (*cmp)(void *a, void *b), void *a);
mk_list_node *mk_common_list_rfind(mk_list *l, int (*cmp)(void *a, void *b), void *a);

#endif
