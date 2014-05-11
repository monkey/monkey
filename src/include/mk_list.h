/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
 *  Copyright (C) 2010, Jonathan Gonzalez V. <zeus@gnu.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef   	MK_LIST_H_
#define   	MK_LIST_H_

#include <stddef.h>

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({                      \
      const typeof( ((type *)0)->member ) *__mptr = (ptr);      \
      (type *)( (char *)__mptr - offsetof(type,member) );})


struct mk_list
{
    struct mk_list *prev, *next;
};

static inline void mk_list_init(struct mk_list *list)
{
    list->next = list;
    list->prev = list;
}

static inline void __mk_list_add(struct mk_list *new, struct mk_list *prev,
                                 struct mk_list *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

static inline void mk_list_add(struct mk_list *new, struct mk_list *head)
{
    __mk_list_add(new, head->prev, head);
}

static inline void __mk_list_del(struct mk_list *prev, struct mk_list *next)
{
    prev->next = next;
    next->prev = prev;
}

static inline void mk_list_del(struct mk_list *entry)
{
    __mk_list_del(entry->prev, entry->next);
    entry->prev = NULL;
    entry->next = NULL;
}

static inline int mk_list_is_empty(struct mk_list *head)
{
    if (head->next == head) return 0;
    else return -1;
}

static inline int mk_list_size(struct mk_list *head)
{
    int ret = 0;
    struct mk_list *it;
    for (it = head->next; it != head; it = it->next, ret++);
    return ret;
}

#define mk_list_foreach(curr, head) for( curr = (head)->next; curr != (head); curr = curr->next )
#define mk_list_foreach_safe(curr, n, head) \
    for (curr = (head)->next, n = curr->next; curr != (head); curr = n, n = curr->next)

#define mk_list_entry( ptr, type, member ) container_of( ptr, type, member )

/*
 * First node of the list
 * ----------------------
 * Be careful with this Macro, its intended to be used when some node is already linked
 * to the list (ptr). If the list is empty it will return the list address as it points
 * to it self: list == list->prev == list->next.
 *
 * If exists some possiblity that your code handle an empty list, use mk_list_is_empty()
 * previously to check if its empty or not.
 */
#define mk_list_entry_first(ptr, type, member) container_of((ptr)->next, type, member)

/* First node of the list
 * ---------------------
 * Be careful with this Macro, its intended to be used when some node is already linked
 * to the list (ptr). If the list is empty it will return the list address as it points
 * to it self: list == list->prev == list->next.
 *
 * If exists some possiblity that your code handle an empty list, use mk_list_is_empty()
 * previously to check if its empty or not.
 */
#define mk_list_entry_last(ptr, type, member) container_of((ptr)->prev, type, member)

/* Next node */
#define mk_list_entry_next(ptr, type, member, head)                     \
    (ptr)->next == (head) ? container_of((head)->next, type, member) :  \
        container_of((ptr)->next, type, member);

#endif /* !MK_LIST_H_ */
