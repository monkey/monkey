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

#ifndef MK_THREAD_H
#define MK_THREAD_H

#include <mk_common.h>
#include <semaphore.h>
#include <pthread.h>

typedef struct {
	unsigned int pl_quantity;
	unsigned int pl_free;

	mk_queue *pl_rqq; /* Requests queue */
	pthread_mutex_t pl_rqq_lock;
	sem_t pl_rqq_sem;

	pthread_mutex_t pl_lock;
} mk_thread_pool;

typedef struct
{
	void (*func)(void *);
	void *arg;
} mk_thread_data;

mk_thread_pool *mk_thread_pool_create(unsigned int n);

void mk_thread_mutex_lock(int *lock);
void mk_thread_mutex_unlock(int *lock);

int mk_thread_pool_set(mk_thread_pool *pool, void (func)(void *data), void *data);

#endif
