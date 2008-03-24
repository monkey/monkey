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

#include <mk_thread.h>

static void *mk_thread_start(void *_pool)
{
	mk_thread_pool *pool = (mk_thread_pool *)_pool;
	mk_thread_data *thread_data;
	int keep = 1;

	do {
		sem_wait(&pool->pl_rqq_sem);

		pthread_mutex_lock(&pool->pl_rqq_lock);
		thread_data = mk_common_dequeue(pool->pl_rqq); /* thread_data never will be NULL */
		pthread_mutex_unlock(&pool->pl_rqq_lock);

		/* Activated */
		thread_data->func(thread_data->arg);
		/* Ended */
		free(thread_data);

		pthread_mutex_lock(&pool->pl_lock);
		keep = (pool->pl_free < pool->pl_quantity);
		pool->pl_free += keep; /* If keep is zero, this thread MUST DIE :_( */
		pthread_mutex_unlock(&pool->pl_lock);
	} while(keep);

	return NULL;
}

static int mk_thread_create_one(mk_thread_pool *pool)
{
	pthread_t thread;

	if(pthread_create(&thread, NULL, mk_thread_start, (void *)pool) != 0)
		return MK_ERROR;

	return MK_OK;
}

static void mk_thread_get_quantity(mk_thread_pool *pool)
{
	/* If possible creates pool->pl_quantity threads. */
	while(pool->pl_free < pool->pl_quantity) {
		if(mk_thread_create_one(pool) == MK_ERROR)
			break;

		pool->pl_free++;
	}
}

mk_thread_pool *mk_thread_pool_create(unsigned int n)
{
	mk_thread_pool *pool;

	pool = malloc(sizeof(mk_thread_pool));
	if(!pool)
		return NULL;

	pool->pl_quantity = n;
	pool->pl_free = 0;

	pool->pl_rqq = mk_common_queue();
	pthread_mutex_init(&pool->pl_rqq_lock, NULL);

	/* Queue's semaphore is initialized to 0, for each request will increase the semaphore */
	sem_init(&pool->pl_rqq_sem, 0, 0);

	pthread_mutex_init(&pool->pl_lock, NULL);
	mk_thread_get_quantity(pool);

	return pool;
}

static inline mk_thread_data *__new_thread_data(void (*func)(void *), void *data)
{
	mk_thread_data *thread_data;

	thread_data = malloc(sizeof(mk_thread_data));
	if(!thread_data)
		/* Oops.. It's really bad! */
		return NULL;

	thread_data->func = func;
	thread_data->arg = data;
	return thread_data;
}

int mk_thread_pool_set(mk_thread_pool *pool, void (*func)(void *), void *data)
{
	mk_thread_data *thread_data;
	int retval;

	thread_data = __new_thread_data(func, data);
	if(!thread_data)
		return MK_ERROR;

	pthread_mutex_lock(&pool->pl_rqq_lock);
	retval = mk_common_enqueue(pool->pl_rqq, thread_data);
	pthread_mutex_unlock(&pool->pl_rqq_lock);

	if(retval == MK_ERROR) {
		free(thread_data);
		return MK_ERROR;
	}

	pthread_mutex_lock(&pool->pl_lock);
	sem_post(&pool->pl_rqq_sem);

	if(pool->pl_free)
		pool->pl_free--;
	else {
		/* Asks pool->pl_quantity threads for pool */
		mk_thread_get_quantity(pool);
		if(pool->pl_free)
			pool->pl_free--;
		else {
			/* We can't create at least one thread for thread_data */
			/* FIXME: wrong behavior.. should return non-OK */ 
			pthread_mutex_lock(&pool->pl_rqq_lock);
			mk_common_dequeue(pool->pl_rqq);
			pthread_mutex_unlock(&pool->pl_rqq_lock);
			free(thread_data);
		}
	}
	pthread_mutex_unlock(&pool->pl_lock);

	return MK_OK;
}
