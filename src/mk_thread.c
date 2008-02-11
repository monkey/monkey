
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
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>

#include <pthread.h>

#include <mk_common.h>
#include <mk_thread.h>

#define FUTEX_WAIT              0
#define FUTEX_WAKE              1
#define futex(a, b, c, d, e, f) syscall(SYS_futex, (a), (b), (c), (d), (e), (f))

static inline void mk_thread_wakeup(int *wakeup)
{
	/* wake up _one_ thread waiting "wakeup" */
	futex(wakeup, FUTEX_WAKE, 1, NULL, NULL, 0);
}

static inline void mk_thread_sleep(int *wakeup)
{
	/* Always waits a WAKE UP */
	futex(wakeup, FUTEX_WAIT, 0xb33f, NULL, NULL, 0);
}

static void *mk_thread_start(void *_pool)
{
	mk_thread_pool *pool = (mk_thread_pool *)_pool;
	int kill;

	do {
		mk_thread_sleep(&pool->pl_wakeup);

		/* Activated */
		pool->pl_func(pool->pl_data);

		/* Starts critical section */
		mk_thread_mutex_lock(&pool->pl_lock);
		kill = (pool->pl_free < pool->pl_quantity);
		pool->pl_free += kill;
		mk_thread_mutex_unlock(&pool->pl_lock);
		/* Ends critical section */
	} while(kill);

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

	pool->pl_func = NULL;
	pool->pl_data = NULL;

	pool->pl_lock = MK_THREAD_UNLOCKED_VAL;
	pool->pl_wakeup = 0xb33f;

	mk_thread_get_quantity(pool);

	return pool;
}

int mk_thread_mutex_lock(int *lock)
{
    int r;

	/* If *lock is equal to MK_THREAD_LOCKED_VAL, waits a WAKE UP */
	r = futex(lock, FUTEX_WAIT, MK_THREAD_LOCKED_VAL, NULL, NULL, 0);
    if(r<0){
        return -1;
    }

	*lock = MK_THREAD_LOCKED_VAL;
    return 0;
}

void mk_thread_mutex_unlock(int *lock)
{
	/* Sends a WAKE UP and sets *lock to MK_THREAD_UNLOCKED_VAL */
	futex(lock, FUTEX_WAKE, 1, NULL, NULL, 0);
	*lock = MK_THREAD_UNLOCKED_VAL;
}

int mk_thread_pool_set(mk_thread_pool *pool, void (*func)(void *data), void *data)
{
	/* Starts critical section */
    mk_thread_mutex_lock(&pool->pl_lock);

	pool->pl_func = func;
	pool->pl_data = data;

	if(pool->pl_free) {
		/* Gets pre-loaded thread */
        printf("\nWAKE UP THREAD FOR: %i", (int) data);
        fflush(stdout);

		mk_thread_wakeup(&pool->pl_wakeup);
		pool->pl_free--;
	} else {
		/* Fatal error: is not able to create a thread for "func(data)" call. */
		if(mk_thread_create_one(pool) == MK_ERROR)
			return MK_ERROR;

		mk_thread_wakeup(&pool->pl_wakeup);
		mk_thread_get_quantity(pool);
	}

	mk_thread_mutex_unlock(&pool->pl_lock);
	/* Ends critical section */

	return MK_OK;
}
