
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

static inline void mk_thread_wait_for(int *wakeup)
{
    futex(wakeup, FUTEX_WAIT, 0xfe119e, NULL, NULL, 0);
}

static void *mk_thread_start(void *_pool)
{
    mk_thread_pool *pool = (mk_thread_pool *)_pool;
    mk_thread_data *thread_data;
    int keep = 1;

    do {
        mk_thread_mutex_lock(&pool->pl_rqq_lock);
        thread_data = mk_common_dequeue(pool->pl_rqq);
        mk_thread_mutex_unlock(&pool->pl_rqq_lock);

        if(!thread_data) {
            mk_thread_wait_for(&pool->pl_wakeup);
            continue;
        }

        /* Activated */
        thread_data->func(thread_data->arg);
        /* Ended */
        free(thread_data);

        mk_thread_mutex_lock(&pool->pl_lock);
        keep = (pool->pl_free < pool->pl_quantity);
        pool->pl_free += keep; /* If keep is zero, this thread MUST DIE :_( */
        mk_thread_mutex_unlock(&pool->pl_lock);
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
    pool->pl_rqq_lock = MK_THREAD_UNLOCKED_VAL;
    pool->pl_lock = MK_THREAD_UNLOCKED_VAL;
    pool->pl_wakeup = 0xfe119e;

    mk_thread_get_quantity(pool);

    return pool;
}

void mk_thread_mutex_lock(int *lock)
{
    if(__sync_lock_test_and_set(lock, MK_THREAD_LOCKED_VAL) == MK_THREAD_LOCKED_VAL)
        futex(lock, FUTEX_WAIT, MK_THREAD_LOCKED_VAL, NULL, NULL, 0);
    *lock = MK_THREAD_LOCKED_VAL;
}

void mk_thread_mutex_unlock(int *lock)
{
    if(*lock == MK_THREAD_LOCKED_VAL) {
        *lock = MK_THREAD_UNLOCKED_VAL;
        futex(lock, FUTEX_WAKE, 1, NULL, NULL, 0);
    }
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

    mk_thread_mutex_lock(&pool->pl_rqq_lock);
    retval = mk_common_enqueue(pool->pl_rqq, thread_data);
    mk_thread_mutex_unlock(&pool->pl_rqq_lock);

    if(retval == MK_ERROR) {
        free(thread_data);
        return MK_ERROR;
    }

    mk_thread_mutex_lock(&pool->pl_lock);
    if(pool->pl_free) {
        pool->pl_free--;

        /* Assigns pre-loaded thread */
        mk_thread_wakeup(&pool->pl_wakeup);
    } else {
        /* Fatal error: is not able to create a thread for "func(data)" call. */
        if(mk_thread_create_one(pool) == MK_ERROR)
            return MK_ERROR;

        /* Asks pool->pl_quantity threads for pool */
        mk_thread_get_quantity(pool);
    }
    mk_thread_mutex_unlock(&pool->pl_lock);

    return MK_OK;
}
