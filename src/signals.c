/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P. <edsiper@gmail.com>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "monkey.h"
#include "signals.h"
#include "clock.h"
#include "plugin.h"

/* (by Daniel R. Ome) */
void mk_signal_handler(int signo)
{

    switch (signo) {
    case SIGUSR2:
        /* Fixme: not yet implemented */
        printf("%s => Monkey reconfiguration \n", log_current_time.data);
        break;

    case SIGINT:
        mk_utils_remove_pid();
        mk_plugin_exit_all();
        printf("\n\n%s => Interrupt from keyboard\n\n",
               log_current_time.data);
        _exit(EXIT_SUCCESS);
    case SIGHUP:
        printf("%s => Hangup\n", log_current_time.data);
        mk_signal_term();
        break;

    case SIGPIPE:
        printf("\n sigpipe");
        fflush(stdout);
        break;

    case SIGBUS:
    case SIGSEGV:
        printf("%s => Invalid memory reference\n", log_current_time.data);
        break;

    case SIGTERM:
        printf("%s => Termination signal\n", log_current_time.data);
        mk_signal_term();
        break;
    }

    pthread_exit(NULL);
}

void mk_signal_init()
{
    signal(SIGHUP, (void *) mk_signal_handler);
    signal(SIGINT, (void *) mk_signal_handler);
    signal(SIGPIPE, (void *) mk_signal_handler);
    signal(SIGBUS, (void *) mk_signal_handler);
    signal(SIGSEGV, (void *) mk_signal_handler);
    signal(SIGTERM, (void *) mk_signal_handler);
    signal(SIGUSR2, (void *) mk_signal_handler);
}

void mk_signal_term()
{
    signal(SIGHUP, (void *) SIG_DFL);
    signal(SIGINT, (void *) SIG_DFL);
    signal(SIGPIPE, (void *) SIG_DFL);
    signal(SIGBUS, (void *) SIG_DFL);
    signal(SIGSEGV, (void *) SIG_DFL);
    signal(SIGTERM, (void *) SIG_DFL);
    signal(SIGUSR2, (void *) SIG_DFL);
    exit(EXIT_SUCCESS);
}

void mk_signal_thread_sigpipe_safe()
{
    sigset_t set, old;

    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, &old);
}
