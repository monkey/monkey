/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2003, Eduardo Silva P.
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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "monkey.h"
#include "signals.h"
#include "utils.h"
#include "logfile.h"
#include "chars.h"
#include "clock.h"

/* (by Daniel R. Ome) */
void mk_signal_handler(int signo)
{

    switch (signo) {
    case SIGUSR2:
        printf("%s => Monkey reconfiguration \n", log_current_time.data);       /* Not ready */
        break;

    case SIGINT:
        mk_logger_remove_pid();
        printf("\n\n%s => Interrupt from keyboard\n\n",
               log_current_time.data);
        exit(0);
    case SIGHUP:
        printf("%s => Hangup\n", log_current_time.data);
        mk_signal_term();
        break;

    case SIGBUS:
        printf("%s => Invalid memory reference\n", log_current_time.data);
        abort();
        break;

    case SIGPIPE:
        printf("\n sigpipe");
        fflush(stdout);
        break;

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
}

void mk_signal_thread_sigpipe_safe()
{
    sigset_t set, old;

    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, &old);
}
