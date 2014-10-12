/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
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

/* If a library, do not interfere with the app's signals */
#ifndef SHAREDLIB

#define _GNU_SOURCE

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <monkey/monkey.h>
#include <monkey/mk_signals.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_macros.h>


/*
 * Some old uclib versions do not implment the sys_siglist, this is mostly
 * related to embedded environments with old toolchains
 */
#ifdef UCLIB_MODE
#include "contrib/uclib/sys_siglist.h"
#endif

/* when we catch a signal and want to exit we call this function
   to do it gracefully */
static void mk_signal_exit()
{
    int i;
    int n = 0;
    uint64_t val;

    /* ignore future signals to properly handle the cleanup */
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT,  SIG_IGN);
    signal(SIGHUP,  SIG_IGN);

    /* Distribute worker signals to stop working */
    val = MK_SCHEDULER_SIGNAL_FREE_ALL;
    for (i = 0; i < config->workers; i++) {
        n = write(sched_list[i].signal_channel_w, &val, sizeof(val));
        if (n < 0) {
            perror("write");
        }
    }

    /* Wait for workers to finish */
    for (i = 0; i < config->workers; i++) {
        pthread_join(sched_list[i].tid, NULL);
    }

    mk_utils_remove_pid();
    mk_plugin_exit_all();
    mk_config_free_all();
    mk_mem_free(sched_list);
    mk_clock_exit();
    mk_info("Exiting... >:(");
    _exit(EXIT_SUCCESS);
}

void mk_signal_thread_sigpipe_safe()
{
    sigset_t old;
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, &old);
}


static void mk_signal_handler(int signo, siginfo_t *si, void *context UNUSED_PARAM)
{
    switch (signo) {
    case SIGTERM:
    case SIGINT:
        abort();
        mk_signal_exit();
        break;
    case SIGHUP:
        /*
         * TODO:
         * we should implement the httpd config reload here (not in SIGUSR2).
         * Daemon processes “overload” this signal with a mechanism to instruct them to
         * reload their configuration files. Sending SIGHUP to Apache, for example,
         * instructs it to reread httpd.conf.
         */
        mk_signal_exit();
        break;
    case SIGBUS:
    case SIGSEGV:
#ifdef DEBUG
        mk_utils_stacktrace();
#endif
        mk_err("%s (%d), code=%d, addr=%p",
               strsignal(signo), signo, si->si_code, si->si_addr);
        //close(sched->server_fd);
        //pthread_exit(NULL);
        abort();
    default:
        /* let the kernel handle it */
        kill(getpid(), signo);
    }

}

void mk_signal_init()
{
    struct sigaction act;
    memset(&act, 0x0, sizeof(act));

    /* allow signals to be handled concurrently */
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    act.sa_sigaction = &mk_signal_handler;

    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS,  &act, NULL);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
}

#endif // !SHAREDLIB
