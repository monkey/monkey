/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P.
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

/* System headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/stat.h>
#include <fcntl.h>

/* Monkey Plugin Interface */
#include "MKPlugin.h"

/* Local header files */
#include "cmd.h"
#include "cheetah.h"

MONKEY_PLUGIN("cheetah",              /* shortname */
              "Cheetah! Shell",       /* name */
              "0.12.0",               /* version */
              MK_PLUGIN_CORE_PRCTX);  /* hooks */

void mk_cheetah_welcome_msg()
{
    CHEETAH_WRITE("\n%s%s***%s Welcome to %sCheetah!%s, the %sMonkey Shell %s:) %s***%s\n",
                  ANSI_BOLD, ANSI_YELLOW,
                  ANSI_WHITE, ANSI_GREEN, 
                  ANSI_WHITE, ANSI_RED, ANSI_WHITE, ANSI_YELLOW, ANSI_RESET);
    CHEETAH_WRITE("\n      << %sType 'help' or '\\h' for help%s >>\n\n",
                  ANSI_BLUE, ANSI_RESET);
    CHEETAH_FLUSH();
}

void mk_cheetah_loop()
{
    int len;
    char cmd[200];
    char line[200];
    char *rcmd;

    mk_cheetah_welcome_msg();

    while (1) {
        CHEETAH_WRITE(MK_CHEETAH_PROMPT, ANSI_BOLD, ANSI_GREEN, ANSI_RESET);
        rcmd = fgets(line, sizeof(line), cheetah_input);

        len = strlen(line);
        
        if (len == 0){
            CHEETAH_WRITE("\n");
            mk_cheetah_cmd_quit();
        }

        strncpy(cmd, line, len - 1);
        cmd[len - 1] = '\0';

        mk_cheetah_cmd(cmd);
        bzero(line, sizeof(line));
    }
}

void mk_cheetah_config(char *path)
{
    unsigned long len;
    char *listen = NULL;
    char *default_file = NULL;
    struct mk_config *conf;
    struct mk_config_section *section;

    /* this variable is defined in cheetah.h and points to
     * the FILE *descriptor where to write out the data
     */
    cheetah_output = NULL;

    /* read configuration file */
    mk_api->str_build(&default_file, &len, "%scheetah.conf", path);
    conf = mk_api->config_create(default_file);
    section = mk_api->config_section_get(conf, "CHEETAH");

    if (!section) {
        CHEETAH_WRITE("\nError, could not find CHEETAH tag");
        exit(1);
    }

    /* no longer needed */
    mk_api->mem_free(default_file);

    /* Listen directive */
    listen = mk_api->config_section_getval(section, "Listen", 
                                           MK_CONFIG_VAL_STR);

    if (strcasecmp(listen, LISTEN_STDIN_STR) == 0) {
        listen_mode = LISTEN_STDIN;
    }
    else if (strcasecmp(listen, LISTEN_CLIENT_STR) == 0) {
        listen_mode = LISTEN_CLIENT;
    }
    else {

    }
}

void mk_cheetah_create_pipe()
{
    int fd, ret;
    unsigned long len;
    char *buf=NULL;
    FILE *f;

    mk_api->str_build(&buf, &len, "/tmp/cheetah.%i", mk_api->config->serverport);

    ret = mkfifo(buf, 0666);
    if ((ret == -1) && (errno != EEXIST)) {
        perror("Error creating pipe");
        exit(1);
    }

    /* A real nasty code, if we run fopen() directly we get a weird
     * behavior after open the file (could be related to a FIFO issue ?)
     */
    fd = open(buf, O_RDWR);
    f = fdopen(fd, "rw");

    cheetah_pipe = buf;

    cheetah_input = cheetah_output = f;
}

void *mk_cheetah_init(void *args)
{
    /* Open right FDs for I/O */
    if (listen_mode == LISTEN_STDIN) {
        cheetah_input = stdin;
        cheetah_output = stdout;
    }
    else if (listen_mode == LISTEN_CLIENT) {
        mk_cheetah_create_pipe();
    }

    mk_cheetah_loop();
    return 0;
}

/* This function is called when the plugin is loaded, it must
 * return 
 */
int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;
    init_time = time(NULL);
    
    mk_cheetah_config(confdir);
    return 0;
}

void _mkp_exit()
{
    if (listen_mode == LISTEN_CLIENT) {
        /* Remote named pipe */
        unlink(cheetah_pipe);
        mk_api->mem_free(cheetah_pipe);
    }
}

int _mkp_core_prctx(struct server_config *config)
{
    pthread_t tid;
    pthread_attr_t thread_attr;

    pthread_attr_init(&thread_attr);
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &thread_attr, 
                       (void *) mk_cheetah_init, config) < 0) {
        perror("pthread_create");
        exit(1);
    }
    
    return 0;
}
