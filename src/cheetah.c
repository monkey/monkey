/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2009, Eduardo Silva P.
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>

#include "monkey.h"
#include "config.h"
#include "scheduler.h"
#include "info.h"
#include "request.h"
#include "str.h"

#define MK_CHEETAH_STATUS "status"
#define MK_CHEETAH_STATUS_SC "\\s"

#define MK_CHEETAH_HELP "help"
#define MK_CHEETAH_HELP_SC "\\h"

#define MK_CHEETAH_UPTIME "uptime"
#define MK_CHEETAH_UPTIME_SC "\\u"

#define MK_CHEETAH_VHOSTS "vhosts"
#define MK_CHEETAH_VHOSTS_SC "\\v"

#define MK_CHEETAH_WORKERS "workers"
#define MK_CHEETAH_WORKERS_SC "\\w"

#define MK_CHEETAH_QUIT "quit"
#define MK_CHEETAH_QUIT_SC "\\q"

#define MK_CHEETAH_PROMPT "cheetah> "
#define MK_CHEETAH_PROC_TASK "/proc/%i/task/%i/stat"
#define MK_CHEETAH_ONEDAY  86400
#define MK_CHEETAH_ONEHOUR  3600
#define MK_CHEETAH_ONEMINUTE  60

void mk_cheetah_print_worker_memory_usage(pid_t pid)
{
        int last, init, n, c = 0;
        char *buf;
        char *value;
        pid_t ppid;
        FILE *f;
        
        ppid = getpid();
        buf = mk_mem_malloc_z(1024);
        sprintf(buf, MK_CHEETAH_PROC_TASK, ppid, pid);

        f = fopen(buf, "r");
        if(!f){
                printf("Cannot get details\n");
                return;
        }

        buf = fgets(buf, 1024, f);
        if(!buf){
                printf("Cannot format details\n");
                return;
        }
        fclose(f);

        last = 0;
        init = 0;
        while((n = mk_string_search(buf+last, " ")) > 0){
                if(c == 23){
                        value = mk_string_copy_substr(buf, init, last+n);
                        printf("%s\n", value);
                        mk_mem_free(buf);
                        mk_mem_free(value);
                        return;
                }
                init = last+n+1;
                last += n +1;
                c++;
        }
}

void mk_cheetah_print_running_user()
{
        struct passwd pwd;
        struct passwd *result;
        char *buf;
        size_t bufsize;
        uid_t uid;

        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize == -1){
                bufsize = 16384;
        }
        
        buf = mk_mem_malloc(bufsize);
        uid = getuid();
        getpwuid_r(uid, &pwd, buf, bufsize, &result);

        printf("%s\n", pwd.pw_name);
        mk_mem_free(buf);
}

void mk_cheetah_cmd_uptime()
{
        int days; int hours; int minutes; int seconds;
        long int upmind; 
        long int upminh;
        long int uptime;
        
        /* uptime in seconds */
        uptime = time(NULL) - mk_init_time;

        /* days */
        days = uptime / MK_CHEETAH_ONEDAY;
        upmind = uptime - (days * MK_CHEETAH_ONEDAY);

        /* hours */
        hours = upmind / MK_CHEETAH_ONEHOUR;
        upminh = upmind - hours * MK_CHEETAH_ONEHOUR;

        /* minutes */
        minutes = upminh / MK_CHEETAH_ONEMINUTE;
        seconds = upminh - minutes * MK_CHEETAH_ONEMINUTE;

        printf("Server has been running: %i day%s, %i hour%s, %i minute%s and %i second%s\n", 
               days, (days > 1) ? "s" : "",
               hours, (hours > 1) ? "s" : "",
               minutes, (minutes > 1) ? "s" : "",
               seconds, (seconds > 1) ? "s" : "");
}

void mk_cheetah_cmd_vhosts()
{
        struct host *host;
        
        host = config->hosts;

        while(host){
                printf("* VHost '%s'\n", host->servername);
                printf("      - Configuration Path     : %s\n",
                       host->file);
                printf("      - Document Root          : %s\n", 
                       host->documentroot.data);
                printf("      - Access Log             : %s\n", 
                       host->access_log_path);
                printf("      - Error Log              : %s\n", 
                       host->error_log_path);
                printf("      - List Directory Content : %s",
                       (host->getdir == VAR_ON) ? "Yes" : "No");
                host = host->next;
        }
}

void mk_cheetah_cmd_workers()
{
        struct sched_list_node *sl;
        sl = sched_list;

        while(sl){
                printf("* Worker %i\n", sl->idx);
                printf("      - Task ID           : %i\n", sl->pid);

                /* Memory Usage */
                printf("      - Memory usage      : ");                
                mk_cheetah_print_worker_memory_usage(sl->pid);

                printf("      - Active Requests   : %i\n", 
                       sl->active_requests);
                printf("      - Closed Requests   : %i\n",
                       sl->closed_requests);
                sl = sl->next;
        }
}

void mk_cheetah_cmd_quit()
{
        printf("Cheeta says: Good Bye!\n");
        fflush(stdout);
        pthread_exit(NULL);
}

void mk_cheetah_cmd_help()
{
        printf("\nList of available commands for Cheetah Shell\n");
        printf("\ncommand  shortcut  description");
        printf("\n----------------------------------------------------");
        printf("\nhelp       (\\h)    Print this help");
        printf("\nstatus     (\\s)    Display general web server information");
        printf("\nuptime     (\\u)    Display how long the web server has been running");
        printf("\nvhosts     (\\v)    List virtual hosts configured");
        printf("\nworkers    (\\w)    Show thread workers information");
        printf("\nquit       (\\q)    Exist Cheetah shell :_(\n");
}

void mk_cheetah_cmd(char *cmd)
{
        int nthreads = 0;
        struct sched_list_node *sl;

        sl = sched_list;
        while(sl){
                nthreads++;
                sl = sl->next;
        }

        if(strcmp(cmd, MK_CHEETAH_STATUS) == 0 || 
           strcmp(cmd, MK_CHEETAH_STATUS_SC) == 0){
                printf("\nMonkey Version     : %s\n", VERSION);
                printf("Configutarion path : %s\n", config->serverconf);
                printf("Process ID         : %i\n", getpid());

                printf("Process User       : ");
                mk_cheetah_print_running_user();

                printf("Server Port        : %i\n", config->serverport);
                printf("Worker Threads     : %i (per configuration: %i)\n", 
                       nthreads, 
                       config->workers);
        }
        else if(strcmp(cmd, MK_CHEETAH_UPTIME) == 0 ||
                strcmp(cmd, MK_CHEETAH_UPTIME_SC) == 0){
                mk_cheetah_cmd_uptime();
        }
        else if(strcmp(cmd, MK_CHEETAH_WORKERS) == 0 ||
                strcmp(cmd, MK_CHEETAH_WORKERS_SC) == 0){
                mk_cheetah_cmd_workers();
        }
        else if(strcmp(cmd, MK_CHEETAH_VHOSTS) == 0 || 
                strcmp(cmd, MK_CHEETAH_VHOSTS_SC) == 0){
                mk_cheetah_cmd_vhosts();
        }
        else if(strcmp(cmd, MK_CHEETAH_HELP) == 0 ||
                strcmp(cmd, MK_CHEETAH_HELP_SC) == 0){
                mk_cheetah_cmd_help();
        }
        else if(strcmp(cmd, MK_CHEETAH_QUIT) == 0 || 
                strcmp(cmd, MK_CHEETAH_QUIT_SC) == 0){
                mk_cheetah_cmd_quit();
        }
        else if(strlen(cmd) == 0){
                return;
        }
        else{
                printf("Invalid command, type 'help' for a list of available commands\n");
        }

        printf("\n");
        fflush(stdout);
}

void mk_cheetah_loop()
{
        int len;
        char cmd[200];
        char line[200];
        char *rcmd;

        printf("\n*** Welcome to Cheetah!, the Monkey Shell :) ***\n");
        printf("\nType 'help' for a list of available commands\n\n");
        fflush(stdout);

        while(1){
                printf("%s", MK_CHEETAH_PROMPT);
                rcmd = fgets(line, sizeof(line), stdin);

                len = strlen(line);
                strncpy(cmd, line, len-1);
                cmd[len-1] = '\0';

                mk_cheetah_cmd(cmd);
                bzero(line, sizeof(line));
        }

}

void *mk_cheetah_init(void *args)
{
        config->cheetah = VAR_ON;
        mk_cheetah_loop();
        return 0;
}
