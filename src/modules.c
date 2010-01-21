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
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "monkey.h"

#define TAG_CLOSE 0
#define TAG_OPEN 1

void Mod_Error()
{
    puts("Configuration Error in modules.conf");
    exit(1);
}

char **MOD_Read_Config(char *mod_name)
{
    int i, flag = TAG_CLOSE;    /* 0: YES , 1: NO */
    int vars_counter = 0;
    char *tag_module_open, *tag_module_close;
    char *path = 0, buffer[255];
    char *variable = 0, *value = 0, *last = 0;
    char **arg = 0, **ptr = 0;
    FILE *configfile;

    ptr = arg = (char **) M_malloc(sizeof(char *) * 10);

    path = m_build_buffer("%s/modules.conf", config->serverconf);

    if ((configfile = fopen(path, "r")) == NULL) {
        puts("Error: I can't open modules.conf file.");
        exit(1);
    }

    tag_module_open = (char *) m_build_buffer("<%s>", mod_name);
    tag_module_close = (char *) m_build_buffer("</%s>", mod_name);

    while (!feof(configfile)) {
        fgets(buffer, 255, configfile);

        if (buffer[0] == '#' || buffer[0] == '\n' || buffer[0] == '\r')
            continue;

        for (i = 0; i < 255 && buffer[i] != '\0'; i++)
            if (buffer[i] == '\n' || buffer[i] == '\r')
                buffer[i] = '\0';

        variable = strtok_r(buffer, "\"\t ", &last);
        value = strtok_r(NULL, "\"\t ", &last);

        if (!variable
            || (!value && (strcasecmp(variable, tag_module_open) != 0)
                && (strcasecmp(variable, tag_module_close) != 0))) {
            continue;
        }

        if (strcasecmp(variable, tag_module_open) == 0 && flag == TAG_CLOSE) {
            flag = TAG_OPEN;
        }
        else {
            if (strcasecmp(variable, tag_module_open) == 0
                && flag == TAG_OPEN) {
                Mod_Error();
            }
        }

        if (variable && vars_counter < 10 && flag == TAG_OPEN) {
            *ptr++ = M_CGI_env_add_var(variable, value);
        }
    }

    fclose(configfile);
    M_free(path);
    *ptr++ = '\0';

    return (char **) arg;
}

char *MOD_get_ptr_value(char **ptr, char *var)
{

    int i = 0, length, pos;
    char *buffer = 0, *value = 0;

    while (ptr[i]) {
        buffer = m_build_buffer("%s", ptr[i]);
        pos = str_search(buffer, "=", 1);
        if (strncasecmp(var, buffer, pos) == 0) {
            length = strlen(buffer);
            value = malloc(length + 1);
            strncpy(value, buffer + pos + 1, length - pos);
            value[length - pos] = '\0';
            M_free(buffer);
            return (char *) value;
        }
        i++;
        M_free(buffer);
        M_free(value);
    }
    return (char *) "";
}
