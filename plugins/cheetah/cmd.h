/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
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

time_t init_time;

/* commands */
int mk_cheetah_cmd(char *cmd);

void mk_cheetah_cmd_clear();
void mk_cheetah_cmd_uptime();

/* Plugins commands */
void mk_cheetah_cmd_plugins_print_stage(struct mk_list *list, const char *stage,
                                        int stage_bw);
void mk_cheetah_cmd_plugins_print_core(struct mk_list *list);
void mk_cheetah_cmd_plugins_print_network(struct mk_list *list);
void mk_cheetah_cmd_plugins();

void mk_cheetah_cmd_vhosts();
void mk_cheetah_cmd_workers();

int  mk_cheetah_cmd_quit();
void mk_cheetah_cmd_help();
void mk_cheetah_cmd_config();
void mk_cheetah_cmd_status();

