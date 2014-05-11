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

#ifndef MK_KERNEL_H
#define MK_KERNEL_H

/* Server features: depends on server setup and Linux Kernel version */
#define MK_KERNEL_TCP_FASTOPEN      1
#define MK_KERNEL_SO_REUSEPORT      2
#define MK_KERNEL_TCP_AUTOCORKING   4

#define MK_KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))

/* Current running version of the Kernel */
int mk_kernel_runver;

int mk_kernel_init();
int mk_kernel_version();
int mk_kernel_features();
int mk_kernel_features_print(char *buffer, size_t size);

#endif
