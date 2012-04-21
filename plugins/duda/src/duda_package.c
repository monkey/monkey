/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
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

#include "MKPlugin.h"
#include "duda.h"
#include "duda_conf.h"
#include "duda_package.h"

duda_package_t *duda_package_load(const char *pkgname)
{
    int ret;
    char *package = NULL;
    void *handle = NULL;
    unsigned long len;
    struct file_info finfo;
    duda_package_t *(*init_pkg)() = NULL;
    duda_package_t *package_info;

    mk_api->str_build(&package, &len, "%s/%s.dpkg", packages_root, pkgname);
    ret = mk_api->file_get_info(package, &finfo);

    if (ret != 0) {
        mk_err("Duda: Package '%s' not found", pkgname);
        mk_api->mem_free(package);
        exit(EXIT_FAILURE);
    }

    if (finfo.is_file == MK_FALSE) {
        mk_warn("Duda: Invalid Package '%s'", pkgname);
        mk_api->mem_free(package);
        return NULL;
    }

    handle = duda_load_library(package);
    if (!handle) {
        mk_warn("Duda: Invalid Package format '%s'", pkgname);
        mk_api->mem_free(package);
        return NULL;
    }

    init_pkg = duda_load_symbol(handle, "init_duda_package");
    if (!init_pkg) {
        mk_err("Duda: the package '%s' is broken", pkgname);
        exit(EXIT_FAILURE);
    }

    package_info = init_pkg();
    mk_api->mem_free(package);

    return package_info;
}
