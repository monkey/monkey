/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2008, Eduardo Silva P.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "monkey.h"
#include "file.h"

struct file_info *mk_file_get_info(char *path)
{
	gid_t egid;
	uid_t euid;

	struct file_info *f_info;
	struct stat f;

	if(stat(path, &f)==-1)
	{
		return NULL;
	}

	/* Getting current user euid/egid */
	euid = geteuid();
	egid = getegid();

	f_info = M_malloc(sizeof(struct file_info));
	f_info->size = f.st_size;
	f_info->is_link = MK_FILE_FALSE;
	f_info->is_directory = MK_FILE_FALSE;
	f_info->exec_access = MK_FILE_FALSE;
	f_info->read_access = MK_FILE_FALSE;
	f_info->last_modification = f.st_mtime;

	/* is it a symbolic link? */
	if(f.st_mode & S_IFLNK){
		f_info->is_link = MK_FILE_TRUE;	
	}

	/* is directory ? */
	if(f.st_mode & S_IFDIR)
	{
		f_info->is_directory = MK_FILE_TRUE;
	}

	/* Checking read access */
	if( (f.st_mode & S_IRUSR && f.st_uid == euid) || 
			(f.st_mode & S_IRGRP && f.st_gid == egid) || 
			(f.st_mode & S_IROTH))
	{
		f_info->read_access = MK_FILE_TRUE;
	}

	/* Checking execution access */
	if( (f.st_mode & S_IXUSR && f.st_uid == euid) ||
			(f.st_mode & S_IXGRP && f.st_gid == egid) ||
			(f.st_mode & S_IXOTH))
	{
		f_info->exec_access = MK_FILE_TRUE;

	}
	return f_info;
}

