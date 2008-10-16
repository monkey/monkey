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
#include <stdio.h>

#include "monkey.h"
#include "file.h"
#include "memory.h"

struct file_info *mk_file_get_info(char *path)
{
	gid_t egid;
	uid_t euid;

	struct file_info *f_info;
	struct stat f, target;

	/* Stat right resource */
	if(lstat(path, &f)==-1)
	{
		return NULL;
	}

	f_info = mk_mem_malloc(sizeof(struct file_info));
	f_info->is_link = MK_FILE_FALSE;
	f_info->is_directory = MK_FILE_FALSE;
	f_info->exec_access = MK_FILE_FALSE;
	f_info->read_access = MK_FILE_FALSE;

	if(S_ISLNK(f.st_mode))
	{
		f_info->is_link = MK_FILE_TRUE;
		if(stat(path, &target)==-1)
		{
			return NULL;
		}
	}
	else{
		target = f;
	}

	f_info->size = target.st_size;
	f_info->last_modification = target.st_mtime;

	if(S_ISDIR(target.st_mode))
	{
		f_info->is_directory = MK_FILE_TRUE;
	}

	/* Getting current user euid/egid */
        /* FIXME: This should be global */ 
	euid = geteuid();
	egid = getegid();

	/* Checking read access */
	if( (target.st_mode & S_IRUSR && target.st_uid == euid) || 
			(target.st_mode & S_IRGRP && target.st_gid == egid) ||
			(target.st_mode & S_IROTH))
	{
		f_info->read_access = MK_FILE_TRUE;
	}

	/* Checking execution access */
	if( (target.st_mode & S_IXUSR && target.st_uid == euid) ||
			(target.st_mode & S_IXGRP && target.st_gid == egid) ||
			(target.st_mode & S_IXOTH))
	{
		f_info->exec_access = MK_FILE_TRUE;

	}
	return f_info;
}

/* Read file content to a memory buffer,
 * Use this function just for really SMALL files
 */
char *mk_file_to_buffer(char *path)
{
	FILE *fp;
	char *buffer;
	long bytes;
	struct file_info *finfo;

	if(!(finfo = mk_file_get_info(path)))
	{
		return NULL;
	}

	if(!(fp = fopen(path, "r")))
	{
		return NULL;
	}

	if(!(buffer = mk_mem_malloc(finfo->size)))
	{
		fclose(fp);
		return NULL;
	}
	       
	bytes = fread(buffer, 1, finfo->size, fp);
	if(bytes < finfo->size)
	{
		mk_mem_free(buffer);
		fclose(fp);
		return NULL;
	}
	
	fclose(fp);
	return (char *) buffer;
	
}

