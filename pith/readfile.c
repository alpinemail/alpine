#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: readfile.c 761 2007-10-23 22:35:18Z hubert@u.washington.edu $";
#endif

/*
 * ========================================================================
 * Copyright 2013-2018 Eduardo Chappa
 * Copyright 2006 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 */

#include "../pith/headers.h"

#include "../pith/store.h"

#include "readfile.h"


/*----------------------------------------------------------------------
    Read whole file into memory

  Args: filename -- path name of file to read

  Result: Returns pointer to malloced memory with the contents of the file
          or NULL

This won't work very well if the file has NULLs in it.
 ----*/
char *
read_file(char *filename, int so_get_flags)
{
    STORE_S *in_file = NULL, *out_store = NULL;
    unsigned char c;
    char *return_text = NULL;

    if((in_file = so_get(FileStar, filename, so_get_flags | READ_ACCESS))){


	if(!(out_store = so_get(CharStar, NULL, EDIT_ACCESS))){
	    so_give(&in_file);
	    return NULL;
	}

	/*
	 * We're just using the READ_FROM_LOCALE flag to translate
	 * to UTF-8.
	 */
	while(so_readc(&c, in_file))
	  so_writec(c, out_store);

	if(in_file)
	  so_give(&in_file);

	if(out_store){
	    return_text = (char *) so_text(out_store);
	    /* avoid freeing this */
	    if(out_store->txt)
	      out_store->txt = NULL;

	    so_give(&out_store);
	}
    }

    return(return_text);
}

/* our copy, to_file and from_file must be full paths. from_file
 * must exist.
 */
int
our_copy(char *to_file, char *from_file)
{
   STORE_S *in_cert, *out_cert;
   unsigned char c;

   in_cert  = so_get(FileStar, from_file, READ_ACCESS | READ_FROM_LOCALE);
   if (in_cert == NULL)
     return -1;

   out_cert = so_get(FileStar, to_file, WRITE_ACCESS | WRITE_TO_LOCALE);
   if (out_cert == NULL){
     so_give(&in_cert);
     return -1;
   }

   so_seek(out_cert, 0L, 0);
   so_truncate(out_cert, 0);

   while(so_readc(&c, in_cert) > 0)
     so_writec(c, out_cert);

   so_give(&in_cert);
   so_give(&out_cert);

   return 0;
}

/* Copy a symbolic link
 * to_file must be linked to realpath of from_file
 */
int
our_copy_link(char *to_file, char *from_file)
{
   char result[MAXPATH+1];

   return realpath(from_file, result) != NULL 
	   ? symlink(result,  to_file) : -1;
}

/* our copy_dir, to_dir and from_dir must be full paths. from_dir
 * must exist and dest_dir must not exist. We only copy regular
 * files and directories, nothing more.
 */
int
our_copy_dir(char *to_dir, char *from_dir)
{
    int rv = 0;
    char *fname;
    char to_file[MAXPATH+1], from_file[MAXPATH];
#ifndef _WINDOWS
    struct dirent *d;
    DIR *dirp;
#else /* _WINDOWS */
    struct _finddata_t dbuf;
    char buf[_MAX_PATH + 4]; 
    long findrv;
#endif /* _WINDOWS */
   struct stat sbuf;

   if(stat(from_dir, &sbuf) < 0		/* origin must exist */
	|| (sbuf.st_mode & S_IFMT) != S_IFDIR	/* and be a directory */
	|| stat(to_dir, &sbuf) == 0 	/* destination must not exist */
	|| create_mail_dir(to_dir) < 0)
     return -1;

#ifndef _WINDOWS
    dirp = opendir(from_dir);
    if(dirp){
        while((d=readdir(dirp)) != NULL){
           fname = d->d_name;
#else /* _WINDOWS */
    snprintf(buf, sizeof(buf), "%s%s*.*", to_dir, (to_dir[strlen(to_dir)-1] == '\\') ? "" : "\\");
    buf[sizeof(buf)-1] = '\0';
    if((findrv = _findfirst(buf, &dbuf)) < 0)
        return(-1);

        do {
           fname = fname_to_utf8(dbuf.name);
#endif
	   if(strcmp(fname, ".") == 0 || strcmp(fname, "..") == 0)
	     continue;

	   build_path(from_file, from_dir, fname, sizeof(from_file));
	   build_path(to_file, to_dir, fname, sizeof(to_file));
	   if(stat(from_file, &sbuf) < 0) /* symbolic link to a non-existing file */
	     continue;
	   switch(sbuf.st_mode & S_IFMT){
		case S_IFREG: 	/* regular file */
			rv += our_copy(to_file, from_file);
			break;

		case S_IFDIR:	/* directory */
			rv += our_copy_dir(to_file, from_file);
			break;

		case S_IFLNK:	/* symbolic link */
			rv += our_copy_link(to_file, from_file);
			break;

		default: 	/* not a regular file, or directory, or symbolic link */
			rv += -1;
			break;
	   }
#ifndef _WINDOWS
        }
        closedir(dirp);
    }   
#else /* _WINDOWS */
    } while(_findnext(findrv, &dbuf) == 0); 
    _findclose(findrv);
#endif /* !_WINDOWS */
   return rv;
}

