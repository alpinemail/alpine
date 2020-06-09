#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: creatdir.c 769 2007-10-24 00:15:40Z hubert@u.washington.edu $";
#endif

/*
 * ========================================================================
 * Copyright 2006-2007 University of Washington
 * Copyright 2013-2020 Eduardo Chappa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 */

#include <system.h>
#include "../charconv/utf8.h"
#include "../charconv/filesys.h"
#include "creatdir.h"


#ifdef	S_IRWXU
#define	MAILDIR_MODE	S_IRWXU
#else
#define	MAILDIR_MODE	0700
#endif



/*----------------------------------------------------------------------
      Create the mail subdirectory.

  Args: dir -- Name of the directory to create
 
 Result: Directory is created.  Returns 0 on success, else -1 on error
	 and errno is valid.
  ----*/
int
create_mail_dir(char *dir)
{
    if(our_mkdir(dir, MAILDIR_MODE) < 0)
      return(-1);

#ifndef _WINDOWS
    our_chmod(dir, MAILDIR_MODE);

    /* Some systems need this, on others we don't care if it fails */
    our_chown(dir, getuid(), getgid());
#endif /* !_WINDOWS */

    return(0);
}


/*----------------------------------------------------------------------
      Create random directory

  Args: dir -- Name of the directory that contains the random directory
	len -- size of dir.

 Result: Directory is created.  Returns 0 on success, else -1 on error
	 and errno is valid.
  ----*/
int
create_random_dir(char *dir, size_t len)
{
    size_t olen, dlen = strlen(dir);

    olen = dlen;	/* save original length */

    if(dir[dlen-1] != C_FILESEP){
	 dir[dlen++] = C_FILESEP;
	 dir[dlen] = '\0';
    }

    if(dlen + 6 < len)
	strcat(dir, "XXXXXX");
    else{
	dir[olen] = '\0';
	return -1;
    }

#ifndef _WINDOWS
    dir = mkdtemp(dir);
    our_chmod(dir, MAILDIR_MODE);

    /* Some systems need this, on others we don't care if it fails */
    our_chown(dir, getuid(), getgid());
#else
    {	int i;
	char *s = &dir[strlen(dir) - 6];
	for(i = 0; i < 10; i++){
	   sprintf(s, "%x%x%x", (unsigned int)(random() % 256), (unsigned int)(random() % 256),
			     (unsigned int)(random() % 256));
	   if(our_mkdir(dir, 0700) == 0) return dir;
	}
	*dir = '\0';	/* if we are here, we failed! */
     }
#endif /* !_WINDOWS */

    return(0);
}
