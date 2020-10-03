/*
 * $Id: imap.h 1074 2008-06-04 00:08:43Z hubert@u.washington.edu $
 *
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

#ifndef PINE_IMAP_INCLUDED
#define PINE_IMAP_INCLUDED


#include "../pith/imap.h"


/* exported prototypes */
void pine_parse_quota (MAILSTREAM *, unsigned char *, QUOTALIST *);
QUOTALIST *pine_quotalist_copy (QUOTALIST  *);
void   *pine_block_notify(int, void *);
long    pine_tcptimeout(long, long, char *);
long    pine_sslcertquery(char *, char *, char *);
char   *pine_newsrcquery(MAILSTREAM *, char *, char *);
int     url_local_certdetails(char *);
void    pine_sslfailure(char *, char *, unsigned long);
void	mm_expunged_current(long unsigned int);
IDLIST *set_alpine_id(unsigned char *, unsigned char *);
char   *oauth2_get_access_code(unsigned char *, char *, OAUTH2_S *, int *);
void    oauth2_set_device_info(OAUTH2_S *, char *);
int     oauth2_elapsed_done(void *);
UCS	oauth2device_decode_reply(void *, void *);

#ifdef	LOCAL_PASSWD_CACHE
int     get_passfile_passwd(char *, char **, char *, STRLIST_S *, int);
int     get_passfile_passwd_auth(char *, char **, char *, STRLIST_S *, int, char *);
int     is_using_passfile(void);
void    set_passfile_passwd(char *, char *, char *, STRLIST_S *, int, int);
void    set_passfile_passwd_auth(char *, char *, char *, STRLIST_S *, int, int, char *);
char   *get_passfile_user(char *, STRLIST_S *);
void	free_passfile_cache(void);
#endif	/* LOCAL_PASSWD_CACHE */

#if	(WINCRED > 0)
void    erase_windows_credentials(void);
#endif

#ifdef	APPLEKEYCHAIN
void    macos_erase_keychain(void);
#endif


#endif /* PINE_IMAP_INCLUDED */
