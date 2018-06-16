/*
 * $Id: init.h 900 2008-01-05 01:13:26Z hubert@u.washington.edu $
 *
 * ========================================================================
 * Copyright 2013-2018 Eduardo Chappa
 * Copyright 2006-2008 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 */

#ifndef PITH_INIT_INCLUDED
#define PITH_INIT_INCLUDED

#include "../pith/state.h"
#include "../pith/conftype.h"
#include "../pith/context.h"


#define ALPINE_VERSION		PACKAGE_VERSION

#define	LEGAL_NOTICE \
   "For Copyright information press \"?\""


typedef struct transfer_s {
        char *tname;  	/* the output name */
	int   is_exact_name;	/* is this the exact name of file or the root of the name */
        char *prepend;  /* what we need to prepend to get input name */
	char *subdir;	/* subdirectory of config_dir */
} TRANSFER_S;

   
#ifdef ALPINE_USE_CONFIG_DIR
#define CONFIG_SUBDIR	"config"
#define REMOTE_SUBDIR	"remote"
#define DEBUG_SUBDIR	"debug"
#define ABOOK_SUBDIR	"addressbook"
#define SGNTURE_SUBDIR	"signature"
#define MAILCAP_SUBDIR	"app"
#endif /* ALPINE_USE_CONFIG_DIR */

static TRANSFER_S transfer_list[] = {
#ifdef ALPINE_USE_CONFIG_DIR
#ifdef PASSFILE
	{PASSFILE, 1, "", NULL},
#endif /* PASSFILE */
	{USER_PINERC, 1, ".", CONFIG_SUBDIR},
	{USER_PINERCEX, 1, ".", CONFIG_SUBDIR},
	{DF_ADDRESSBOOK, 1, ".", ABOOK_SUBDIR},
	{USER_PINE_CRASH, 1, ".", DEBUG_SUBDIR},
	{DEBUGFILE, 0, ".", DEBUG_SUBDIR},
	{DF_SIGNATURE_FILE, 1, ".", SGNTURE_SUBDIR},
	{DF_PUBLICCERT_DIR, 1, ".", NULL},
	{DF_PRIVATEKEY_DIR, 1, ".", NULL},
	{DF_CACERT_DIR, 1, ".", NULL},
	{DF_PWDCERTDIR, 1, ".", NULL},
	{DF_SMIMETMPDIR, 1, ".", NULL},
#endif /* ALPINE_USE_CONFIG_DIR */
	{NULL, 0, NULL, NULL}
	};


/* exported protoypes */
int               init_username(struct pine *);
int               init_userdir(struct pine *);
int               init_hostname(struct pine *);
TRANSFER_S	  transfer_list_from_token(char *);
#ifdef ALPINE_USE_CONFIG_DIR
int		  init_config_dir(struct pine *);
int		  transfer_config_file(TRANSFER_S, char *, int *);
int		  rd_transfer_metadata(char *, char *);
int		  transfer_addressbook(char **, char *);
int		  transfer_signature(char *, char **, char *);
char		 *target_transfer_filename(char *);
#endif /* ALPINE_USE_CONFIG_DIR */
void              init_save_defaults(void);
int               check_prune_time(time_t *, struct tm **);
int               prune_move_folder(char *, char *, CONTEXT_S *);
int               first_run_of_month(void);
int               first_run_of_year(void);
struct sm_folder *get_mail_list(CONTEXT_S *, char *);
void		  display_init_err(char *, int);

#endif /* PITH_INIT_INCLUDED */
