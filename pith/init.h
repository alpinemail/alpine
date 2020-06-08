/*
 * $Id: init.h 900 2008-01-05 01:13:26Z hubert@u.washington.edu $
 *
 * ========================================================================
 * Copyright 2013-2020 Eduardo Chappa
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

/* exported prototypes */
int               init_username(struct pine *);
int               init_userdir(struct pine *);
int               init_hostname(struct pine *);  
void              init_save_defaults(void);
int               check_prune_time(time_t *, struct tm **);
int               prune_move_folder(char *, char *, CONTEXT_S *);
int               first_run_of_month(void);
int               first_run_of_year(void);
struct sm_folder *get_mail_list(CONTEXT_S *, char *);
char		 *html_directory_path(char *, char *, size_t);
int		  init_html_directory(char *);
HTML_LOG_S	 *create_html_log(void);
void		  add_html_log(HTML_LOG_S **, char *);
void		  free_html_log(HTML_LOG_S **);
void		  html_dir_clean(int);

#endif /* PITH_INIT_INCLUDED */
