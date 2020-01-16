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

#ifndef XOAUTH2_CONFIG
#define XOAUTH2_CONFIG

#include "confscroll.h"
#include "../pith/state.h"

/* exported prototypes */
void	alpine_xoauth2_configuration(struct pine *, int);
void	xoauth_parse_client_info(char *, char **, char **, char **);
void	oauth2_get_client_info(char *, char **, char **);
char	*xoauth_config_line(char *, char *, char *);

#endif /* XOAUTH2_CONFIG */
