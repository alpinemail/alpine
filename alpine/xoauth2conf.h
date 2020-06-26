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
#include "xoauth2.h"
#include "../pith/state.h"

/* exported prototypes */
void	alpine_xoauth2_configuration(struct pine *, int);
XOAUTH2_INFO_S *xoauth_parse_client_info(char *);
XOAUTH2_INFO_S *oauth2_get_client_info(unsigned char *, char *);
char	*xoauth_config_line(XOAUTH2_INFO_S *);
void write_xoauth_conf_entry(XOAUTH2_INFO_S *, XOAUTH2_INFO_S *, CONF_S **, CONF_S **, CONF_S **, struct variable ***, int *, int, int);

#endif /* XOAUTH2_CONFIG */
