/*
 * $Id: savetype.h 761 2007-10-23 22:35:18Z hubert@u.washington.edu $
 *
 * ========================================================================
 * Copyright 2013-2020 Eduardo Chappa
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

#ifndef PITH_SAVETYPE_INCLUDED
#define PITH_SAVETYPE_INCLUDED


#include "../pith/msgno.h"
#include "../pith/store.h"


typedef struct append_package {
  MAILSTREAM *stream;
  char *flags;
  char *date;
  STRING *msg;
  MSGNO_S *msgmap;
  long msgno;
  STORE_S *so;
} APPENDPACKAGE;


/* exported prototypes */


#endif /* PITH_SAVETYPE_INCLUDED */
