/*
 * ========================================================================
 * Copyright 2018 Eduardo Chappa
 * Copyright 2006-2009 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 */

#ifndef ALPINE_XOAUTH2_INCLUDED
#define ALPINE_XOAUTH2_INCLUDED

typedef struct xoauth_default_s {
   unsigned char *name;
   char *client_id;
   char *client_secret;
} XOAUTH2_INFO_S;

#define GMAIL_NAME "Gmail"
#define GMAIL_ID "624395471329-0qee3goofj7kbl7hsukou3rqq0igntv1.apps.googleusercontent.com"
#define GMAIL_SECRET "vwnqVJQrJZpR6JilCfAN5nY7"

#define OUTLOOK_NAME "Outlook"
#define OUTLOOK_ID   "f21dcaf2-8020-469b-8135-343bfc35d046"
#define OUTLOOK_SECRET "lIE42T4kZ2ZrN-2-AVNYSZ~8i_Co2WG4m."

#endif /* ALPINE_XOAUTH2_INCLUDED */
