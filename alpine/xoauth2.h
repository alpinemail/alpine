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
#define OUTLOOK_ID   "c8df0dbf-4750-4bb9-98e9-562b10caa26a"
#define OUTLOOK_SECRET "ijrmPVDYP4yxbNL3442;!!_"

#endif /* ALPINE_XOAUTH2_INCLUDED */
