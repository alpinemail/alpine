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

/* 
 * This is the private information of the client, which is passed to 
 * c-client for processing. Every c-client application must have its
 * own.
 */
OAUTH2_S alpine_oauth2_list[] =
{
  {"Gmail",
   {"imap.gmail.com", "smtp.gmail.com", NULL, NULL},
   {{"client_id", "624395471329-0qee3goofj7kbl7hsukou3rqq0igntv1.apps.googleusercontent.com"},
    {"client_secret", "vwnqVJQrJZpR6JilCfAN5nY7"},
    {"code", NULL},
    {"refresh_token", NULL},
    {"scope", "https://mail.google.com/"},
    {"redirect_uri", "urn:ietf:wg:oauth:2.0:oob"},
    {"grant_type", "authorization_code"},
    {"grant_type", "refresh_token"},
    {"response_type", "code"},
    {"state", NULL},
    {"prompt", NULL}
   },
   {{"GET", "https://accounts.google.com/o/oauth2/auth",
	{OA2_Id, OA2_Scope, OA2_Redirect, OA2_Response, OA2_End, OA2_End, OA2_End}},
    {"POST", "https://accounts.google.com/o/oauth2/token",
	{OA2_Id, OA2_Secret, OA2_Redirect, OA2_GrantTypeforAccessToken, OA2_Code, OA2_End, OA2_End}},
    {"POST", "https://accounts.google.com/o/oauth2/token",
	{OA2_Id, OA2_Secret, OA2_RefreshToken, OA2_GrantTypefromRefreshToken, OA2_End, OA2_End, OA2_End}}
   },
    NULL, 0
  },
#if 0
  {"Outlook",
   {"outlook.office365.com", "smtp.gmail.com", NULL, NULL},
//   {{"client_id", "2d681b88-9675-4ff0-b033-4de97dcb7a04"},
//    {"client_secret", "FHLY770;@%fmrzxbnEKG44!"},
   {{"client_id", "c8df0dbf-4750-4bb9-98e9-562b10caa26a"},
    {"client_secret", "ijrmPVDYP4yxbNL3442;!!_"},
    {"code", NULL},
    {"refresh_token", NULL},
    {"scope", "openid offline_access profile https://outlook.office.com/mail.readwrite https://outlook.office.com/mail.readwrite.shared https://outlook.office.com/mail.send https://outlook.office.com/mail.send.shared https://outlook.office.com/calendars.readwrite https://outlook.office.com/calendars.readwrite.shared https://outlook.office.com/contacts.readwrite https://outlook.office.com/contacts.readwrite.shared https://outlook.office.com/tasks.readwrite https://outlook.office.com/tasks.readwrite.shared https://outlook.office.com/mailboxsettings.readwrite https://outlook.office.com/people.read https://outlook.office.com/user.readbasic.all"},
    {"redirect_uri", "https://login.microsoftonline.com/common/oauth2/nativeclient"},
    {"grant_type", "authorization_code"},
    {"grant_type", "refresh_token"},
    {"response_type", "code"},
    {"state", NULL},
    {"prompt", "login"}
   },
   {{"GET", "https://login.microsoftonline.com/common/oauth2/authorize",
	{OA2_Id, OA2_Scope, OA2_Redirect, OA2_Response, OA2_State, OA2_Prompt, OA2_End}},
    {"POST", "https://login.microsoftonline.com/common/oauth2/token",
	{OA2_Id, OA2_Secret, OA2_Redirect, OA2_GrantTypeforAccessToken, OA2_Code, OA2_Scope, OA2_End}},
    {"POST", "https://login.microsoftonline.com/common/oauth2/token",
	{OA2_Id, OA2_Secret, OA2_RefreshToken, OA2_GrantTypefromRefreshToken, OA2_End, OA2_End, OA2_End}}
   },
    NULL, 0
  },
#endif
  { NULL, NULL, NULL, NULL, NULL, 0},
};
#endif /* ALPINE_XOAUTH2_INCLUDED */
