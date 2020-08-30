/*
 * ========================================================================
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
  

/* OAUTH2 support code goes here. This is necessary because
 * 1. it helps to coordinate two different methods, such as XOAUTH2 and
 *    OAUTHBEARER, which use the same code, so it can all go in one place
 *
 * 2. It helps with coordinating with the client when the server requires
 *    the deviceinfo method.
 */

#include "http.h"
#include "json.h"
#include "oauth2_aux.h"

/* we generate something like a guid, but not care about
 * anything, but that it is really random.
 */
char *oauth2_generate_state(void)
{
  char rv[37];
  int i;

  rv[0] = '\0';
  for(i = 0; i < 4; i++)
     sprintf(rv + strlen(rv), "%x", (unsigned int) (random() % 256));
  sprintf(rv + strlen(rv), "%c", '-');
  for(i = 0; i < 2; i++)
     sprintf(rv + strlen(rv), "%x", (unsigned int) (random() % 256));
  sprintf(rv + strlen(rv), "%c", '-');
  for(i = 0; i < 2; i++)
     sprintf(rv + strlen(rv), "%x", (unsigned int) (random() % 256));
  sprintf(rv + strlen(rv), "%c", '-');
  for(i = 0; i < 2; i++)
     sprintf(rv + strlen(rv), "%x", (unsigned int) (random() % 256));
  sprintf(rv + strlen(rv), "%c", '-');
  for(i = 0; i < 6; i++)
     sprintf(rv + strlen(rv), "%x", (unsigned int) (random() % 256));
  rv[36] = '\0';
  return cpystr(rv);
}


JSON_S *oauth2_json_reply(OAUTH2_SERVER_METHOD_S, OAUTH2_S *, int *);
char *xoauth2_server(char *, char *);

#define LOAD_HTTP_PARAMS(X, Y)	{				\
     int i;							\
     for(i = 0; (X).params[i] != OA2_End; i++){			\
	OA2_type j = (X).params[i];				\
	(Y)[i].name  = oauth2->param[j].name;			\
	(Y)[i].value = oauth2->param[j].value;			\
     }								\
     (Y)[i].name = (Y)[i].value = NULL;				\
}

char *xoauth2_server(char *server, char *tenant)
{
    char *rv = NULL;
    char *s;

    if (server == NULL) return NULL;

    s = cpystr(server);
    if(tenant){
	char *t = s, *u;
	int i;
	for(i = 0; t != NULL; i++){
	   t = strchr(t, '\001');
	   if(t != NULL) t++;
	}
	rv = fs_get((strlen(s) + i*(strlen(tenant)-1) + 1)*sizeof(char));
	*rv = '\0';
	for(u = t = s; t != NULL; i++){
	   t = strchr(t, '\001');
	   if (t != NULL) *t = '\0';
	   strcat(rv, u);
	   if(t != NULL){
	      strcat(rv, tenant);
	      *t++ = '\001';
	   }
	   u = t;
	}

    }
    else
      rv = cpystr(server);

    return rv;
}

JSON_S *oauth2_json_reply(OAUTH2_SERVER_METHOD_S RefreshMethod, OAUTH2_S *oauth2, int *status)
{
    JSON_S *json = NULL;
    HTTP_PARAM_S params[OAUTH2_PARAM_NUMBER];
    unsigned char *s;
    char *server = NULL;

    LOAD_HTTP_PARAMS(RefreshMethod, params);
    *status = 0;
    server = xoauth2_server(RefreshMethod.urlserver, oauth2->param[OA2_Tenant].value);
    if(strcmp(RefreshMethod.name, "POST") == 0
	&& ((s = http_post_param(server, params, status)) != NULL)){
	unsigned char *u = s;
	json = json_parse(&u);
	fs_give((void **) &s);
    }
    if(server)
	fs_give((void **) &server);

    return json;
}


void 
mm_login_oauth2_c_client_method (NETMBX *mb, char *user, char *method,
			OAUTH2_S *oauth2, unsigned long trial, int *tryanother)
{
   int status;
   char *s = NULL;
   JSON_S *json = NULL;

   if(oauth2->param[OA2_Id].value == NULL
	|| (oauth2->require_secret && oauth2->param[OA2_Secret].value == NULL)){
     XOAUTH2_INFO_S *x;
     oauth2clientinfo_t ogci =
		(oauth2clientinfo_t) mail_parameters (NIL, GET_OA2CLIENTINFO, NIL);

     if(ogci && (x = (*ogci)(oauth2->name, user)) != NULL){
	 oauth2->param[OA2_Id].value = cpystr(x->client_id);
	 oauth2->param[OA2_Secret].value = x->client_secret ? cpystr(x->client_secret) : NULL;
	 oauth2->param[OA2_Tenant].value = x->tenant ? cpystr(x->tenant) : NULL;
	 free_xoauth2_info(&x);
     }
   }

   if(oauth2->param[OA2_Id].value == NULL
	|| (oauth2->require_secret && oauth2->param[OA2_Secret].value == NULL))
      return;

   /* Do we have a method to execute? */
   if (oauth2->first_time && oauth2->server_mthd[OA2_GetDeviceCode].name){
     oauth2deviceinfo_t ogdi;

     json = oauth2_json_reply(oauth2->server_mthd[OA2_GetDeviceCode], oauth2, &status);

     if(json != NULL){
	JSON_X *jx;

	jx = json_body_value(json, "device_code");
	if(jx && jx->jtype == JString)
	   oauth2->devicecode.device_code = cpystr((char *) jx->value);

	jx = json_body_value(json, "user_code");
	if(jx && jx->jtype == JString)
	   oauth2->devicecode.user_code = cpystr((char *) jx->value);

	jx = json_body_value(json, "verification_uri");
	if(jx && jx->jtype == JString)
	   oauth2->devicecode.verification_uri = cpystr((char *) jx->value);

	if((jx = json_body_value(json, "expires_in")) != NULL)
	   switch(jx->jtype){
	      case JString: oauth2->devicecode.expires_in = atoi((char *) jx->value);
			    break;
	      case JLong  : oauth2->devicecode.expires_in = *(long *) jx->value;
			    break;
	   }

	if((jx = json_body_value(json, "interval")) != NULL)
	   switch(jx->jtype){
	      case JString: oauth2->devicecode.interval = atoi((char *) jx->value);
			    break;
	      case JLong  : oauth2->devicecode.interval = *(long *) jx->value;
			    break;
	   }

	jx = json_body_value(json, "message");
	if(jx && jx->jtype == JString)
	   oauth2->devicecode.message = cpystr((char *) jx->value);

	json_free(&json);

	if(oauth2->devicecode.verification_uri && oauth2->devicecode.user_code){
	   ogdi = (oauth2deviceinfo_t) mail_parameters (NIL, GET_OA2DEVICEINFO, NIL);
	   if(ogdi) (*ogdi)(oauth2, method);
	}
     }
     return;
   }

   /* else check if we have a refresh token, and in that case use it */

   if(oauth2->param[OA2_RefreshToken].value){
     json = oauth2_json_reply(oauth2->server_mthd[OA2_GetAccessTokenFromRefreshToken], oauth2, &status);

     if(json != NULL){
	JSON_X *jx;

	switch(status){
	   case HTTP_UNAUTHORIZED:
			mm_log("Client not authorized (wrong client-id?)", ERROR);
			break;
	   case HTTP_OK: jx = json_body_value(json, "access_token");
			 if(jx && jx->jtype == JString)
			   oauth2->access_token = cpystr((char *) jx->value);

			 if((jx = json_body_value(json, "expires_in")) != NULL)
			 switch(jx->jtype){
			      case JString: oauth2->expiration = time(0) + atol((char *) jx->value);
				    break;
			      case JLong  : oauth2->expiration = time(0) + *(long *) jx->value;
				    break;
			 }
			 oauth2->cancel_refresh_token = 0;	/* do not cancel this token. It is good */
			 break;

	     default :  { char tmp[100];
			  sprintf(tmp, "Oauth2 client Received Code %d", status);
			  mm_log (tmp, ERROR);
			  oauth2->cancel_refresh_token++;
			}
			break;
	}
	json_free(&json);
     }
     return;
   }
   /* 
    * else, we do not have a refresh token, nor an access token.
    * We need to start the process to get an access code. We use this
    * to get an access token and refresh token.
    */
   { OAUTH2_SERVER_METHOD_S RefreshMethod = oauth2->server_mthd[OA2_GetAccessCode];
     HTTP_PARAM_S params[OAUTH2_PARAM_NUMBER];

     LOAD_HTTP_PARAMS(RefreshMethod, params);

     if(strcmp(RefreshMethod.name, "GET") == 0){
	char *server = xoauth2_server(RefreshMethod.urlserver, oauth2->param[OA2_Tenant].value);
	char *url = http_get_param_url(server, params);
	oauth2getaccesscode_t ogac = 
	(oauth2getaccesscode_t) mail_parameters (NIL, GET_OA2CLIENTGETACCESSCODE, NIL);

	if(ogac)
	  oauth2->param[OA2_Code].value = (*ogac)(url, method, oauth2, tryanother);

	if(server) fs_give((void **) &server);
     }

     if(oauth2->param[OA2_Code].value){
	json = oauth2_json_reply(oauth2->server_mthd[OA2_GetAccessTokenFromAccessCode], oauth2, &status);

	if(json != NULL){
	   JSON_X *jx;

	  switch(status){
	     case HTTP_OK : jx = json_body_value(json, "refresh_token");
			     if(jx && jx->jtype == JString)
			       oauth2->param[OA2_RefreshToken].value = cpystr((char *) jx->value);

			     jx = json_body_value(json, "access_token");
			     if(jx && jx->jtype == JString)
			       oauth2->access_token = cpystr((char *) jx->value);

			     if((jx = json_body_value(json, "expires_in")) != NULL)
			     switch(jx->jtype){
				case JString: oauth2->expiration = time(0) + atol((char *) jx->value);
				    break;
				case JLong  : oauth2->expiration = time(0) + *(long *) jx->value;
				    break;
			     }

			     jx = json_body_value(json, "expires_in");
			     if(jx && jx->jtype == JString)
			       oauth2->expiration = time(0) + atol((char *) jx->value);

			     oauth2->cancel_refresh_token = 0;	/* do not cancel this token. It is good */

			     break;

	     case HTTP_BAD :  break;

		default   :  { char tmp[100];
			       sprintf(tmp, "Oauth2 Client Received Code %d", status);
			       mm_log (tmp, ERROR);
			       oauth2->cancel_refresh_token++;
			     }
	  }

	  json_free(&json);
	}
     }
     return;
   }
}

void oauth2deviceinfo_get_accesscode(void *inp, void *outp)
{
  OAUTH2_DEVICEPROC_S *oad = (OAUTH2_DEVICEPROC_S *) inp;
  OAUTH2_S *oauth2 = oad->xoauth2;
  OAUTH2_DEVICECODE_S *dcode = &oauth2->devicecode;
  int done = 0, status, rv;
  JSON_S *json;

  if(dcode->device_code && oauth2->param[OA2_DeviceCode].value == NULL)
     oauth2->param[OA2_DeviceCode].value = cpystr(dcode->device_code);

  rv = OA2_CODE_WAIT;	/* wait by default */
  json = oauth2_json_reply(oauth2->server_mthd[OA2_GetAccessTokenFromAccessCode], oauth2, &status);

  if(json != NULL){
     JSON_X *jx;
     char *error;

     switch(status){
	case HTTP_BAD : jx = json_body_value(json, "error");
			if(jx && jx->jtype == JString)
			  error = cpystr((char *) jx->value);
			else
			  break;

			if(compare_cstring(error, "authorization_pending") == 0)
			   rv = OA2_CODE_WAIT;
			else if(compare_cstring(error, "authorization_declined") == 0)
			   rv = OA2_CODE_FAIL;
			else if(compare_cstring(error, "bad_verification_code") == 0)
			   rv = OA2_CODE_FAIL;
			else if(compare_cstring(error, "expired_token") == 0)
			   rv = OA2_CODE_FAIL;
			else	/* keep waiting? */
			   rv = OA2_CODE_WAIT;

			break;

	case HTTP_OK :  jx = json_body_value(json, "refresh_token");
		        if(jx && jx->jtype == JString)
			   oauth2->param[OA2_RefreshToken].value = cpystr((char *) jx->value);

			jx = json_body_value(json, "access_token");
			if(jx && jx->jtype == JString)
			  oauth2->access_token = cpystr((char *) jx->value);

			if((jx = json_body_value(json, "expires_in")) != NULL)
			  switch(jx->jtype){
				case JString: oauth2->expiration = time(0) + atol((char *) jx->value);
				   break;
				case JLong  : oauth2->expiration = time(0) + *(long *) jx->value;
				   break;
			  }

			rv = OA2_CODE_SUCCESS;
			oauth2->cancel_refresh_token = 0;	/* do not cancel this token. It is good */

			break;

	     default :  { char tmp[100];
			  sprintf(tmp, "Oauth device Received Code %d", status);
			  mm_log (tmp, ERROR);
			  oauth2->cancel_refresh_token++;
			}
     }

     json_free(&json);
  }

  *(int *)outp = rv;
}

XOAUTH2_INFO_S *new_xoauth2_info(void)
{
  XOAUTH2_INFO_S *rv = fs_get(sizeof(XOAUTH2_INFO_S));
  memset((void *) rv, 0, sizeof(XOAUTH2_INFO_S));
  return rv;
}

void free_xoauth2_info(XOAUTH2_INFO_S **xp)
{
  if(xp == NULL || *xp == NULL) return;

  if((*xp)->name) fs_give((void **) &(*xp)->name);
  if((*xp)->client_id) fs_give((void **) &(*xp)->client_id);
  if((*xp)->client_secret) fs_give((void **) &(*xp)->client_secret);
  if((*xp)->tenant) fs_give((void **) &(*xp)->tenant);
  if((*xp)->flow) fs_give((void **) &(*xp)->flow);
  if((*xp)->users) fs_give((void **) &(*xp)->users);
  fs_give((void **) xp);
}

XOAUTH2_INFO_S *copy_xoauth2_info(XOAUTH2_INFO_S *x)
{
  XOAUTH2_INFO_S *y;

  if(x == NULL) return NULL;
  y = new_xoauth2_info();
  if(x->name) y->name = cpystr(x->name);
  if(x->client_id) y->client_id = cpystr(x->client_id);
  if(x->client_secret) y->client_secret = cpystr(x->client_secret);
  if(x->tenant) y->tenant = cpystr(x->tenant);
  if(x->flow) y->flow = cpystr(x->flow);
  if(x->users) y->users = cpystr(x->users);
  return y;
}

/* This function does not create a refresh token and and
 * an access token, but uses an already known refresh token
 * to generate a refresh token on an ALREADY OPEN stream.
 * The assumption is that the user has already unlocked all
 * passwords and the app can access them from some source
 * (key chain/credentials/memory) to go through this
 * process seamlessly.
 */
void renew_accesstoken(MAILSTREAM *stream)
{
    OAUTH2_S oauth2;
    NETMBX mb;
    char user[MAILTMPLEN];
    int tryanother;
    unsigned long trial = 0;

    memset((void *) &oauth2, 0, sizeof(OAUTH2_S));
    mail_valid_net_parse(stream->original_mailbox, &mb);
    user[0] = '\0';
    mm_login_method (&mb, user, (void *) &oauth2, trial, stream->auth.name);

    if(oauth2.param[OA2_State].value)
      fs_give((void **) &oauth2.param[OA2_State].value);

    if(stream->auth.expiration == 0){
       stream->auth.expiration = oauth2.expiration;
       return;
    }

    if(oauth2.access_token)
      fs_give((void **) &oauth2.access_token);

    oauth2.param[OA2_State].value = oauth2_generate_state();

    mm_login_oauth2_c_client_method (&mb, user, stream->auth.name, &oauth2, trial, &tryanother);

    if(oauth2.access_token)
	mm_login_method (&mb, user, (void *) &oauth2, trial, stream->auth.name);

    stream->auth.expiration = oauth2.expiration;
    if(oauth2.param[OA2_Id].value) fs_give((void **) &oauth2.param[OA2_Id].value);
    if(oauth2.param[OA2_Secret].value) fs_give((void **) &oauth2.param[OA2_Secret].value);
    if(oauth2.param[OA2_Tenant].value) fs_give((void **) &oauth2.param[OA2_Tenant].value);
}
