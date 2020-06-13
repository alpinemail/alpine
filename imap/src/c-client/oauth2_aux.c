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

#define LOAD_HTTP_PARAMS(X, Y)	{				\
     int i;							\
     for(i = 0; (X).params[i] != OA2_End; i++){			\
	OA2_type j = (X).params[i];				\
	(Y)[i].name  = oauth2->param[j].name;			\
	(Y)[i].value = oauth2->param[j].value;			\
     }								\
     (Y)[i].name = (Y)[i].value = NULL;				\
}

JSON_S *oauth2_json_reply(OAUTH2_SERVER_METHOD_S RefreshMethod, OAUTH2_S *oauth2, int *status)
{
    JSON_S *json = NULL;
    HTTP_PARAM_S params[OAUTH2_PARAM_NUMBER];
    unsigned char *s;

    LOAD_HTTP_PARAMS(RefreshMethod, params);
    *status = 0;
    if(strcmp(RefreshMethod.name, "POST") == 0
	&& ((s = http_post_param(RefreshMethod.urlserver, params, status)) != NULL)){
	unsigned char *u = s;
	json = json_parse(&u);
	fs_give((void **) &s);
    }
    return json;
}


void 
mm_login_oauth2_c_client_method (NETMBX *mb, char *user, char *method,
			OAUTH2_S *oauth2, unsigned long trial, int *tryanother)
{
   int i, status;
   char *s = NULL;
   JSON_S *json = NULL;

   if(oauth2->param[OA2_Id].value == NULL
	|| (oauth2->require_secret && oauth2->param[OA2_Secret].value == NULL)){
     oauth2clientinfo_t ogci =
		(oauth2clientinfo_t) mail_parameters (NIL, GET_OA2CLIENTINFO, NIL);

     if(ogci) (*ogci)(oauth2->name, &oauth2->param[OA2_Id].value,
				&oauth2->param[OA2_Secret].value);
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
	char *url = http_get_param_url(RefreshMethod.urlserver, params);
	oauth2getaccesscode_t ogac = 
	(oauth2getaccesscode_t) mail_parameters (NIL, GET_OA2CLIENTGETACCESSCODE, NIL);

	if(ogac)
	  oauth2->param[OA2_Code].value = (*ogac)(url, method, oauth2, tryanother);
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

			     break;

	     case HTTP_BAD :  break;

		default   :  { char tmp[100];
			       sprintf(tmp, "Oauth Client Received Code %d", status);
			       fatal (tmp);
			     }
	  }

	  json_free(&json);
	}
     }
     return;
   }

   /* Else, does this server use the /devicecode method? */
}

void oauth2deviceinfo_get_accesscode(void *inp, void *outp)
{
  OAUTH2_DEVICEPROC_S *oad = (OAUTH2_DEVICEPROC_S *) inp;
  OAUTH2_S *oauth2 = oad->xoauth2;
  OAUTH2_DEVICECODE_S *dcode = &oauth2->devicecode;
  int done = 0, status, rv;
  HTTP_PARAM_S params[OAUTH2_PARAM_NUMBER];
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

			break;

	     default :  { char tmp[100];
			    sprintf(tmp, "Oauth device Received Code %d", status);
			    fatal (tmp);
			  }
     }

     json_free(&json);
  }

  *(int *)outp = rv;
}
