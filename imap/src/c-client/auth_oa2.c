/* ========================================================================
 * Copyright 2018 Eduardo Chappa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * 
 * ========================================================================
 */

long auth_oauth2_client (authchallenge_t challenger,authrespond_t responder,
			char *service,NETMBX *mb,void *stream,
			unsigned long *trial,char *user);

void mm_login_oauth2_c_client_method (NETMBX *, char *, OAUTH2_S *, unsigned long, int *);

char *oauth2_generate_state(void);

AUTHENTICATOR auth_oa2 = {
  AU_HIDE,			/* hidden */
  OA2NAME,			/* authenticator name */
  NIL,				/* always valid */
  auth_oauth2_client,		/* client method */
  NIL,				/* server method */
  NIL				/* next authenticator */
};

#define OAUTH2_USER	"user="
#define OAUTH2_BEARER	"auth=Bearer "

/* we generate something like a guid, but not care about
 * anything, but that it is really random.
 */
char *oauth2_generate_state(void)
{
  char rv[36];
  int i;

  rv[0] = '\0';
  for(i = 0; i < 4; i++)
     sprintf(rv + strlen(rv), "%x", random() % 256);
  sprintf(rv + strlen(rv), "%c", '-');
  for(i = 0; i < 2; i++)
     sprintf(rv + strlen(rv), "%x", random() % 256);
  sprintf(rv + strlen(rv), "%c", '-');
  for(i = 0; i < 2; i++)
     sprintf(rv + strlen(rv), "%x", random() % 256);
  sprintf(rv + strlen(rv), "%c", '-');
  for(i = 0; i < 2; i++)
     sprintf(rv + strlen(rv), "%x", random() % 256);
  sprintf(rv + strlen(rv), "%c", '-');
  for(i = 0; i < 6; i++)
     sprintf(rv + strlen(rv), "%x", random() % 256);
  rv[36] = '\0';
  return cpystr(rv);
}


/* Client authenticator
 * Accepts: challenger function
 *	    responder function
 *	    SASL service name
 *	    parsed network mailbox structure
 *	    stream argument for functions
 *	    pointer to current trial count
 *	    returned user name
 * Returns: T if success, NIL otherwise, number of trials incremented if retry
 */

long auth_oauth2_client (authchallenge_t challenger,authrespond_t responder,
			char *service,NETMBX *mb,void *stream,
			unsigned long *trial,char *user)
{
  char *u;
  void *challenge;
  unsigned long clen;
  long ret = NIL;
  OAUTH2_S oauth2;
  int tryanother = 0;	/* try another authentication method */

  memset((void *) &oauth2, 0, sizeof(OAUTH2_S));
				/* snarl if not SSL/TLS session */
  if (!mb->sslflag && !mb->tlsflag)
    mm_log ("SECURITY PROBLEM: insecure server advertised AUTH=XOAUTH2",WARN);

				/* get initial (empty) challenge */
  if ((challenge = (*challenger) (stream,&clen)) != NULL) {
    fs_give ((void **) &challenge);
    if (clen) {			/* abort if challenge non-empty */
      mm_log ("Server bug: non-empty initial XOAUTH2 challenge",WARN);
      (*responder) (stream,NIL,0);
      ret = LONGT;		/* will get a BAD response back */
    }

    /* 
     * the call to mm_login_method is supposed to return the username
     * and access token. If this is not known by the application, then
     * we call our internal functions to get a refresh token, access token
     * and expiration time.
     *
     * Programmers note: We always call mm_login_method at least once.
     * The first call is done with empty parameters and it indicates
     * we are asking the application to load it the best it can. Then
     * the application returns the loaded value. If we get it fully loaded
     * we use the value, but if we don't get it fully loaded, we call 
     * our internal functions to try to fully load it.
     *
     * If in the internal call we get it loaded, then we use these values
     * to log in. At this time we call the app to send back the loaded values
     * so it can save them for the next time we call. This is done in a
     * second call to mm_login_method. If we do not get oauth2 back with 
     * fully loaded values we cancel authentication completely. If the
     * user cannot load this variable, then the user, through the client,
     * should disable XOAUTH2 as an authentication method and try a new one.
     *
     * If we make our internal mm_login_oauth2_c_client_method call, 
     * we might still need to call the client to get the access token, 
     * this is done through a callback declared by the client. If we need 
     * that information, but the callback is not declared, this process 
     * will fail, so we will check if that call is declared as soon as we 
     * know we should start it, and we will only start it if this callback 
     * is declared.
     *
     * We start this process by calling the client and loading oauth2
     * with the required information as best as we can.
     */

    mm_login_method (mb, user, (void *) &oauth2, *trial, OA2NAME);

    if(oauth2.param[OA2_State].value)
      fs_give((void **) &oauth2.param[OA2_State].value);

    oauth2.param[OA2_State].value = oauth2_generate_state();

    /* 
     * If we did not get an access token, try to get one through 
     * our internal functions
     */
    if(oauth2.name && oauth2.access_token == NIL){
       char *RefreshToken = NIL;

       if(oauth2.param[OA2_RefreshToken].value)
	 RefreshToken = cpystr(oauth2.param[OA2_RefreshToken].value);

       mm_login_oauth2_c_client_method (mb, user, &oauth2, *trial, &tryanother);

       /* 
        * if we got an access token from the c_client_method call, 
        * or somehow there was a change in the refresh token, return
        * it to the client so that it will save it. 
        */

       if(!tryanother
	  && (oauth2.access_token 
	  || (!RefreshToken && oauth2.param[OA2_RefreshToken].value)
	  || (RefreshToken && oauth2.param[OA2_RefreshToken].value
	      && strcmp(RefreshToken, oauth2.param[OA2_RefreshToken].value))))
         mm_login_method (mb, user, (void *) &oauth2, *trial, OA2NAME);
    }

    /* empty challenge or user requested abort or client does not have info */
    if(!oauth2.access_token) {
      (*responder) (stream,NIL,0);
      *trial = 0;		/* cancel subsequent attempts */
      ret = LONGT;		/* will get a BAD response back */
    }
    else {
      unsigned long rlen = strlen(OAUTH2_USER) + strlen(user)
			+ strlen(OAUTH2_BEARER) + strlen(oauth2.access_token) + 1 + 2;
      char *response = (char *) fs_get (rlen);
      char *t = response;	/* copy authorization id */
      for (u = OAUTH2_USER; *u; *t++ = *u++);
      for (u = user; *u; *t++ = *u++);
      *t++ = '\001';		/* delimiting ^A */
      for (u = OAUTH2_BEARER; *u; *t++ = *u++);
      for (u = oauth2.access_token; *u; *t++ = *u++);
      *t++ = '\001';		/* delimiting ^A */
      *t++ = '\001';		/* delimiting ^A */
      if ((*responder) (stream,response,rlen)) {
	if ((challenge = (*challenger) (stream,&clen)) != NULL)
	  fs_give ((void **) &challenge);
	else {
	  ++*trial;				/* can try again if necessary */
	  ret = *trial < 3 ? LONGT : NIL;	/* check the authentication */
	  /* When the Access Token expires we fail once, but after we get
	   * a new one, we should succeed at the second attempt. If the
	   * Refresh Token has expired somehow, we invalidate it if we
	   * reach *trial to 3. This forces the process to restart later on.
	   */
	  if(*trial == 3){
	     if(oauth2.param[OA2_State].value)
		fs_give((void **) &oauth2.param[OA2_State].value);
	     fs_give((void **) &oauth2.param[OA2_RefreshToken].value);
	     fs_give((void **) &oauth2.access_token);
	     oauth2.expiration = 0L;
	  }
	}
      }
      fs_give ((void **) &response);
    }
  }
  if (!ret || !oauth2.name || tryanother) 
      *trial = 65535; 			/* don't retry if bad protocol */
  return ret;
}

/* 
 * The code above is enough to implement XOAUTH2, all one needs is the username
 * and access token and give it to the function above. However, normal users cannot
 * be expected to get the access token, so we ask the client to help with getting 
 * the access token, refresh token and expire values, so the code below is written
 * to help with that.
 */

#include "http.h"
#include "json.h"

void 
mm_login_oauth2_c_client_method (NETMBX *mb, char *user, 
			OAUTH2_S *oauth2, unsigned long trial, int *tryanother)
{
   int i;
   HTTP_PARAM_S params[OAUTH2_PARAM_NUMBER];
   OAUTH2_SERVER_METHOD_S RefreshMethod;
   char *s = NULL;
   JSON_S *json = NULL;

   if(oauth2->param[OA2_Id].value == NULL 
      || oauth2->param[OA2_Secret].value == NULL){
    /*
     * We need to implement client-side entering client_id and
     * client_secret, and other parameters. In the mean time, bail out.
     */
     return;
   }

   /* first check if we have a refresh token, and in that case use it */
   if(oauth2->param[OA2_RefreshToken].value){

     RefreshMethod = oauth2->server_mthd[OA2_GetAccessTokenFromRefreshToken];
     for(i = 0; RefreshMethod.params[i] != OA2_End; i++){
	OA2_type j = RefreshMethod.params[i];
	params[i].name  = oauth2->param[j].name;
	params[i].value = oauth2->param[j].value;
     }
     params[i].name = params[i].value = NULL;

     if(strcmp(RefreshMethod.name, "POST") == 0)
	s = http_post_param(RefreshMethod.urlserver, params);
     else if(strcmp(RefreshMethod.name, "POST2") == 0)
	s = http_post_param2(RefreshMethod.urlserver, params);

     if(s){
	unsigned char *t, *u;
	if((t = strstr(s, "\r\n\r\n")) && (u = strchr(t, '{')))
	   json = json_parse(&u);
	fs_give((void **) &s);
     }

     if(json != NULL){
	JSON_X *jx;

	jx = json_body_value(json, "access_token");
	if(jx && jx->jtype == JString)
	   oauth2->access_token = cpystr((char *) jx->value);

	jx = json_body_value(json, "expires_in");
	if(jx){
	   if(jx->jtype == JString){
	      unsigned long *l = fs_get(sizeof(unsigned long));
	      *l = atol((char *) jx->value);
	      fs_give(&jx->value);
	      jx->value = (void *) l;
	      jx->jtype = JLong;
	   }
	   if(jx->jtype == JLong)
	      oauth2->expiration   = time(0) + *(unsigned long *) jx->value;
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
   { 
     RefreshMethod = oauth2->server_mthd[OA2_GetAccessCode];
     for(i = 0; RefreshMethod.params[i] != OA2_End; i++){
	OA2_type j = RefreshMethod.params[i];
	params[i].name  = oauth2->param[j].name;
	params[i].value = oauth2->param[j].value;
     }
     params[i].name = params[i].value = NULL;

     if(strcmp(RefreshMethod.name, "GET") == 0){
	char *url = http_get_param_url(RefreshMethod.urlserver, params);
	oauth2getaccesscode_t ogac = 
	(oauth2getaccesscode_t) mail_parameters (NIL, GET_OA2CLIENTGETACCESSCODE, NIL);

	if(ogac)
	  oauth2->param[OA2_Code].value = (*ogac)(url, oauth2, tryanother);
     }

     if(oauth2->param[OA2_Code].value){
        RefreshMethod = oauth2->server_mthd[OA2_GetAccessTokenFromAccessCode];
        for(i = 0; RefreshMethod.params[i] != OA2_End; i++){
	   OA2_type j = RefreshMethod.params[i];
	   params[i].name  = oauth2->param[j].name;
	   params[i].value = oauth2->param[j].value;
        }
        params[i].name = params[i].value = NULL;

        if(strcmp(RefreshMethod.name, "POST") == 0)
	   s = http_post_param(RefreshMethod.urlserver, params);
	else if(strcmp(RefreshMethod.name, "POST2") == 0)
	   s = http_post_param2(RefreshMethod.urlserver, params);

        if(s){
	   unsigned char *t, *u;
	   if((t = strstr(s, "\r\n\r\n")) && (u = strchr(t, '{')))
		json = json_parse(&u);
	   fs_give((void **) &s);
        }

	if(json != NULL){
	   JSON_X *jx;

	   jx = json_body_value(json, "refresh_token");
	   if(jx && jx->jtype == JString)
	      oauth2->param[OA2_RefreshToken].value = cpystr((char *) jx->value);

	   jx = json_body_value(json, "access_token");
	   if(jx && jx->jtype == JString)
	      oauth2->access_token = cpystr((char *) jx->value);

	   jx = json_body_value(json, "expires_in");
	   if(jx){
	      if(jx->jtype == JString){
		unsigned long *l = fs_get(sizeof(unsigned long));
		*l = atol((char *) jx->value);
		fs_give(&jx->value);
		jx->value = (void *) l;
		jx->jtype = JLong;
	      }
	      if(jx->jtype == JLong)
	         oauth2->expiration = time(0) + *(unsigned long *) jx->value;
	   }
	   json_free(&json);
	}
     }
     return;
   }
}
