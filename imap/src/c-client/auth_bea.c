/* ========================================================================
 * Copyright 2020 Eduardo Chappa
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

long auth_oauthbearer_client (authchallenge_t challenger,authrespond_t responder, char *base,
			char *service,NETMBX *mb,void *stream, unsigned long port,
			unsigned long *trial,char *user);
#ifndef HTTP_OAUTH2_INCLUDED
void mm_login_oauth2_c_client_method (NETMBX *, char *, char *, OAUTH2_S *, unsigned long, int *);
#endif /* HTTP_OAUTH2_INCLUDED */

AUTHENTICATOR auth_bea = {
  AU_HIDE | AU_SINGLE,		/* hidden, single trip */
  BEARERNAME,			/* authenticator name */
  NIL,				/* always valid */
  auth_oauthbearer_client,	/* client method */
  NIL,				/* server method */
  NIL				/* next authenticator */
};

#define BEARER_ACCOUNT	"n,a="
#ifndef OAUTH2_BEARER
#define OAUTH2_BEARER	"auth=Bearer "
#endif
#define BEARER_HOST	"host="
#define BEARER_PORT	"port="

#ifndef OAUTH2_GENERATE_STATE
#define OAUTH2_GENERATE_STATE
char *oauth2_generate_state(void);

/* we generate something like a guid, but not care about
 * anything, but that it is really random.
 */
char *oauth2_generate_state(void)
{
  char rv[37];
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
#endif /* OAUTH2_GENERATE_STATE */

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

long auth_oauthbearer_client (authchallenge_t challenger,authrespond_t responder,char *base,
			char *service,NETMBX *mb,void *stream, unsigned long port,
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
    mm_log ("SECURITY PROBLEM: insecure server advertised AUTH=OAUTHBEARER",WARN);

				/* get initial (empty) challenge */
  if (base || (challenge = (*challenger) (stream,&clen)) != NULL) {
    if(base == NIL){
	 fs_give ((void **) &challenge);
         if (clen) {			/* abort if challenge non-empty */
	    mm_log ("Server bug: non-empty initial OAUTHBEARER challenge",WARN);
	    (*responder) (stream,NIL,NIL,0);
	    ret = LONGT;		/* will get a BAD response back */
	 }
    }

    mm_login_method (mb, user, (void *) &oauth2, *trial, BEARERNAME);

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

       mm_login_oauth2_c_client_method (mb, user, BEARERNAME, &oauth2, *trial, &tryanother);

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
         mm_login_method (mb, user, (void *) &oauth2, *trial, BEARERNAME);
    }

    /* empty challenge or user requested abort or client does not have info */
    if(tryanother || !oauth2.access_token) {
      if (!base)
	(*responder) (stream,NIL,NIL,0);
      *trial = 0;		/* cancel subsequent attempts */
      ret = LONGT;		/* will get a BAD response back */
    }
    else {
      char ports[10];
      unsigned long rlen;
      char *t, *response;

      sprintf(ports, "%lu", port);
      rlen = strlen(BEARER_ACCOUNT) + strlen(user) + 1 + 1
		+ strlen(BEARER_HOST) + strlen(mb->orighost) + 1
		+ strlen(BEARER_PORT) + strlen(ports) + 1
		+ strlen(OAUTH2_BEARER) + strlen(oauth2.access_token) + 2;
      t = response = (char *) fs_get (rlen);
      for (u = BEARER_ACCOUNT; *u; *t++ = *u++);
      for (u = user; *u; *t++ = *u++);
      *t++ = ',';
      *t++ = '\001';		/* delimiting ^A */
      for (u = BEARER_HOST; *u; *t++ = *u++);
      for (u = mb->orighost; *u; *t++ = *u++);
      *t++ = '\001';		/* delimiting ^A */
      for (u = BEARER_PORT; *u; *t++ = *u++);
      for (u = ports; *u; *t++ = *u++);
      *t++ = '\001';		/* delimiting ^A */
      for (u = OAUTH2_BEARER; *u; *t++ = *u++);
      for (u = oauth2.access_token; *u; *t++ = *u++);
      *t++ = '\001';		/* delimiting ^A */
      *t++ = '\001';		/* delimiting ^A */
      if ((*responder) (stream,base,response,rlen)) {
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
  if (!ret || !oauth2.name)
      *trial = 65535; 			/* don't retry if bad protocol */
  return ret;
}

#ifndef HTTP_OAUTH2_INCLUDED
#define HTTP_OAUTH2_INCLUDED
/* 
 * The code above is enough to implement OAUTHBEARER, all one needs is the username
 * and access token and give it to the function above. However, normal users cannot
 * be expected to get the access token, so we ask the client to help with getting 
 * the access token, refresh token and expire values, so the code below is written
 * to help with that.
 */

#include "http.h"
#include "json.h"

void 
mm_login_oauth2_c_client_method (NETMBX *mb, char *user, char *method,
			OAUTH2_S *oauth2, unsigned long trial, int *tryanother)
{
   int i;
   HTTP_PARAM_S params[OAUTH2_PARAM_NUMBER];
   OAUTH2_SERVER_METHOD_S RefreshMethod;
   unsigned char *s = NULL;
   JSON_S *json = NULL;
   int status = 0;

   if(oauth2->param[OA2_Id].value == NULL || oauth2->param[OA2_Secret].value == NULL){
     oauth2clientinfo_t ogci =
		(oauth2clientinfo_t) mail_parameters (NIL, GET_OA2CLIENTINFO, NIL);

     if(ogci) (*ogci)(oauth2->name, &oauth2->param[OA2_Id].value,
				&oauth2->param[OA2_Secret].value);
   }

   if(oauth2->param[OA2_Id].value == NULL || oauth2->param[OA2_Secret].value == NULL)
      return;

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
	s = http_post_param(RefreshMethod.urlserver, params, &status);
     else if(strcmp(RefreshMethod.name, "POST2") == 0)
	s = http_post_param2(RefreshMethod.urlserver, params, &status);

    if(status != 200 && s)
      fs_give((void **) &s);	/* at this moment ignore the reply text */

     if(s){
	unsigned char *u = s;
	json = json_parse(&u);
	fs_give((void **) &s);
     }

     if(json != NULL){
	JSON_X *jx;

	jx = json_body_value(json, "access_token");
	if(jx && jx->jtype == JString)
	   oauth2->access_token = cpystr((char *) jx->value);

	jx = json_body_value(json, "expires_in");
	if(jx && jx->jtype == JString)
	   oauth2->expiration   = time(0) + atol((char *) jx->value);

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
	  oauth2->param[OA2_Code].value = (*ogac)(url, method, oauth2, tryanother);
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
	   s = http_post_param(RefreshMethod.urlserver, params, &status);
	else if(strcmp(RefreshMethod.name, "POST2") == 0)
	   s = http_post_param2(RefreshMethod.urlserver, params, &status);

	if(status != 200 && s)
	   fs_give((void **) &s);	/* at this moment ignore the error */

        if(s){
	   unsigned char *u = s;
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
	   if(jx && jx->jtype == JString)
	      oauth2->expiration   = time(0) + atol((char *) jx->value);

	   json_free(&json);
	}
     }
     return;
   }
}
#endif /* HTTP_OAUTH2_INCLUDED */
