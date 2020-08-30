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

#include "oauth2_aux.h"

long auth_oauthbearer_client (authchallenge_t challenger,authrespond_t responder, char *base,
			char *service,NETMBX *mb,void *stream, unsigned long port,
			unsigned long *trial,char *user);

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
	      && strcmp(RefreshToken, oauth2.param[OA2_RefreshToken].value)
	  || oauth2.cancel_refresh_token)))
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
      char *response;

      sprintf(ports, "%lu", port);
      rlen = strlen(BEARER_ACCOUNT) + strlen(user) + 1 + 1
		+ strlen(BEARER_HOST) + strlen(mb->orighost) + 1
		+ strlen(BEARER_PORT) + strlen(ports) + 1
		+ strlen(OAUTH2_BEARER) + strlen(oauth2.access_token) + 2;
      response = (char *) fs_get (rlen+1);
      sprintf(response, "%s%s,\001%s%s\001%s%s\001%s%s\001\001", BEARER_ACCOUNT, user,
		BEARER_HOST, mb->orighost, BEARER_PORT, ports, OAUTH2_BEARER, oauth2.access_token);
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
  if(oauth2.param[OA2_Id].value) fs_give((void **) &oauth2.param[OA2_Id].value);
  if(oauth2.param[OA2_Secret].value) fs_give((void **) &oauth2.param[OA2_Secret].value);
  if(oauth2.param[OA2_Tenant].value) fs_give((void **) &oauth2.param[OA2_Tenant].value);
  if (!ret || !oauth2.name)
      *trial = 65535; 			/* don't retry if bad protocol */
  return ret;
}
