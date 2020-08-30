/* ========================================================================
 * Copyright 2018 - 2020 Eduardo Chappa
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

long auth_oauth2_client (authchallenge_t challenger,authrespond_t responder, char *base,
			char *service,NETMBX *mb,void *stream, unsigned long port,
			unsigned long *trial,char *user);

AUTHENTICATOR auth_oa2 = {
  AU_HIDE | AU_SINGLE,		/* hidden */
  OA2NAME,			/* authenticator name */
  NIL,				/* always valid */
  auth_oauth2_client,		/* client method */
  NIL,				/* server method */
  NIL				/* next authenticator */
};

#define OAUTH2_USER	"user="
#define OAUTH2_BEARER	"auth=Bearer "

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

long auth_oauth2_client (authchallenge_t challenger,authrespond_t responder, char *base,
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
    mm_log ("SECURITY PROBLEM: insecure server advertised AUTH=XOAUTH2",WARN);

				/* get initial (empty) challenge */
  if (base || (challenge = (*challenger) (stream,&clen)) != NULL) {
    if(base == NIL){
	fs_give ((void **) &challenge);
	if (clen) {		/* abort if challenge non-empty */
	   mm_log ("Server bug: non-empty initial XOAUTH2 challenge",WARN);
	   (*responder) (stream,NIL,NIL,0);
	   ret = LONGT;		/* will get a BAD response back */
	}
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

       mm_login_oauth2_c_client_method (mb, user, OA2NAME, &oauth2, *trial, &tryanother);

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
         mm_login_method (mb, user, (void *) &oauth2, *trial, OA2NAME);
    }

    /* empty challenge or user requested abort or client does not have info */
    if(tryanother || !oauth2.access_token) {
       if (!base) (*responder) (stream,base,NIL,0);
      *trial = 0;		/* cancel subsequent attempts */
      ret = LONGT;		/* will get a BAD response back */
    }
    else {
      unsigned long rlen = strlen(OAUTH2_USER) + strlen(user)
			+ strlen(OAUTH2_BEARER) + strlen(oauth2.access_token) + 1 + 2;
      char *response = (char *) fs_get (rlen + 1);
      sprintf(response, "%s%s\001%s%s\001\001", OAUTH2_USER, user, OAUTH2_BEARER, oauth2.access_token);
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
