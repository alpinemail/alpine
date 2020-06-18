/* ========================================================================
 * Copyright 2018-2020 Eduardo Chappa
 * Copyright 2015      Imagination Technologies
 * Copyright 1988-2008 University of Washington
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

/*
 * Program:	NT LAN Manager authenticator
 *
 * Author:	Maciej W. Rozycki
 *
 * Date:	25 January 2015
 * Last Edited:	25 January 2015
 */

#include <ntlm.h>

long auth_ntlm_client (authchallenge_t challenger,authrespond_t responder,char *base,
			char *service,NETMBX *mb,void *stream, unsigned long port,
			unsigned long *trial,char *user);

AUTHENTICATOR auth_ntl = {	/* secure, has full auth, hidden */
  AU_SECURE | AU_AUTHUSER | AU_HIDE,
  "NTLM",			/* authenticator name */
  NIL,				/* always valid */
  auth_ntlm_client,		/* client method */
  NIL,				/* no server method */
  NIL				/* next authenticator */
};

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

long auth_ntlm_client (authchallenge_t challenger, authrespond_t responder,char *base,
		       char *service, NETMBX *mb, void *stream, unsigned long port,
		       unsigned long *trial, char *user)
{
  tSmbNtlmAuthChallenge *challenge;
  tSmbNtlmAuthResponse response;
  tSmbNtlmAuthRequest request;
  char tbuf[MAILTMPLEN];
  char ubuf[MAILTMPLEN];
  char *pass = NIL;
  unsigned long clen;
  unsigned long ulen;
  unsigned long dlen;
  long ret = NIL;
  char *sep;

				/* get initial (empty) challenge */
  if (challenge = (*challenger) (stream, &clen)) {
    fs_give ((void **) &challenge);
    mm_login (mb, user, &pass, *trial);
    if (!pass) {		/* user requested abort */
      (*responder) (stream, base, NIL, 0);
      *trial = 0;		/* cancel subsequent attempts */
      ret = LONGT;		/* will get a BAD response back */
    } else {
				/* translate domain\user to user@domain */
				/* otherwise buildSmbNtlmAuthResponse */
				/* will override the domain requested with */
				/* one returned by the challenge message */
      sep = strchr (user, '\\');
      if (*sep) {
	dlen = sep - user;
	ulen = strlen (sep + 1);
	memcpy (ubuf, sep + 1, ulen);
	ubuf[ulen] = '@';
	memcpy (ubuf + ulen + 1, user, dlen);
	ubuf[ulen + dlen + 1] = '\0';
	user = ubuf;
      }
      buildSmbNtlmAuthRequest (&request, user, NULL);
				/* send a negotiate message */
      if ((*responder) (stream, base, (void *) &request, SmbLength (&request)) &&
	  (challenge = (*challenger) (stream, &clen))) {
				/* interpret the challenge message */
	buildSmbNtlmAuthResponse (challenge, &response, user, pass);
        fs_give ((void **) &challenge);
				/* send a response message */
	if ((*responder) (stream, base, (void *) &response, SmbLength (&response))) {
	  if (challenge = (*challenger) (stream, &clen))
	    fs_give ((void **) &challenge);
	  else {
	    ++*trial;		/* can try again if necessary */
	    ret = LONGT;	/* check the authentication */
	  }
	}
      }
      if(pass) fs_give((void **) &pass);
    }
  }
  if(pass) fs_give((void **) &pass);
  if (!ret) *trial = 65535;	/* don't retry if bad protocol */
  return ret;
}
