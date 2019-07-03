#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: imap.c 1266 2009-07-14 18:39:12Z hubert@u.washington.edu $";
#endif

/*
 * ========================================================================
 * Copyright 2013-2019 Eduardo Chappa
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

/*======================================================================
    imap.c
    The call back routines for the c-client/imap
       - handles error messages and other notification
       - handles prelimirary notification of new mail and expunged mail
       - prompting for imap server login and password 

 ====*/

#include "headers.h"
#include "alpine.h"
#include "imap.h"
#include "status.h"
#include "mailview.h"
#include "mailcmd.h"
#include "radio.h"
#include "keymenu.h"
#include "signal.h"
#include "mailpart.h"
#include "mailindx.h"
#include "arg.h"
#include "busy.h"
#include "titlebar.h"
#include "xoauth2.h"
#include "../pith/state.h"
#include "../pith/conf.h"
#include "../pith/msgno.h"
#include "../pith/filter.h"
#include "../pith/news.h"
#include "../pith/util.h"
#include "../pith/list.h"
#include "../pith/margin.h"
#ifdef SMIME
#include "../pith/smime.h"
#endif /* SMIME */

#if	(WINCRED > 0)
#include <wincred.h>
#define TNAME     "UWash_Alpine_"
#define TNAMESTAR "UWash_Alpine_*"

/*
 * WinCred Function prototypes
 */
typedef BOOL (WINAPI CREDWRITEW) ( __in PCREDENTIALW Credential, __in DWORD Flags );
typedef BOOL (WINAPI CREDENUMERATEW) ( __in LPCWSTR Filter, __reserved DWORD Flags,
        __out DWORD *Count, __deref_out_ecount(*Count) PCREDENTIALW **Credential );
typedef BOOL (WINAPI CREDDELETEW) ( __in LPCWSTR TargetName, __in DWORD Type,
        __reserved DWORD Flags );
typedef VOID (WINAPI CREDFREE) ( __in PVOID Buffer );

/*
 * WinCred functions
 */
int              g_CredInited = 0;  /* 1 for loaded successfully,
                                     * -1 for not available.
                                     * 0 for not initialized yet.
				     */
CREDWRITEW       *g_CredWriteW;
CREDENUMERATEW   *g_CredEnumerateW;
CREDDELETEW      *g_CredDeleteW;
CREDFREE         *g_CredFree;

#endif	/* WINCRED */

#ifdef	APPLEKEYCHAIN
#include <Security/SecKeychain.h>
#include <Security/SecKeychainItem.h>
#include <Security/SecKeychainSearch.h>
#define TNAME       "UWash_Alpine"
#define TNAMEPROMPT "UWash_Alpine_Prompt_For_Password"

int   macos_store_pass_prompt(void);
void  macos_set_store_pass_prompt(int);

static int storepassprompt = -1;
#endif	/* APPLEKEYCHAIN */


/*
 * Internal prototypes
 */
void  mm_login_alt_cue(NETMBX *);
long  pine_tcptimeout_noscreen(long, long, char *);
int   answer_cert_failure(int, MSGNO_S *, SCROLL_S *);
int   oauth2_auth_answer(int, MSGNO_S *, SCROLL_S *);

#ifdef	LOCAL_PASSWD_CACHE
int   read_passfile(char *, MMLOGIN_S **);
void  write_passfile(char *, MMLOGIN_S *);
int   preserve_prompt(char *);
int   preserve_prompt_auth(char *, char *authtype);
void  update_passfile_hostlist(char *, char *, STRLIST_S *, int);
void  update_passfile_hostlist_auth(char *, char *, STRLIST_S *, int, char *);
void  free_passfile_cache_work(MMLOGIN_S **);

static	MMLOGIN_S	*passfile_cache = NULL;
static  int             using_passfile = -1;
int  save_password = 1;
#endif	/* LOCAL_PASSWD_CACHE */

#ifdef	PASSFILE
char  xlate_in(int);
char  xlate_out(char);
int  line_get(char *, size_t, char **);
#endif	/* PASSFILE */

#if	(WINCRED > 0)
void  ask_erase_credentials(void);
int   init_wincred_funcs(void);
#endif	/* WINCRED */


static	char *details_cert, *details_host, *details_reason;

typedef struct auth_code_s {
  char *code;
  int   answer;
} AUTH_CODE_S;

char *
oauth2_get_access_code(char *url, OAUTH2_S *oauth2, int *tryanother)
{
   char tmp[MAILTMPLEN];
   char *code;

   if(ps_global->ttyo){
	SCROLL_S  sargs;
	STORE_S  *in_store, *out_store;
	gf_io_t   pc, gc;
	HANDLE_S *handles = NULL;
	AUTH_CODE_S user_input;

	if(!(in_store = so_get(CharStar, NULL, EDIT_ACCESS)) ||
	   !(out_store = so_get(CharStar, NULL, EDIT_ACCESS)))
	  goto try_wantto;

	so_puts(in_store, "<HTML><P>");
	sprintf(tmp, _("<CENTER>Auhtorizing Alpine Access to %s Email Services</CENTER>"), oauth2->name);
	so_puts(in_store, tmp);
	sprintf(tmp, _("</P><P>Alpine is attempting to log you into your %s account, using the XOAUTH2 method."), oauth2->name),
	so_puts(in_store, tmp);

	so_puts(in_store, _(" In order to do that, Alpine needs to open the following URL:"));
	so_puts(in_store,"</P><P>");
	sprintf(tmp_20k_buf, _("<A HREF=\"%s\">%s.</A>"), url, url);
	so_puts(in_store, tmp_20k_buf);

	so_puts(in_store, _("</P><P> Alpine will try to use your URL Viewers setting to find a browser to open this URL."));
	sprintf(tmp, _(" When you open this link, you will be sent to %s's servers to complete this process."), oauth2->name);
	so_puts(in_store, tmp);
	so_puts(in_store, _(" Alternatively, you can copy and paste the previous link and open it with the browser of your choice."));

        so_puts(in_store, _("</P><P> After you open the previous link, you will be asked to authenticate and later to authorize access to Alpine. "));
        so_puts(in_store, _(" At the end of this process, you will be given an access code or redirected to a web page."));
	so_puts(in_store, _(" If you see a code, copy it and then press 'C', and enter the code at the prompt."));
	so_puts(in_store, _(" If you do not see a code, copy the url of the page you were redirected to and again press 'C' and copy and paste it into the prompt. "));
	so_puts(in_store, _(" Once you have completed this process,  Alpine will proceed with authentication."));
	so_puts(in_store, _(" If you do not wish to proceed, cancel by pressing 'E' to exit"));
	so_puts(in_store, _("</P></HTML>"));

	so_seek(in_store, 0L, 0);
	init_handles(&handles);
	gf_filter_init();
	gf_link_filter(gf_html2plain,
		       gf_html2plain_opt(NULL,
					 ps_global->ttyo->screen_cols, non_messageview_margin(),
					 &handles, NULL, GFHP_LOCAL_HANDLES));
	gf_set_so_readc(&gc, in_store);
	gf_set_so_writec(&pc, out_store);
	gf_pipe(gc, pc);
	gf_clear_so_writec(out_store);
	gf_clear_so_readc(in_store);

	memset(&sargs, 0, sizeof(SCROLL_S));
	sargs.text.handles  = handles;
	sargs.text.text     = so_text(out_store);
	sargs.text.src      = CharStar;
	sargs.text.desc     = _("help text");
	sargs.bar.title     = _("SETTING UP XOAUTH2 AUTHORIZATION");
	sargs.proc.tool     = oauth2_auth_answer;
	sargs.proc.data.p   = (void *)&user_input;
	sargs.keys.menu     = &oauth2_auth_keymenu;
	/* don't want to re-enter c-client */
	sargs.quell_newmail = 1;
	setbitmap(sargs.keys.bitmap);
	sargs.help.text     = h_oauth2_start;
	sargs.help.title    = _("HELP FOR SETTING UP XOAUTH2");

	do {
	   scrolltool(&sargs);
	   ps_global->mangled_screen = 1;
	   ps_global->painted_body_on_startup = 0;
	   ps_global->painted_footer_on_startup = 0;
	} while (user_input.answer != 'e');

	if(!struncmp(user_input.code, "https://", 8)){
	     char *s, *t;
	     s = strstr(user_input.code, "code=");
	     if(s != NULL){
		t = strchr(s, '&');
		if(t) *t = '\0';
		code = cpystr(s+5);
		if(t) *t = '&';
	     }
	}
	else code = user_input.code ? cpystr(user_input.code) : NULL;
	if(user_input.code) fs_give((void **) &user_input.code);

	if(code == NULL) *tryanother = 1;

	so_give(&in_store);
	so_give(&out_store);
	free_handles(&handles);
    }
    else{
	int flags, rc, q_line;
	/* TRANSLATORS: user needs to input an access code from the server */
	char *accesscodelabel = _("Copy and Paste Access Code");
	char prompt[MAILTMPLEN], token[MAILTMPLEN];
	/*
	 * If screen hasn't been initialized yet, use want_to.
	 */
try_wantto:
	memset((void *)tmp, 0, sizeof(tmp));
	strncpy(tmp, _("Alpine would like to get authorization to access your email: "), sizeof(tmp));
	tmp[sizeof(tmp)-1] = '\0';
	strncat(tmp, _(": Proceed "), sizeof(tmp)-strlen(tmp)-1);

	if(want_to(tmp, 'n', 'x', NO_HELP, WT_NORM) == 'y'){
	  q_line = -(ps_global->ttyo ? ps_global->ttyo->footer_rows : 3);
	  flags = OE_APPEND_CURRENT;
	  sprintf(prompt, "%s: ", accesscodelabel);
	  do {
	     rc = optionally_enter(token, q_line, 0, MAILTMPLEN,
			   prompt, NULL, NO_HELP, &flags);
	  } while (rc != 0 && rc != 1);
	  if(!struncmp(token, "https://", 8)){
	     char *s, *t;
	     s = strstr(token, "code=");
	     if(s != NULL){
		t = strchr(s, '&');
		if(t) *t = '\0';
		code = cpystr(s+5);
		if(t) *t = '&';
	     }
	  }
	  else code = token[0] ? cpystr(token) : NULL;
	}
   }

   return code;
}

void mm_login_oauth2(NETMBX *, char *, OAUTH2_S *, long int, char *, char *);

/* The purpose of this function is to report to c-client the values of the
 * different tokens and codes so that c-client can try to log in the user
 * to the server. This function DOES NOT attempt to get these values for
 * the user. That is attempted in the c-client side (as best as it can be
 * done given our circumstances: no http support, no javascript support,
 * etc.). This is the best we can do:
 *
 * 1. In a first call, get an unloaded OAUTH2_S login pointer and load it
 *    as best as we can. Unloaded means that there is no server known to
 *    connect, no access token, etc. Pretty much nothing is known about
 *    how to get access code, access token, etc. We ask the user to fill
 *    it up for us, if they can. If the user fills it up we save those
 *    values.
 *
 * 2. In a subsequent call, if the OAUTH2_S login pointer is loaded, we
 *    save the information that c-client got for us.
 *
 * 3. When saving this information we use the password caching facilities,
 *    but we must do it in a different format so that old information and
 *    new information are not mixed. In order to accomodate this for new
 *    authentication methods, we save the information in the same fields,
 *    but this time we modify it slightly, so that old functions fail to
 *    understand the new information and so not modify it nor use it. The
 *    modification is simple: Every piece of information that was saved
 *    before is prepended  XOAUTH2\001 to indicate the authentication
 *    method for which it works. The character \001 is a separator. New 
 *    Alpine will know how to deal with this, but old versions, will not
 *    strip this prefix from the information and fail to get the
 *    information or modify it when needed. Only new versions of Alpine will
 *    know how to process this information.
 *       new_value             = authenticator_method separator old_value
 *       authenticator_method  = "XOAUTH2_S"
 *       separator             = "U+1"
 *    example: if old value is imap.gmail.com, the new value for the XOAUTH2
 *    authenticator is "XOAUTH2\001imap.gmail.com".
 *    In addition, the password field is not used to encode the password
 *    anymore, it is used to save login information needed in a format that
 *    the caller function chooses, but that must be preceeded by the 
 *    "authenticator_method separator" code as above.
 */
void
mm_login_oauth2(NETMBX *mb, char *user, OAUTH2_S *login, long int trial,
	        char *usethisprompt, char *altuserforcache)
{
    char      *token, tmp[MAILTMPLEN];
    char      prompt[4*MAILTMPLEN], value[4*MAILTMPLEN], *last;
    char      defuser[NETMAXUSER];
    char      hostleadin[80], hostname[200], defubuf[200];
    char      logleadin[80], pwleadin[50];
    char     *url_oauth2;
    char     *tool = NULL;
    char     *OldRefreshToken, *OldAccessToken;
    char     *NewRefreshToken, *NewAccessToken;
    char     *SaveRefreshToken, *SaveAccessToken;
    /* TRANSLATORS: A label for the hostname that the user is logging in on */
    char     *hostlabel = _("HOST");
    /* TRANSLATORS: user is logging in as a particular user (a particular
       login name), this is just labelling that user name. */
    char     *userlabel = _("USER");
    STRLIST_S hostlist[2], hostlist2[OAUTH2_TOT_EQUIV+1];
    HelpType  help ;
    int       len, rc, q_line, flags, i, j;
    int       oespace, avail, need, save_dont_use;
    int       save_in_init;
    int	      registered;
    int       ChangeAccessToken, ChangeRefreshToken, ChangeExpirationTime;
    OAUTH2_S  *oa2list;
    unsigned long OldExpirationTime, NewExpirationTime, SaveExpirationTime;
#if defined(_WINDOWS) || defined(LOCAL_PASSWD_CACHE)
    int       preserve_password = -1;
#endif

    dprint((9, "mm_login_oauth2 trial=%ld user=%s service=%s%s%s%s%s\n",
	       trial, mb->user ? mb->user : "(null)",
	       mb->service ? mb->service : "(null)",
	       mb->port ? " port=" : "",
	       mb->port ? comatose(mb->port) : "",
	       altuserforcache ? " altuserforcache =" : "",
	       altuserforcache ? altuserforcache : ""));

    q_line = -(ps_global->ttyo ? ps_global->ttyo->footer_rows : 3);

    save_in_init = ps_global->in_init_seq;
    ps_global->in_init_seq = 0;
    ps_global->no_newmail_check_from_optionally_enter = 1;

    /* make sure errors are seen */
    if(ps_global->ttyo)
      flush_status_messages(0);

    token = NULL;	/* start from scratch */

    hostlist[0].name = mb->host;
    if(mb->orighost && mb->orighost[0] && strucmp(mb->host, mb->orighost)){
       hostlist[0].next = &hostlist[1];
       hostlist[1].name = mb->orighost;
       hostlist[1].next = NULL;
    }
    else
       hostlist[0].next = NULL;

    if(hostlist[0].name){
	dprint((9, "mm_login_oauth2: host=%s\n",
	       hostlist[0].name ? hostlist[0].name : "?"));
	if(hostlist[0].next && hostlist[1].name){
	    dprint((9, "mm_login_oauth2: orighost=%s\n", hostlist[1].name));
	}
    }

    /*
     * We check to see if the server we are going to log in to is already
     * registered. This gives us a list of servers with the same
     * credentials, so we use the same credentials for all of them.
     */

    for(registered = 0, oa2list = alpine_oauth2_list; 
	  oa2list && oa2list->host != NULL && oa2list->host[0] != NULL;
	  oa2list++){
	for(i = 0; i < OAUTH2_TOT_EQUIV 
		   && oa2list->host[i] != NULL
		   && strucmp(oa2list->host[i], mb->orighost) != 0; i++);
	if(i < OAUTH2_TOT_EQUIV && oa2list->host[i] != NULL){
	   registered++;
	   break;
	}
    }

    if(registered){
       hostlist2[i = 0].name = mb->host;
       if(mb->orighost && mb->orighost[0] && strucmp(mb->host, mb->orighost))
          hostlist2[++i].name = mb->orighost;

       for(j = 0; j < OAUTH2_TOT_EQUIV && oa2list->host[j] != NULL; j++){
	  int k;
	  for(k = 0; k <= i && hostlist2[k].name 
		     && strcmp(hostlist2[k].name, oa2list->host[j]); k++);
	  if(k == i + 1)
	     hostlist2[++i].name = oa2list->host[j];
       }
       hostlist2[i+1].name = NULL;
       hostlist2[i+1].next = NULL;
       for(j = i; j >= 0; j--)
	  hostlist2[j].next = &hostlist2[j+1];
    }

    /*
     * We check if we have a refresh token saved somewhere, if so
     * we use it to get a new access token, otherwise we need to
     * get an access code so we can get (and save) a refresh token
     * and use the access token.
     */
    if(trial == 0L && !altuserforcache){
	int code;

	if(*mb->user != '\0')
	   strncpy(user, mb->user, NETMAXUSER);
	else{
	   flags = OE_APPEND_CURRENT;
	   sprintf(prompt, "%s: %s - %s: ", hostlabel, mb->orighost, userlabel);
	   rc = optionally_enter(user, q_line, 0, NETMAXUSER,
			   prompt, NULL, NO_HELP, &flags);
	}
	user[NETMAXUSER-1] = '\0';

	/* Search for a refresh token that is already loaded ... */
	if(imap_get_passwd_auth(mm_login_list, &token, user, 
	   registered ? hostlist2 : hostlist,
	   (mb->sslflag||mb->tlsflag), OA2NAME)){
	    dprint((9, "mm_login_oauth2: found a refresh token\n"));
	    ps_global->no_newmail_check_from_optionally_enter = 0;
	    ps_global->in_init_seq = save_in_init;
	}
#ifdef	LOCAL_PASSWD_CACHE
	/* or see if we have saved one in the local password cache and load it */
	else if(get_passfile_passwd_auth(ps_global->pinerc, &token,
			       user, registered ? hostlist2 : hostlist,
			       (mb->sslflag||mb->tlsflag), OA2NAME)){
	    imap_set_passwd_auth(&mm_login_list, token, user,
			    hostlist, (mb->sslflag||mb->tlsflag), 0, 0, OA2NAME);
	    update_passfile_hostlist_auth(ps_global->pinerc, user, hostlist,
				     (mb->sslflag||mb->tlsflag), OA2NAME);
	    dprint((9, "mm_login_oauth2: found a refresh token in cache\n"));
	    ps_global->no_newmail_check_from_optionally_enter = 0;
	    ps_global->in_init_seq = save_in_init;
	}
	if(token && *token) preserve_password = 1;   /* resave it, no need to ask */
#endif	/* LOCAL_PASSWD_CACHE */
    }
    user[NETMAXUSER-1] = '\0';

    /* The Old* variables is what c_client knows */
    OldRefreshToken   = login->param[OA2_RefreshToken].value;
    OldAccessToken    = login->access_token;
    OldExpirationTime = login->expiration;

    /* The New* variables is what Alpine knows */
    NewRefreshToken   = NewAccessToken  = NULL;
    NewExpirationTime = 0L;
    ChangeAccessToken = ChangeRefreshToken = ChangeExpirationTime = 0;

    if(token && *token){
       char *s, *t;

       s = token;
       t = strchr(s, PWDAUTHSEP);
       if(t == NULL)
	  NewRefreshToken = cpystr(s);
       else {
	  *t++ = '\0';
	  NewRefreshToken = cpystr(s);
	  s = t;
	  t = strchr(s, PWDAUTHSEP);
	  if(t == NULL)
	    NewAccessToken = cpystr(s);
	  else {
	     *t++ = '\0';
	     NewAccessToken = cpystr(s);
	     s = t;
	     NewExpirationTime = strtol(s, &s, 10);
	     if(NewExpirationTime <= 0 || NewExpirationTime <= time(0))
		NewExpirationTime = 0L;
	  }
       }
       /* check we got good information, and send good information below */
       if(NewRefreshToken && !*NewRefreshToken)
	  fs_give((void **) &NewRefreshToken);
       if(NewAccessToken && (NewExpirationTime == 0L || !*NewAccessToken)) 
	  fs_give((void **) &NewAccessToken);
    }

    /* Default to saving what we already had saved */

    SaveRefreshToken = NewRefreshToken;
    SaveAccessToken  = NewAccessToken;
    SaveExpirationTime = NewExpirationTime;

    /* Translation of the logic below:
     * if (c-client has a refresh token
	   and (alpine does not have a refresh token or (alpine and c-client have different refresh tokens)){
	   forget the Alpine refresh token;
	   make the Alpine Refresh token = c-client refresh token.;
	   signal that we changed the refresh token;
	   In this situation we do not need to clear up the Alpine access token. This will
           expire, so we can use it until it expires. We can save the c-client refresh token
           together with the Alpine Access Token and the expiration date of the Alpine Access
	   Token.
       } else if(c-client does not have a refresh token and Alpine has one and this is not the first attempt){
	   forget the Alpine refresh token;
	   if Alpine has an access token, forget it;
	   reset the expiration time
	   signal that we changed the refresh token;  (because the service expired it)
       }
     */

    if(OldRefreshToken != NULL 
	&& (NewRefreshToken == NULL || strcmp(OldRefreshToken, NewRefreshToken))){
	if(NewRefreshToken) fs_give((void **) &NewRefreshToken);
	NewRefreshToken = cpystr(OldRefreshToken);
	ChangeRefreshToken++;
	SaveRefreshToken = OldRefreshToken;
	SaveAccessToken  = NewAccessToken;
	SaveExpirationTime = NewExpirationTime;
    } else if (OldRefreshToken == NULL && NewRefreshToken != NULL && trial > 0){
	fs_give((void **) &NewRefreshToken);
	if(NewAccessToken) fs_give((void **) &NewAccessToken);
	NewExpirationTime = 0L;
	ChangeRefreshToken++;
	SaveRefreshToken = NULL;
	SaveAccessToken  = NULL;
	SaveExpirationTime = 0L;
    }

    if(OldAccessToken != NULL 
	&& (NewAccessToken == NULL || strcmp(OldAccessToken, NewAccessToken))){
	if(NewAccessToken) fs_give((void **) &NewAccessToken);
	NewAccessToken = cpystr(OldAccessToken);
	ChangeAccessToken++;
	NewExpirationTime = OldExpirationTime;
	SaveRefreshToken = NewRefreshToken;
	SaveAccessToken  = NewAccessToken;
	SaveExpirationTime = NewExpirationTime;
    }

    if(!registered){
       login->param[OA2_RefreshToken].value = SaveRefreshToken;
       login->access_token = SaveAccessToken;
       login->expiration = SaveExpirationTime;
    } else {
       oa2list->param[OA2_RefreshToken].value = SaveRefreshToken;
       oa2list->access_token = SaveAccessToken;
       oa2list->expiration = SaveExpirationTime;
      *login = *oa2list;	/* load login pointer */
    }

    if(!ChangeAccessToken && !ChangeRefreshToken)
       return;

    /* get ready to save this information. The format will be
     *  RefreshToken \001 LastAccessToken \001 ExpirationTime
     * (spaces added for clarity, \001 is PWDAUTHSEP)
     */
    if(token) fs_give((void **) &token);
    sprintf(tmp, "%lu", SaveExpirationTime);
    tmp[sizeof(tmp) - 1] = '\0';
    len = strlen(SaveRefreshToken ? SaveRefreshToken : "")
		  + strlen(SaveAccessToken ? SaveAccessToken : "")
		  + strlen(tmp) + 2;
    token = fs_get(len + 1);
    sprintf(token, "%s%c%s%c%lu", 
		    SaveRefreshToken ? SaveRefreshToken : "", PWDAUTHSEP,
		    SaveAccessToken  ? SaveAccessToken  : "", PWDAUTHSEP, 
		    SaveExpirationTime);

    /* remember the access information for next time */
    if(F_OFF(F_DISABLE_PASSWORD_CACHING,ps_global))
	    imap_set_passwd_auth(&mm_login_list, token,
		      altuserforcache ? altuserforcache : user, hostlist,
		      (mb->sslflag||mb->tlsflag), 0, 0, OA2NAME);
#ifdef	LOCAL_PASSWD_CACHE
#ifdef	PASSFILE
    /* if requested, remember it on disk for next session */
    if(save_password && F_OFF(F_DISABLE_PASSWORD_FILE_SAVING,ps_global))
	    set_passfile_passwd_auth(ps_global->pinerc, token,
		        altuserforcache ? altuserforcache : user, hostlist,
			(mb->sslflag||mb->tlsflag),
			(preserve_password == -1 ? 0
			 : (preserve_password == 0 ? 2 :1)), OA2NAME);
#endif	/* PASSFILE */
#endif	/* LOCAL_PASSWD_CACHE */

    ps_global->no_newmail_check_from_optionally_enter = 0;
}

/*----------------------------------------------------------------------
         recieve notification from IMAP

  Args: stream  --  Mail stream message is relavant to 
        string  --  The message text
        errflg  --  Set if it is a serious error

 Result: message displayed in status line

 The facility is for general notices, such as connection to server;
 server shutting down etc... It is used infrequently.
  ----------------------------------------------------------------------*/
void
mm_notify(MAILSTREAM *stream, char *string, long int errflg)
{
    time_t      now;
    struct tm  *tm_now;

    now = time((time_t *)0);
    tm_now = localtime(&now);

    /* be sure to log the message... */
#ifdef DEBUG
    if(ps_global->debug_imap || ps_global->debugmem)
      dprint((errflg == TCPDEBUG ? 7 : 2,
	      "IMAP %2.2d:%2.2d:%2.2d %d/%d mm_notify %s: %s: %s\n",
	      tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec,
	      tm_now->tm_mon+1, tm_now->tm_mday,
              (!errflg)            ? "babble"     : 
	       (errflg == ERROR)    ? "error"   :
	        (errflg == WARN)     ? "warning" :
	         (errflg == PARSE)    ? "parse"   :
		  (errflg == TCPDEBUG) ? "tcp"     :
		   (errflg == BYE)      ? "bye"     : "unknown",
	      (stream && stream->mailbox) ? stream->mailbox : "-no folder-",
	      string ? string : "?"));
#endif

    snprintf(ps_global->last_error, sizeof(ps_global->last_error), "%s : %.*s",
	    (stream && stream->mailbox) ? stream->mailbox : "-no folder-",
	    (int) MIN(MAX_SCREEN_COLS, sizeof(ps_global->last_error)-70),
	    string);
    ps_global->last_error[ps_global->ttyo ? ps_global->ttyo->screen_cols
		    : sizeof(ps_global->last_error)-1] = '\0';

    /*
     * Then either set special bits in the pine struct or
     * display the message if it's tagged as an "ALERT" or
     * its errflg > NIL (i.e., WARN, or ERROR)
     */
    if(errflg == BYE)
      /*
       * We'd like to sp_mark_stream_dead() here but we can't do that because
       * that might call mail_close and we are already in a c-client callback.
       * So just set the dead bit and clean it up later.
       */
      sp_set_dead_stream(stream, 1);
    else if(!strncmp(string, "[TRYCREATE]", 11))
      ps_global->try_to_create = 1;
    else if(!strncmp(string, "[REFERRAL ", 10))
      ;  /* handled in the imap_referral() callback */
    else if(!strncmp(string, "[ALERT]", 7))
      q_status_message2(SM_MODAL, 3, 3,
		        _("Alert received while accessing \"%s\":  %s"),
			(stream && stream->mailbox)
			  ? stream->mailbox : "-no folder-",
			rfc1522_decode_to_utf8((unsigned char *)(tmp_20k_buf+10000),
					       SIZEOF_20KBUF-10000, string));
    else if(!strncmp(string, "[UNSEEN ", 8)){
	char *p;
	long  n = 0;

	for(p = string + 8; isdigit(*p); p++)
	  n = (n * 10) + (*p - '0');

	sp_set_first_unseen(stream, n);
    }
    else if(!strncmp(string, "[READ-ONLY]", 11)
	    && !(stream && stream->mailbox && IS_NEWS(stream)))
      q_status_message2(SM_ORDER | SM_DING, 3, 3, "%s : %s",
			(stream && stream->mailbox)
			  ? stream->mailbox : "-no folder-",
			string + 11);
    else if((errflg && errflg != BYE && errflg != PARSE)
	    && !ps_global->noshow_error
	    && !(errflg == WARN
	         && (ps_global->noshow_warn || (stream && stream->unhealthy))))
      q_status_message(SM_ORDER | ((errflg == ERROR) ? SM_DING : 0),
			   3, 6, ps_global->last_error);
}


/*----------------------------------------------------------------------
      Queue imap log message for display in the message line

   Args: string -- The message 
         errflg -- flag set to 1 if pertains to an error

 Result: Message queued for display

 The c-client/imap reports most of it's status and errors here
  ---*/
void
mm_log(char *string, long int errflg)
{
    char        message[sizeof(ps_global->c_client_error)];
    char       *occurence;
    int         was_capitalized;
    static char saw_kerberos_init_warning;
    time_t      now;
    struct tm  *tm_now;

    now = time((time_t *)0);
    tm_now = localtime(&now);

    dprint((((errflg == TCPDEBUG) && ps_global->debug_tcp) ? 1 :
           (errflg == TCPDEBUG) ? 10 : 2,
	    "IMAP %2.2d:%2.2d:%2.2d %d/%d mm_log %s: %s\n",
	    tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec,
	    tm_now->tm_mon+1, tm_now->tm_mday,
            (!errflg)            ? "babble"  : 
	     (errflg == ERROR)    ? "error"   :
	      (errflg == WARN)     ? "warning" :
	       (errflg == PARSE)    ? "parse"   :
		(errflg == TCPDEBUG) ? "tcp"     :
		 (errflg == BYE)      ? "bye"     : "unknown",
	    string ? string : "?"));

    if(errflg == ERROR && !strncmp(string, "[TRYCREATE]", 11)){
	ps_global->try_to_create = 1;
	return;
    }
    else if(ps_global->try_to_create
       || !strncmp(string, "[CLOSED]", 8)
       || (sp_dead_stream(ps_global->mail_stream) && strstr(string, "No-op")))
      /*
       * Don't display if creating new folder OR
       * warning about a dead stream ...
       */
      return;

    strncpy(message, string, sizeof(message));
    message[sizeof(message) - 1] = '\0';

    if(errflg == WARN && srchstr(message, "try running kinit") != NULL){
	if(saw_kerberos_init_warning)
	  return;

	saw_kerberos_init_warning = 1;
    }

    /*---- replace all "mailbox" with "folder" ------*/
    occurence = srchstr(message, "mailbox");
    while(occurence) {
	if(!*(occurence+7)
	   || isspace((unsigned char) *(occurence+7))
	   || *(occurence+7) == ':'){
	    was_capitalized = isupper((unsigned char) *occurence);
	    rplstr(occurence, sizeof(message)-(occurence-message), 7, (errflg == PARSE ? "address" : "folder"));
	    if(was_capitalized)
	      *occurence = (errflg == PARSE ? 'A' : 'F');
	}
	else
	  occurence += 7;

        occurence = srchstr(occurence, "mailbox");
    }

    /*---- replace all "GSSAPI" with "Kerberos" ------*/
    occurence = srchstr(message, "GSSAPI");
    while(occurence) {
	if(!*(occurence+6)
	   || isspace((unsigned char) *(occurence+6))
	   || *(occurence+6) == ':')
	  rplstr(occurence, sizeof(message)-(occurence-message), 6, "Kerberos");
	else
	  occurence += 6;

        occurence = srchstr(occurence, "GSSAPI");
    }

    if(errflg == ERROR)
      ps_global->mm_log_error = 1;

    if(errflg == PARSE || (errflg == ERROR && ps_global->noshow_error))
      strncpy(ps_global->c_client_error, message,
	      sizeof(ps_global->c_client_error));

    if(ps_global->noshow_error
       || (ps_global->noshow_warn && errflg == WARN)
       || !(errflg == ERROR || errflg == WARN))
      return; /* Only care about errors; don't print when asked not to */

    /*---- Display the message ------*/
    q_status_message((errflg == ERROR) ? (SM_ORDER | SM_DING) : SM_ORDER,
		     3, 5, message);
    strncpy(ps_global->last_error, message, sizeof(ps_global->last_error));
    ps_global->last_error[sizeof(ps_global->last_error) - 1] = '\0';
}

void
mm_login_method_work(NETMBX *mb, char *user, void *login, long int trial,
	      char *method, char *usethisprompt, char *altuserforcache)
{
   if(method == NULL)
      return;
   if(strucmp(method, OA2NAME) == 0)
     mm_login_oauth2(mb, user, (OAUTH2_S *) login, trial, usethisprompt, altuserforcache);
}

void
mm_login_work(NETMBX *mb, char *user, char **pwd, long int trial,
	      char *usethisprompt, char *altuserforcache)
{
    char      tmp[MAILTMPLEN];
    char      prompt[1000], *last;
    char      port[20], non_def_port[20], insecure[20];
    char      defuser[NETMAXUSER];
    char      hostleadin[80], hostname[200], defubuf[200];
    char      logleadin[80], pwleadin[50];
    char      hostlist0[MAILTMPLEN], hostlist1[MAILTMPLEN];
    /* TRANSLATORS: when logging in, this text is added to the prompt to show
       that the password will be sent unencrypted over the network. This is
       just a warning message that gets added parenthetically when the user
       is asked for a password. */
    char     *insec = _(" (INSECURE)");
    /* TRANSLATORS: Retrying is shown when the user is being asked for a password
       after having already failed at least once. */
    char     *retry = _("Retrying - ");
    /* TRANSLATORS: A label for the hostname that the user is logging in on */
    char     *hostlabel = _("HOST");
    /* TRANSLATORS: user is logging in as a particular user (a particular
       login name), this is just labelling that user name. */
    char     *userlabel = _("USER");
    STRLIST_S hostlist[2];
    HelpType  help ;
    int       len, rc, q_line, flags;
    int       oespace, avail, need, save_dont_use;
    int       save_in_init;
    struct servent *sv;
#if defined(_WINDOWS) || defined(LOCAL_PASSWD_CACHE)
    int       preserve_password = -1;
#endif

    dprint((9, "mm_login_work trial=%ld user=%s service=%s%s%s%s%s\n",
	       trial, mb->user ? mb->user : "(null)",
	       mb->service ? mb->service : "(null)",
	       mb->port ? " port=" : "",
	       mb->port ? comatose(mb->port) : "",
	       altuserforcache ? " altuserforcache =" : "",
	       altuserforcache ? altuserforcache : ""));
    q_line = -(ps_global->ttyo ? ps_global->ttyo->footer_rows : 3);

    save_in_init = ps_global->in_init_seq;
    ps_global->in_init_seq = 0;
    ps_global->no_newmail_check_from_optionally_enter = 1;

    /* make sure errors are seen */
    if(ps_global->ttyo)
      flush_status_messages(0);

    /*
     * Add port number to hostname if going through a tunnel or something
     */
    non_def_port[0] = '\0';
    if(mb->port && mb->service &&
       (sv = getservbyname(mb->service, "tcp")) &&
       (mb->port != ntohs(sv->s_port))){
	snprintf(non_def_port, sizeof(non_def_port), ":%lu", mb->port);
	non_def_port[sizeof(non_def_port)-1] = '\0';
	dprint((9, "mm_login: using non-default port=%s\n",
		   non_def_port ? non_def_port : "?"));
    }

    /*
     * set up host list for sybil servers...
     */
    if(*non_def_port){
	strncpy(hostlist0, mb->host, sizeof(hostlist0)-1);
	hostlist0[sizeof(hostlist0)-1] = '\0';
	strncat(hostlist0, non_def_port, sizeof(hostlist0)-strlen(hostlist0)-1);
	hostlist0[sizeof(hostlist0)-1] = '\0';
	hostlist[0].name = hostlist0;
	if(mb->orighost && mb->orighost[0] && strucmp(mb->host, mb->orighost)){
	    strncpy(hostlist1, mb->orighost, sizeof(hostlist1)-1);
	    hostlist1[sizeof(hostlist1)-1] = '\0';
	    strncat(hostlist1, non_def_port, sizeof(hostlist1)-strlen(hostlist1)-1);
	    hostlist1[sizeof(hostlist1)-1] = '\0';
	    hostlist[0].next = &hostlist[1];
	    hostlist[1].name = hostlist1;
	    hostlist[1].next = NULL;
	}
	else
	  hostlist[0].next = NULL;
    }
    else{
	hostlist[0].name = mb->host;
	if(mb->orighost && mb->orighost[0] && strucmp(mb->host, mb->orighost)){
	    hostlist[0].next = &hostlist[1];
	    hostlist[1].name = mb->orighost;
	    hostlist[1].next = NULL;
	}
	else
	  hostlist[0].next = NULL;
    }

    if(hostlist[0].name){
	dprint((9, "mm_login: host=%s\n",
	       hostlist[0].name ? hostlist[0].name : "?"));
	if(hostlist[0].next && hostlist[1].name){
	    dprint((9, "mm_login: orighost=%s\n", hostlist[1].name));
	}
    }

    /*
     * Initialize user name with either 
     *     1) /user= value in the stream being logged into,
     *  or 2) the user name we're running under.
     *
     * Note that VAR_USER_ID is not yet initialized if this login is
     * the one to access the remote config file. In that case, the user
     * can supply the username in the config file name with /user=.
     */
    if(trial == 0L && !altuserforcache){
	strncpy(user, (*mb->user) ? mb->user :
		       ps_global->VAR_USER_ID ? ps_global->VAR_USER_ID : "",
		       NETMAXUSER);
	user[NETMAXUSER-1] = '\0';

	/* try last working password associated with this host. */
	if(imap_get_passwd(mm_login_list, pwd, user, hostlist,
	   (mb->sslflag||mb->tlsflag))){
	    dprint((9, "mm_login: found a password to try\n"));
	    ps_global->no_newmail_check_from_optionally_enter = 0;
	    ps_global->in_init_seq = save_in_init;
	    return;
	}

#ifdef	LOCAL_PASSWD_CACHE
	/* check to see if there's a password left over from last session */
	if(get_passfile_passwd(ps_global->pinerc, pwd,
			       user, hostlist, (mb->sslflag||mb->tlsflag))){
	    imap_set_passwd(&mm_login_list, *pwd, user,
			    hostlist, (mb->sslflag||mb->tlsflag), 0, 0);
	    update_passfile_hostlist(ps_global->pinerc, user, hostlist,
				     (mb->sslflag||mb->tlsflag));
	    dprint((9, "mm_login: found a password in passfile to try\n"));
	    ps_global->no_newmail_check_from_optionally_enter = 0;
	    ps_global->in_init_seq = save_in_init;
	    return;
	}
#endif	/* LOCAL_PASSWD_CACHE */

	/*
	 * If no explicit user name supplied and we've not logged in
	 * with our local user name, see if we've visited this
	 * host before as someone else.
	 */
	if(!*mb->user &&
	   ((last = imap_get_user(mm_login_list, hostlist))
#ifdef	LOCAL_PASSWD_CACHE
	    ||
	    (last = get_passfile_user(ps_global->pinerc, hostlist))
#endif	/* LOCAL_PASSWD_CACHE */
								   )){
	    strncpy(user, last, NETMAXUSER);
	    user[NETMAXUSER-1] = '\0';
	    dprint((9, "mm_login: found user=%s\n",
		   user ? user : "?"));

	    /* try last working password associated with this host/user. */
	    if(imap_get_passwd(mm_login_list, pwd, user, hostlist,
	       (mb->sslflag||mb->tlsflag))){
		dprint((9,
		       "mm_login: found a password for user=%s to try\n",
		       user ? user : "?"));
		ps_global->no_newmail_check_from_optionally_enter = 0;
		ps_global->in_init_seq = save_in_init;
		return;
	    }

#ifdef	LOCAL_PASSWD_CACHE
	    /* check to see if there's a password left over from last session */
	    if(get_passfile_passwd(ps_global->pinerc, pwd,
				   user, hostlist, (mb->sslflag||mb->tlsflag))){
		imap_set_passwd(&mm_login_list, *pwd, user,
				hostlist, (mb->sslflag||mb->tlsflag), 0, 0);
		update_passfile_hostlist(ps_global->pinerc, user, hostlist,
					 (mb->sslflag||mb->tlsflag));
		dprint((9,
		  "mm_login: found a password for user=%s in passfile to try\n",
		  user ? user : "?"));
		ps_global->no_newmail_check_from_optionally_enter = 0;
		ps_global->in_init_seq = save_in_init;
		return;
	    }
#endif	/* LOCAL_PASSWD_CACHE */
	}

#if !defined(DOS) && !defined(OS2)
	if(!*mb->user && !*user &&
	   (last = (ps_global->ui.login && ps_global->ui.login[0])
				    ? ps_global->ui.login : NULL)
								 ){
	    strncpy(user, last, NETMAXUSER);
	    user[NETMAXUSER-1] = '\0';
	    dprint((9, "mm_login: found user=%s\n",
		   user ? user : "?"));

	    /* try last working password associated with this host. */
	    if(imap_get_passwd(mm_login_list, pwd, user, hostlist,
	       (mb->sslflag||mb->tlsflag))){
		dprint((9, "mm_login:ui: found a password to try\n"));
		ps_global->no_newmail_check_from_optionally_enter = 0;
		ps_global->in_init_seq = save_in_init;
		return;
	    }

#ifdef	LOCAL_PASSWD_CACHE
	    /* check to see if there's a password left over from last session */
	    if(get_passfile_passwd(ps_global->pinerc, pwd,
				   user, hostlist, (mb->sslflag||mb->tlsflag))){
		imap_set_passwd(&mm_login_list, *pwd, user,
				hostlist, (mb->sslflag||mb->tlsflag), 0, 0);
		update_passfile_hostlist(ps_global->pinerc, user, hostlist,
					 (mb->sslflag||mb->tlsflag));
		dprint((9, "mm_login:ui: found a password in passfile to try\n"));
		ps_global->no_newmail_check_from_optionally_enter = 0;
		ps_global->in_init_seq = save_in_init;
		return;
	    }
#endif	/* LOCAL_PASSWD_CACHE */
	}
#endif
    }

    user[NETMAXUSER-1] = '\0';

    if(trial == 0)
      retry = "";

    /*
     * Even if we have a user now, user gets a chance to change it.
     */
    ps_global->mangled_footer = 1;
    if(!*mb->user && !altuserforcache){

	help = NO_HELP;

	/*
	 * Instead of offering user with a value that the user can edit,
	 * we offer [user] as a default so that the user can type CR to
	 * use it. Otherwise, the user has to type in whole name.
	 */
	strncpy(defuser, user, sizeof(defuser)-1);
	defuser[sizeof(defuser)-1] = '\0';
	user[0] = '\0';

	/*
	 * Need space for "Retrying - "
	 *                "+ HOST: "
	 *                hostname
	 *                " (INSECURE)"
	 *                ENTER LOGIN NAME
	 *                " [defuser] : "
	 *                about 15 chars for input
	 */

	snprintf(hostleadin, sizeof(hostleadin), "%s%s: ",
		(!ps_global->ttyo && (mb->sslflag||mb->tlsflag)) ? "+ " : "", hostlabel);
	hostleadin[sizeof(hostleadin)-1] = '\0';

	strncpy(hostname, mb->host, sizeof(hostname)-1);
	hostname[sizeof(hostname)-1] = '\0';

	/*
	 * Add port number to hostname if going through a tunnel or something
	 */
	if(*non_def_port)
	  strncpy(port, non_def_port, sizeof(port));
	else
	  port[0] = '\0';
	
	insecure[0] = '\0';
	/* if not encrypted and SSL/TLS is supported */
	if(!(mb->sslflag||mb->tlsflag) &&
	   mail_parameters(NIL, GET_SSLDRIVER, NIL))
	  strncpy(insecure, insec, sizeof(insecure));

	/* TRANSLATORS: user is being asked to type in their login name */
	snprintf(logleadin, sizeof(logleadin), "  %s", _("ENTER LOGIN NAME"));

	snprintf(defubuf, sizeof(defubuf), "%s%s%s : ", (*defuser) ? " [" : "",
					  (*defuser) ? defuser : "",
					  (*defuser) ? "]" : "");
	defubuf[sizeof(defubuf)-1] = '\0';
	/* space reserved after prompt */
	oespace = MAX(MIN(15, (ps_global->ttyo ? ps_global->ttyo->screen_cols : 80)/5), 6);

	avail = ps_global->ttyo ? ps_global->ttyo->screen_cols : 80;
	need = utf8_width(retry) + utf8_width(hostleadin) + strlen(hostname) + strlen(port) +
	       utf8_width(insecure) + utf8_width(logleadin) + strlen(defubuf) + oespace;

	/* If we're retrying cut the hostname back to the first word. */
	if(avail < need && trial > 0){
	    char *p;

	    len = strlen(hostname);
	    if((p = strchr(hostname, '.')) != NULL){
	      *p = '\0';
	      need -= (len - strlen(hostname));
	    }
	}

	if(avail < need){
	  need -= utf8_width(retry);
	  retry = "";

	  if(avail < need){

	    /* reduce length of logleadin */
	    len = utf8_width(logleadin);
	    /* TRANSLATORS: An abbreviated form of ENTER LOGIN NAME because
	       longer version doesn't fit on screen */
	    snprintf(logleadin, sizeof(logleadin), " %s", _("LOGIN"));
	    need -= (len - utf8_width(logleadin));

	    if(avail < need){
		/* get two spaces from hostleadin */
		len = utf8_width(hostleadin);
		snprintf(hostleadin, sizeof(hostleadin), "%s%s:",
		  (!ps_global->ttyo && (mb->sslflag||mb->tlsflag)) ? "+" : "", hostlabel);
		hostleadin[sizeof(hostleadin)-1] = '\0';
		need -= (len - utf8_width(hostleadin));

		/* get rid of port */
		if(avail < need && strlen(port) > 0){
		    need -= strlen(port);
		    port[0] = '\0';
		}

		if(avail < need){
		    int reduce_to;

		    /*
		     * Reduce space for hostname. Best we can do is 6 chars
		     * with hos...
		     */
		    reduce_to = (need - avail < strlen(hostname) - 6) ? (strlen(hostname)-(need-avail)) : 6;
		    len = strlen(hostname);
		    strncpy(hostname+reduce_to-3, "...", 4);
		    need -= (len - strlen(hostname));

		    if(avail < need && strlen(insecure) > 0){
			if(need - avail <= 3 && !strcmp(insecure," (INSECURE)")){
			    need -= 3;
			    insecure[strlen(insecure)-4] = ')';
			    insecure[strlen(insecure)-3] = '\0';
			}
			else{
			    need -= utf8_width(insecure);
			    insecure[0] = '\0';
			}
		    }

		    if(avail < need){
			if(strlen(defubuf) > 3){
			    len = strlen(defubuf);
			    strncpy(defubuf, " [..] :", 9);
			    need -= (len - strlen(defubuf));
			}

			if(avail < need)
			  strncpy(defubuf, ":", 2);

			/*
			 * If it still doesn't fit, optionally_enter gets
			 * to worry about it.
			 */
		    }
		}
	    }
	  }
	}

	snprintf(prompt, sizeof(prompt), "%s%s%s%s%s%s%s",
		retry, hostleadin, hostname, port, insecure, logleadin, defubuf);
	prompt[sizeof(prompt)-1] = '\0';

	while(1) {
	    if(ps_global->ttyo)
	      mm_login_alt_cue(mb);

	    flags = OE_APPEND_CURRENT;
	    save_dont_use = ps_global->dont_use_init_cmds;
	    ps_global->dont_use_init_cmds = 1;
#ifdef _WINDOWS
	    if(!*user && *defuser){
		strncpy(user, defuser, NETMAXUSER);
		user[NETMAXUSER-1] = '\0';
	    }

	    rc = os_login_dialog(mb, user, NETMAXUSER, pwd, NETMAXPASSWD,
#ifdef	LOCAL_PASSWD_CACHE
				 is_using_passfile() ? 1 :
#endif	/* LOCAL_PASSWD_CACHE */
				 0, 0, &preserve_password);
	    ps_global->dont_use_init_cmds = save_dont_use;
	    if(rc == 0 && *user && *pwd)
	      goto nopwpmt;
#else /* !_WINDOWS */
	    rc = optionally_enter(user, q_line, 0, NETMAXUSER,
				  prompt, NULL, help, &flags);
#endif /* !_WINDOWS */
	    ps_global->dont_use_init_cmds = save_dont_use;

	    if(rc == 3) {
		help = help == NO_HELP ? h_oe_login : NO_HELP;
		continue;
	    }

	    /* default */
	    if(rc == 0 && !*user){
		strncpy(user, defuser, NETMAXUSER);
		user[NETMAXUSER-1] = '\0';
	    }
	      
	    if(rc != 4)
	      break;
	}

	if(rc == 1 || !user[0]) {
	    ps_global->user_says_cancel = (rc == 1);
	    user[0]   = '\0';
	    pwd[0] = '\0';
	}
    }
    else{
	strncpy(user, mb->user, NETMAXUSER);
	user[NETMAXUSER-1] = '\0';
    }

    user[NETMAXUSER-1] = '\0';
    pwd[NETMAXPASSWD-1] = '\0';

    if(!(user[0] || altuserforcache)){
	ps_global->no_newmail_check_from_optionally_enter = 0;
	ps_global->in_init_seq = save_in_init;
	return;
    }

    /*
     * Now that we have a user, we can check in the cache again to see
     * if there is a password there. Try last working password associated
     * with this host and user.
     */
    if(trial == 0L && !*mb->user && !altuserforcache){
	if(imap_get_passwd(mm_login_list, pwd, user, hostlist,
	   (mb->sslflag||mb->tlsflag))){
	    ps_global->no_newmail_check_from_optionally_enter = 0;
	    ps_global->in_init_seq = save_in_init;
	    return;
	}

#ifdef	LOCAL_PASSWD_CACHE
	if(get_passfile_passwd(ps_global->pinerc, pwd,
			       user, hostlist, (mb->sslflag||mb->tlsflag))){
	    imap_set_passwd(&mm_login_list, *pwd, user,
			    hostlist, (mb->sslflag||mb->tlsflag), 0, 0);
	    ps_global->no_newmail_check_from_optionally_enter = 0;
	    ps_global->in_init_seq = save_in_init;
	    return;
	}
#endif	/* LOCAL_PASSWD_CACHE */
    }
    else if(trial == 0 && altuserforcache){
	if(imap_get_passwd(mm_login_list, pwd, altuserforcache, hostlist,
	   (mb->sslflag||mb->tlsflag))){
	    ps_global->no_newmail_check_from_optionally_enter = 0;
	    ps_global->in_init_seq = save_in_init;
	    return;
	}

#ifdef	LOCAL_PASSWD_CACHE
	if(get_passfile_passwd(ps_global->pinerc, pwd,
			       altuserforcache, hostlist, (mb->sslflag||mb->tlsflag))){
	    imap_set_passwd(&mm_login_list, *pwd, altuserforcache,
			    hostlist, (mb->sslflag||mb->tlsflag), 0, 0);
	    ps_global->no_newmail_check_from_optionally_enter = 0;
	    ps_global->in_init_seq = save_in_init;
	    return;
	}
#endif	/* LOCAL_PASSWD_CACHE */
    }

    /*
     * Didn't find password in cache or this isn't the first try. Ask user.
     */
    help = NO_HELP;

    /*
     * Need space for "Retrying - "
     *                "+ HOST: "
     *                hostname
     *                " (INSECURE) "
     *                "  USER: "
     *                user
     *                "  ENTER PASSWORD: "
     *                about 15 chars for input
     */
    
    snprintf(hostleadin, sizeof(hostleadin), "%s%s: ",
	    (!ps_global->ttyo && (mb->sslflag||mb->tlsflag)) ? "+ " : "", hostlabel);

    strncpy(hostname, mb->host, sizeof(hostname)-1);
    hostname[sizeof(hostname)-1] = '\0';

    /*
     * Add port number to hostname if going through a tunnel or something
     */
    if(*non_def_port)
      strncpy(port, non_def_port, sizeof(port));
    else
      port[0] = '\0';
    
    insecure[0] = '\0';

    /* if not encrypted and SSL/TLS is supported */
    if(!(mb->sslflag||mb->tlsflag) &&
       mail_parameters(NIL, GET_SSLDRIVER, NIL))
      strncpy(insecure, insec, sizeof(insecure));
    
    if(usethisprompt){
	strncpy(logleadin, usethisprompt, sizeof(logleadin));
	logleadin[sizeof(logleadin)-1] = '\0';
	defubuf[0] = '\0';
	user[0] = '\0';
    }
    else{
	snprintf(logleadin, sizeof(logleadin), "  %s: ", userlabel);

	strncpy(defubuf, user, sizeof(defubuf)-1);
	defubuf[sizeof(defubuf)-1] = '\0';
    }

    /* TRANSLATORS: user is being asked to type in their password */
    snprintf(pwleadin, sizeof(pwleadin), "  %s: ", _("ENTER PASSWORD"));

    /* space reserved after prompt */
    oespace = MAX(MIN(15, (ps_global->ttyo ? ps_global->ttyo->screen_cols : 80)/5), 6);

    avail = ps_global->ttyo ? ps_global->ttyo->screen_cols : 80;
    need = utf8_width(retry) + utf8_width(hostleadin) + strlen(hostname) + strlen(port) +
	   utf8_width(insecure) + utf8_width(logleadin) + strlen(defubuf) +
	   utf8_width(pwleadin) + oespace;
    
    if(avail < need && trial > 0){
	char *p;

	len = strlen(hostname);
	if((p = strchr(hostname, '.')) != NULL){
	  *p = '\0';
	  need -= (len - strlen(hostname));
	}
    }

    if(avail < need){
      need -= utf8_width(retry);
      retry = "";

      if(avail < need){

	if(!usethisprompt){
	    snprintf(logleadin, sizeof(logleadin), " %s: ", userlabel);
	    need--;
	}

	rplstr(pwleadin, sizeof(pwleadin), 1, "");
	need--;

	if(avail < need){
	    /* get two spaces from hostleadin */
	    len = utf8_width(hostleadin);
	    snprintf(hostleadin, sizeof(hostleadin), "%s%s:",
	      (!ps_global->ttyo && (mb->sslflag||mb->tlsflag)) ? "+" : "", hostlabel);
	    hostleadin[sizeof(hostleadin)-1] = '\0';
	    need -= (len - utf8_width(hostleadin));

	    /* get rid of port */
	    if(avail < need && strlen(port) > 0){
		need -= strlen(port);
		port[0] = '\0';
	    }

	    if(avail < need){
		len = utf8_width(pwleadin);
		/* TRANSLATORS: An abbreviated form of ENTER PASSWORD */
		snprintf(pwleadin, sizeof(pwleadin), " %s: ", _("PASSWORD"));
		need -= (len - utf8_width(pwleadin));
	    }
	}

	if(avail < need){
	    int reduce_to;

	    /*
	     * Reduce space for hostname. Best we can do is 6 chars
	     * with hos...
	     */
	    reduce_to = (need - avail < strlen(hostname) - 6) ? (strlen(hostname)-(need-avail)) : 6;
	    len = strlen(hostname);
	    strncpy(hostname+reduce_to-3, "...", 4);
	    need -= (len - strlen(hostname));
	    
	    if(avail < need && strlen(insecure) > 0){
		if(need - avail <= 3 && !strcmp(insecure," (INSECURE)")){
		    need -= 3;
		    insecure[strlen(insecure)-4] = ')';
		    insecure[strlen(insecure)-3] = '\0';
		}
		else{
		    need -= utf8_width(insecure);
		    insecure[0] = '\0';
		}
	    }

	    if(avail < need){
		len = utf8_width(logleadin);
		strncpy(logleadin, " ", sizeof(logleadin));
		logleadin[sizeof(logleadin)-1] = '\0';
		need -= (len - utf8_width(logleadin));

		if(avail < need){
		    reduce_to = (need - avail < strlen(defubuf) - 6) ? (strlen(defubuf)-(need-avail)) : 0;
		    if(reduce_to)
		      strncpy(defubuf+reduce_to-3, "...", 4);
		    else
		      defubuf[0] = '\0';
		}
	    }
	}
      }
    }

    snprintf(prompt, sizeof(prompt), "%s%s%s%s%s%s%s%s",
	    retry, hostleadin, hostname, port, insecure, logleadin, defubuf, pwleadin);
    prompt[sizeof(prompt)-1] = '\0';

    tmp[0] = '\0';
    while(1) {
	if(ps_global->ttyo)
	  mm_login_alt_cue(mb);

	save_dont_use = ps_global->dont_use_init_cmds;
	ps_global->dont_use_init_cmds = 1;
	flags = F_ON(F_QUELL_ASTERISKS, ps_global) ? OE_PASSWD_NOAST : OE_PASSWD;
#ifdef _WINDOWS
	rc = os_login_dialog(mb, user, NETMAXUSER, tmp, NETMAXPASSWD, 0, 1,
			     &preserve_password);
#else /* !_WINDOWS */
        rc = optionally_enter(tmp, q_line, 0, NETMAXPASSWD,
			      prompt, NULL, help, &flags);
#endif /* !_WINDOWS */
	*pwd = cpystr(tmp);
	ps_global->dont_use_init_cmds = save_dont_use;

        if(rc == 3) {
            help = help == NO_HELP ? h_oe_passwd : NO_HELP;
        }
	else if(rc == 4){
	}
	else
          break;
    }

    if(rc == 1 || !tmp[0]) {
	ps_global->user_says_cancel = (rc == 1);
        user[0] = '\0';
	ps_global->no_newmail_check_from_optionally_enter = 0;
	ps_global->in_init_seq = save_in_init;
        return;
    }

#ifdef _WINDOWS
 nopwpmt:
#endif
    /* remember the password for next time */
    if(F_OFF(F_DISABLE_PASSWORD_CACHING,ps_global))
      imap_set_passwd(&mm_login_list, *pwd,
		      altuserforcache ? altuserforcache : user, hostlist,
		      (mb->sslflag||mb->tlsflag), 0, 0);
#ifdef	LOCAL_PASSWD_CACHE
#ifdef  PASSFILE
    /* if requested, remember it on disk for next session */
      if(save_password && F_OFF(F_DISABLE_PASSWORD_FILE_SAVING,ps_global))
      set_passfile_passwd(ps_global->pinerc, *pwd,
		        altuserforcache ? altuserforcache : user, hostlist,
			(mb->sslflag||mb->tlsflag),
			(preserve_password == -1 ? 0
			 : (preserve_password == 0 ? 2 :1)));
#endif	/* PASSFILE */
#endif	/* LOCAL_PASSWD_CACHE */

    ps_global->no_newmail_check_from_optionally_enter = 0;
}


void
mm_login_alt_cue(NETMBX *mb)
{
    if(ps_global->ttyo){
	COLOR_PAIR  *lastc;

	lastc = pico_set_colors(ps_global->VAR_TITLE_FORE_COLOR,
				ps_global->VAR_TITLE_BACK_COLOR,
				PSC_REV | PSC_RET);

	mark_titlebar_dirty();
	PutLine0(0, ps_global->ttyo->screen_cols - 1, 
		 (mb->sslflag||mb->tlsflag) ? "+" : " ");

	if(lastc){
	    (void)pico_set_colorp(lastc, PSC_NONE);
	    free_color_pair(&lastc);
	}

	fflush(stdout);
    }
}


/*----------------------------------------------------------------------
       Receive notification of an error writing to disk
      
  Args: stream  -- The stream the error occured on
        errcode -- The system error code (errno)
        serious -- Flag indicating error is serious (mail may be lost)

Result: If error is non serious, the stream is marked as having an error
        and deletes are disallowed until error clears
        If error is serious this goes modal, allowing the user to retry
        or get a shell escape to fix the condition. When the condition is
        serious it means that mail existing in the mailbox will be lost
        if Pine exits without writing, so we try to induce the user to 
        fix the error, go get someone that can fix the error, or whatever
        and don't provide an easy way out.
  ----*/
long
mm_diskerror (MAILSTREAM *stream, long int errcode, long int serious)
{
    int  i, j;
    char *p, *q, *s;
    static ESCKEY_S de_opts[] = {
	{'r', 'r', "R", "Retry"},
	{'f', 'f', "F", "FileBrowser"},
	{'s', 's', "S", "ShellPrompt"},
	{-1, 0, NULL, NULL}
    };
#define	DE_COLS		(ps_global->ttyo->screen_cols)
#define	DE_LINE		(ps_global->ttyo->screen_rows - 3)

#define	DE_FOLDER(X)	(((X) && (X)->mailbox) ? (X)->mailbox : "<no folder>")
#define	DE_PMT	\
   "Disk error!  Choose Retry, or the File browser or Shell to clean up: "
#define	DE_STR1		"SERIOUS DISK ERROR WRITING: \"%s\""
#define	DE_STR2	\
   "The reported error number is %s.  The last reported mail error was:"
    static char *de_msg[] = {
	"Please try to correct the error preventing Alpine from saving your",
	"mail folder.  For example if the disk is out of space try removing",
	"unneeded files.  You might also contact your system administrator.",
	"",
	"Both Alpine's File Browser and an option to enter the system's",
	"command prompt are offered to aid in fixing the problem.  When",
	"you believe the problem is resolved, choose the \"Retry\" option.",
	"Be aware that messages may be lost or this folder left in an",
	"inaccessible condition if you exit or kill Alpine before the problem",
	"is resolved.",
	NULL};
    static char *de_shell_msg[] = {
	"\n\nPlease attempt to correct the error preventing saving of the",
	"mail folder.  If you do not know how to correct the problem, contact",
	"your system administrator.  To return to Alpine, type \"exit\".",
	NULL};

    dprint((0,
       "\n***** DISK ERROR on stream %s. Error code %ld. Error is %sserious\n",
	       DE_FOLDER(stream), errcode, serious ? "" : "not "));
    dprint((0, "***** message: \"%s\"\n\n",
	   ps_global->last_error ? ps_global->last_error : "?"));

    if(!serious) {
	sp_set_io_error_on_stream(stream, 1);
        return (1) ;
    }

    while(1){
	/* replace pine's body display with screen full of explanatory text */
	ClearLine(2);
	PutLine1(2, MAX((DE_COLS - sizeof(DE_STR1)
					    - strlen(DE_FOLDER(stream)))/2, 0),
		 DE_STR1, DE_FOLDER(stream));
	ClearLine(3);
	PutLine1(3, 4, DE_STR2, long2string(errcode));
	     
	PutLine0(4, 0, "       \"");
	removing_leading_white_space(ps_global->last_error);
	for(i = 4, p = ps_global->last_error; *p && i < DE_LINE; ){
	    for(s = NULL, q = p; *q && q - p < DE_COLS - 16; q++)
	      if(isspace((unsigned char)*q))
		s = q;

	    if(*q && s)
	      q = s;

	    while(p < q)
	      Writechar(*p++, 0);

	    if(*(p = q)){
		ClearLine(++i);
		PutLine0(i, 0, "        ");
		while(*p && isspace((unsigned char)*p))
		  p++;
	    }
	    else{
		Writechar('\"', 0);
		CleartoEOLN();
		break;
	    }
	}

	ClearLine(++i);
	for(j = ++i; i < DE_LINE && de_msg[i-j]; i++){
	    ClearLine(i);
	    PutLine0(i, 0, "  ");
	    Write_to_screen(de_msg[i-j]);
	}

	while(i < DE_LINE)
	  ClearLine(i++);

	switch(radio_buttons(DE_PMT, -FOOTER_ROWS(ps_global), de_opts,
			     'r', 0, NO_HELP, RB_FLUSH_IN | RB_NO_NEWMAIL)){
	  case 'r' :				/* Retry! */
	    ps_global->mangled_screen = 1;
	    return(0L);

	  case 'f' :				/* File Browser */
	    {
		char full_filename[MAXPATH+1], filename[MAXPATH+1];

		filename[0] = '\0';
		build_path(full_filename, ps_global->home_dir, filename,
			   sizeof(full_filename));
		file_lister("DISK ERROR", full_filename, sizeof(full_filename), 
                             filename, sizeof(filename), FALSE, FB_SAVE);
	    }

	    break;

	  case 's' :
	    EndInverse();
	    end_keyboard(ps_global ? F_ON(F_USE_FK,ps_global) : 0);
	    end_tty_driver(ps_global);
	    for(i = 0; de_shell_msg[i]; i++)
	      puts(de_shell_msg[i]);

	    /*
	     * Don't use our piping mechanism to spawn a subshell here
	     * since it will the server (thus reentering c-client).
	     * Bad thing to do.
	     */
#ifdef	_WINDOWS
#else
	    system("csh");
#endif
	    init_tty_driver(ps_global);
	    init_keyboard(F_ON(F_USE_FK,ps_global));
	    break;
	}

	if(ps_global->redrawer)
	  (*ps_global->redrawer)();
    }
}


long
pine_tcptimeout_noscreen(long int elapsed, long int sincelast, char *host)
{
    long rv = 1L;
    char pmt[128];

#ifdef _WINDOWS
    mswin_killsplash();
#endif

    if(elapsed >= (long)ps_global->tcp_query_timeout){
	snprintf(pmt, sizeof(pmt),
	 _("No reply in %s seconds from server %s. Break connection"),
		long2string(elapsed), host);
	pmt[sizeof(pmt)-1] = '\0';
	if(want_to(pmt, 'n', 'n', NO_HELP, WT_FLUSH_IN) == 'y'){
	  ps_global->user_says_cancel = 1;
	  return(0L);
	}
    }

    ps_global->tcptimeout = 0;
    return(rv);
}


/*
 * -------------------------------------------------------------
 * These are declared in pith/imap.h as mandatory to implement.
 * -------------------------------------------------------------
 */


/*
 * pine_tcptimeout - C-client callback to handle tcp-related timeouts.
 */
long
pine_tcptimeout(long int elapsed, long int sincelast, char *host)
{
    long rv = 1L;			/* keep trying by default */
    unsigned long ch;

    ps_global->tcptimeout = 1;
#ifdef	DEBUG
    dprint((1, "tcptimeout: waited %s seconds, server: %s\n",
	       long2string(elapsed), host));
    if(debugfile)
      fflush(debugfile);
#endif

#ifdef _WINDOWS
    mswin_killsplash();
#endif

    if(ps_global->noshow_timeout)
      return(rv);

    if(ps_global->can_interrupt
	&& ps_global->close_connection_timeout > 0L
	&& elapsed >= (long)ps_global->tcp_query_timeout
	&& elapsed >= (long)ps_global->close_connection_timeout){
	ps_global->can_interrupt = 0;	/* do not return here */
	ps_global->read_bail = 0;
	ps_global->user_says_cancel = 1;
	return 0;
    } 

    if(!ps_global->ttyo)
      return(pine_tcptimeout_noscreen(elapsed, sincelast, host));

    suspend_busy_cue();
    
    /*
     * Prompt after a minute (since by then things are probably really bad)
     * A prompt timeout means "keep trying"...
     */
    if(elapsed >= (long)ps_global->tcp_query_timeout){
	int clear_inverse;

	ClearLine(ps_global->ttyo->screen_rows - FOOTER_ROWS(ps_global));
	if((clear_inverse = !InverseState()) != 0)
	  StartInverse();

	Writechar(BELL, 0);

	PutLine2(ps_global->ttyo->screen_rows - FOOTER_ROWS(ps_global), 0,
	 _("No reply in %s seconds from server %s. Break connection?"),
	   long2string(elapsed), host);
	CleartoEOLN();
	fflush(stdout);
	flush_input();
	ch = read_char(7);
	if(ps_global->read_bail || ch == 'y' || ch == 'Y'){
	  ps_global->read_bail = 0;
	  ps_global->user_says_cancel = 1;
	  rv = 0L;
	}

	if(clear_inverse)
	  EndInverse();

	ClearLine(ps_global->ttyo->screen_rows - FOOTER_ROWS(ps_global));
    }

    if(rv == 1L){			/* just warn 'em something's up */
	q_status_message2(SM_ORDER, 0, 0,
	 _("No reply in %s seconds from server %s. Still Waiting..."),
		  long2string(elapsed), host);
	flush_status_messages(0);	/* make sure it's seen */
    }

    mark_status_dirty();		/* make sure it get's cleared */

    resume_busy_cue((rv == 1) ? 3 : 0);
    ps_global->tcptimeout = 0;

    return(rv);
}

QUOTALIST *pine_quotalist_copy (QUOTALIST *pquota)
{
  QUOTALIST *cquota = NULL;

  if(pquota){
     cquota = mail_newquotalist();
     if (pquota->name && *pquota->name)
	cquota->name = cpystr(pquota->name);
     cquota->usage = pquota->usage;
     cquota->limit = pquota->limit;
     if (pquota->next)
        cquota->next = pine_quotalist_copy(pquota->next);
  }
  return cquota;
}


/* c-client callback to handle quota */

void
pine_parse_quota (MAILSTREAM *stream, unsigned char *msg, QUOTALIST *pquota)
{
   ps_global->quota = pine_quotalist_copy (pquota);
} 

/*
 * C-client callback to handle SSL/TLS certificate validation failures
 *
 * Returning 0 means error becomes fatal
 *           Non-zero means certificate problem is ignored and SSL session is
 *             established
 *
 *  We remember the answer and won't re-ask for subsequent open attempts to
 *  the same hostname.
 */
long
pine_sslcertquery(char *reason, char *host, char *cert)
{
    char      tmp[500];
    char     *unknown = "<unknown>";
    long      rv = 0L;
    STRLIST_S hostlist;
    int       ok_novalidate = 0, warned = 0;

    dprint((1, "sslcertificatequery: host=%s reason=%s cert=%s\n",
			   host ? host : "?", reason ? reason : "?",
			   cert ? cert : "?"));

    hostlist.name = host ? host : "";
    hostlist.next = NULL;

    /*
     * See if we've been asked about this host before.
     */
    if(imap_get_ssl(cert_failure_list, &hostlist, &ok_novalidate, &warned)){
	/* we were asked before, did we say Yes? */
	if(ok_novalidate)
	  rv++;

	if(rv){
	    dprint((5,
		       "sslcertificatequery: approved automatically\n"));
	    return(rv);
	}

	dprint((1, "sslcertificatequery: we were asked before and said No, so ask again\n"));
    }

    if(ps_global->ttyo){
	SCROLL_S  sargs;
	STORE_S  *in_store, *out_store;
	gf_io_t   pc, gc;
	HANDLE_S *handles = NULL;
	int       the_answer = 'n';

	if(!(in_store = so_get(CharStar, NULL, EDIT_ACCESS)) ||
	   !(out_store = so_get(CharStar, NULL, EDIT_ACCESS)))
	  goto try_wantto;

	so_puts(in_store, "<HTML><P>");
	so_puts(in_store, _("There was a failure validating the SSL/TLS certificate for the server"));

	so_puts(in_store, "<P><CENTER>");
	so_puts(in_store, host ? host : unknown);
	so_puts(in_store, "</CENTER>");

	so_puts(in_store, "<P>");
	so_puts(in_store, _("The reason for the failure was"));

	/* squirrel away details */
	if(details_host)
	  fs_give((void **)&details_host);
	if(details_reason)
	  fs_give((void **)&details_reason);
	if(details_cert)
	  fs_give((void **)&details_cert);
	
	details_host   = cpystr(host ? host : unknown);
	details_reason = cpystr(reason ? reason : unknown);
	details_cert   = cpystr(cert ? cert : unknown);

	so_puts(in_store, "<P><CENTER>");
	snprintf(tmp, sizeof(tmp), "%s (<A HREF=\"X-Alpine-Cert:\">details</A>)",
		reason ? reason : unknown);
	tmp[sizeof(tmp)-1] = '\0';

	so_puts(in_store, tmp);
	so_puts(in_store, "</CENTER>");

	so_puts(in_store, "<P>");
	so_puts(in_store, _("We have not verified the identity of your server. If you ignore this certificate validation problem and continue, you could end up connecting to an imposter server."));

	so_puts(in_store, "<P>");
	so_puts(in_store, _("If the certificate validation failure was expected and permanent you may avoid seeing this warning message in the future by adding the option"));

	so_puts(in_store, "<P><CENTER>");
	so_puts(in_store, "/novalidate-cert");
	so_puts(in_store, "</CENTER>");

	so_puts(in_store, "<P>");
	so_puts(in_store, _("to the name of the folder you attempted to access. In other words, wherever you see the characters"));

	so_puts(in_store, "<P><CENTER>");
	so_puts(in_store, host ? host : unknown);
	so_puts(in_store, "</CENTER>");

	so_puts(in_store, "<P>");
	so_puts(in_store, _("in your configuration, replace those characters with"));

	so_puts(in_store, "<P><CENTER>");
	so_puts(in_store, host ? host : unknown);
	so_puts(in_store, "/novalidate-cert");
	so_puts(in_store, "</CENTER>");

	so_puts(in_store, "<P>");
	so_puts(in_store, _("Answer \"Yes\" to ignore the warning and continue, \"No\" to cancel the open of this folder."));

	so_seek(in_store, 0L, 0);
	init_handles(&handles);
	gf_filter_init();
	gf_link_filter(gf_html2plain,
		       gf_html2plain_opt(NULL,
					 ps_global->ttyo->screen_cols, non_messageview_margin(),
					 &handles, NULL, GFHP_LOCAL_HANDLES));
	gf_set_so_readc(&gc, in_store);
	gf_set_so_writec(&pc, out_store);
	gf_pipe(gc, pc);
	gf_clear_so_writec(out_store);
	gf_clear_so_readc(in_store);

	memset(&sargs, 0, sizeof(SCROLL_S));
	sargs.text.handles  = handles;
	sargs.text.text     = so_text(out_store);
	sargs.text.src      = CharStar;
	sargs.text.desc     = _("help text");
	sargs.bar.title     = _("SSL/TLS CERTIFICATE VALIDATION FAILURE");
	sargs.proc.tool     = answer_cert_failure;
	sargs.proc.data.p   = (void *)&the_answer;
	sargs.keys.menu     = &ans_certquery_keymenu;
	/* don't want to re-enter c-client */
	sargs.quell_newmail = 1;
	setbitmap(sargs.keys.bitmap);
	sargs.help.text     = h_tls_validation_failure;
	sargs.help.title    = _("HELP FOR CERT VALIDATION FAILURE");

	scrolltool(&sargs);

	if(the_answer == 'y')
	  rv++;

	ps_global->mangled_screen = 1;
	ps_global->painted_body_on_startup = 0;
	ps_global->painted_footer_on_startup = 0;
	so_give(&in_store);
	so_give(&out_store);
	free_handles(&handles);
	if(details_host)
	  fs_give((void **)&details_host);
	if(details_reason)
	  fs_give((void **)&details_reason);
	if(details_cert)
	  fs_give((void **)&details_cert);
    }
    else{
	/*
	 * If screen hasn't been initialized yet, use want_to.
	 */
try_wantto:
	memset((void *)tmp, 0, sizeof(tmp));
	strncpy(tmp,
		reason ? reason : _("SSL/TLS certificate validation failure"),
		sizeof(tmp));
	tmp[sizeof(tmp)-1] = '\0';
	strncat(tmp, _(": Continue anyway "), sizeof(tmp)-strlen(tmp)-1);

	if(want_to(tmp, 'n', 'x', NO_HELP, WT_NORM) == 'y')
	  rv++;
    }

    if(rv == 0)
      q_status_message1(SM_ORDER, 1, 3, _("Open of %s cancelled"),
			host ? host : unknown);

    imap_set_passwd(&cert_failure_list, "", "", &hostlist, 0, rv ? 1 : 0, 0);

    dprint((5, "sslcertificatequery: %s\n",
			   rv ? "approved" : "rejected"));

    return(rv);
}


char *
pine_newsrcquery(MAILSTREAM *stream, char *mulname, char *name)
{
    char buf[MAILTMPLEN];

    if((can_access(mulname, ACCESS_EXISTS) == 0)
       || !(can_access(name, ACCESS_EXISTS) == 0))
      return(mulname);

    snprintf(buf, sizeof(buf),
	    _("Rename newsrc \"%s%s\" for use as new host-specific newsrc"),
	    last_cmpnt(name), 
	    strlen(last_cmpnt(name)) > 15 ? "..." : "");
    buf[sizeof(buf)-1] = '\0';
    if(want_to(buf, 'n', 'n', NO_HELP, WT_NORM) == 'y')
      rename_file(name, mulname);
    return(mulname);
}


int
url_local_certdetails(char *url)
{
    if(!struncmp(url, "x-alpine-cert:", 14)){
	STORE_S  *store;
	SCROLL_S  sargs;
	char     *folded;

	if(!(store = so_get(CharStar, NULL, EDIT_ACCESS))){
	    q_status_message(SM_ORDER | SM_DING, 7, 10,
			     _("Error allocating space for details."));
	    return(0);
	}

	so_puts(store, _("Host given by user:\n\n  "));
	so_puts(store, details_host);
	so_puts(store, _("\n\nReason for failure:\n\n  "));
	so_puts(store, details_reason);
	so_puts(store, _("\n\nCertificate being verified:\n\n"));
	folded = fold(details_cert, ps_global->ttyo->screen_cols, ps_global->ttyo->screen_cols, "  ", "  ", FLD_NONE);
	so_puts(store, folded);
	fs_give((void **)&folded);
	so_puts(store, "\n");

	memset(&sargs, 0, sizeof(SCROLL_S));
	sargs.text.text     = so_text(store);
	sargs.text.src      = CharStar;
	sargs.text.desc     = _("Details");
	sargs.bar.title     = _("CERT VALIDATION DETAILS");
	sargs.help.text     = NO_HELP;
	sargs.help.title    = NULL;
	sargs.quell_newmail = 1;
	sargs.help.text     = h_tls_failure_details;
	sargs.help.title    = _("HELP FOR CERT VALIDATION DETAILS");

	scrolltool(&sargs);

	so_give(&store);	/* free resources associated with store */
	ps_global->mangled_screen = 1;
	return(1);
    }

    return(0);
}


/*
 * C-client callback to handle SSL/TLS certificate validation failures
 */
void
pine_sslfailure(char *host, char *reason, long unsigned int flags)
{
    SCROLL_S sargs;
    STORE_S *store;
    int      the_answer = 'n', indent, len, cols;
    char     buf[500], buf2[500];
    char    *folded;
    char    *hst = host ? host : "<unknown>";
    char    *rsn = reason ? reason : "<unknown>";
    char    *notls = "/notls";
    STRLIST_S hostlist;
    int       ok_novalidate = 0, warned = 0;


    dprint((1, "sslfailure: host=%s reason=%s\n",
	   hst ? hst : "?",
	   rsn ? rsn : "?"));

    if(flags & NET_SILENT)
      return;

    hostlist.name = host ? host : "";
    hostlist.next = NULL;

    /*
     * See if we've been told about this host before.
     */
    if(imap_get_ssl(cert_failure_list, &hostlist, &ok_novalidate, &warned)){
	/* we were told already */
	if(warned){
	    snprintf(buf, sizeof(buf), _("SSL/TLS failure for %s: %s"), hst, rsn);
	    buf[sizeof(buf)-1] = '\0';
	    mm_log(buf, ERROR);
	    return;
	}
    }

    cols = ps_global->ttyo ? ps_global->ttyo->screen_cols : 80;
    cols--;

    if(!(store = so_get(CharStar, NULL, EDIT_ACCESS)))
      return;

    strncpy(buf, _("There was an SSL/TLS failure for the server"), sizeof(buf));
    folded = fold(buf, cols, cols, "", "", FLD_NONE);
    so_puts(store, folded);
    fs_give((void **)&folded);
    so_puts(store, "\n");

    if((len=strlen(hst)) <= cols){
	if((indent=((cols-len)/2)) > 0)
	  so_puts(store, repeat_char(indent, SPACE));

	so_puts(store, hst);
	so_puts(store, "\n");
    }
    else{
	strncpy(buf, hst, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	folded = fold(buf, cols, cols, "", "", FLD_NONE);
	so_puts(store, folded);
	fs_give((void **)&folded);
    }

    so_puts(store, "\n");

    strncpy(buf, _("The reason for the failure was"), sizeof(buf));
    folded = fold(buf, cols, cols, "", "", FLD_NONE);
    so_puts(store, folded);
    fs_give((void **)&folded);
    so_puts(store, "\n");

    if((len=strlen(rsn)) <= cols){
	if((indent=((cols-len)/2)) > 0)
	  so_puts(store, repeat_char(indent, SPACE));

	so_puts(store, rsn);
	so_puts(store, "\n");
    }
    else{
	strncpy(buf, rsn, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	folded = fold(buf, cols, cols, "", "", FLD_NONE);
	so_puts(store, folded);
	fs_give((void **)&folded);
    }

    so_puts(store, "\n");

    strncpy(buf, _("This is just an informational message. With the current setup, SSL/TLS will not work. If this error re-occurs every time you run Alpine, your current setup is not compatible with the configuration of your mail server. You may want to add the option"), sizeof(buf));
    folded = fold(buf, cols, cols, "", "", FLD_NONE);
    so_puts(store, folded);
    fs_give((void **)&folded);
    so_puts(store, "\n");

    if((len=strlen(notls)) <= cols){
	if((indent=((cols-len)/2)) > 0)
	  so_puts(store, repeat_char(indent, SPACE));

	so_puts(store, notls);
	so_puts(store, "\n");
    }
    else{
	strncpy(buf, notls, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	folded = fold(buf, cols, cols, "", "", FLD_NONE);
	so_puts(store, folded);
	fs_give((void **)&folded);
    }

    so_puts(store, "\n");

    strncpy(buf, _("to the name of the mail server you are attempting to access. In other words, wherever you see the characters"),
	    sizeof(buf));
    folded = fold(buf, cols, cols, "", "", FLD_NONE);
    so_puts(store, folded);
    fs_give((void **)&folded);
    so_puts(store, "\n");

    if((len=strlen(hst)) <= cols){
	if((indent=((cols-len)/2)) > 0)
	  so_puts(store, repeat_char(indent, SPACE));

	so_puts(store, hst);
	so_puts(store, "\n");
    }
    else{
	strncpy(buf, hst, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	folded = fold(buf, cols, cols, "", "", FLD_NONE);
	so_puts(store, folded);
	fs_give((void **)&folded);
    }

    so_puts(store, "\n");

    strncpy(buf, _("in your configuration, replace those characters with"),
	    sizeof(buf));
    folded = fold(buf, cols, cols, "", "", FLD_NONE);
    so_puts(store, folded);
    fs_give((void **)&folded);
    so_puts(store, "\n");

    snprintf(buf2, sizeof(buf2), "%s%s", hst, notls);
    buf2[sizeof(buf2)-1] = '\0';
    if((len=strlen(buf2)) <= cols){
	if((indent=((cols-len)/2)) > 0)
	  so_puts(store, repeat_char(indent, SPACE));

	so_puts(store, buf2);
	so_puts(store, "\n");
    }
    else{
	strncpy(buf, buf2, sizeof(buf));
	buf[sizeof(buf)-1] = '\0';
	folded = fold(buf, cols, cols, "", "", FLD_NONE);
	so_puts(store, folded);
	fs_give((void **)&folded);
    }

    so_puts(store, "\n");

    if(ps_global->ttyo){
	strncpy(buf, _("Type RETURN to continue."), sizeof(buf));
	folded = fold(buf, cols, cols, "", "", FLD_NONE);
	so_puts(store, folded);
	fs_give((void **)&folded);
    }

    memset(&sargs, 0, sizeof(SCROLL_S));
    sargs.text.text = so_text(store);
    sargs.text.src  = CharStar;
    sargs.text.desc = _("help text");
    sargs.bar.title = _("SSL/TLS FAILURE");
    sargs.proc.tool = answer_cert_failure;
    sargs.proc.data.p = (void *)&the_answer;
    sargs.keys.menu = &ans_certfail_keymenu;
    setbitmap(sargs.keys.bitmap);
    /* don't want to re-enter c-client */
    sargs.quell_newmail = 1;
    sargs.help.text     = h_tls_failure;
    sargs.help.title    = _("HELP FOR TLS/SSL FAILURE");

    if(ps_global->ttyo)
      scrolltool(&sargs);
    else{
	char **q, **qp;
	char  *p;
	unsigned char c;
	int    cnt = 0;
	
	/*
	 * The screen isn't initialized yet, which should mean that this
	 * is the result of a -p argument. Display_args_err knows how to deal
	 * with the uninitialized screen, so we mess with the data to get it
	 * in shape for display_args_err. This is pretty hacky.
	 */
	
	so_seek(store, 0L, 0);		/* rewind */
	/* count the lines */
	while(so_readc(&c, store))
	  if(c == '\n')
	    cnt++;
	
	qp = q = (char **)fs_get((cnt+1) * sizeof(char *));
	memset(q, 0, (cnt+1) * sizeof(char *));

	so_seek(store, 0L, 0);		/* rewind */
	p = buf;
	while(so_readc(&c, store)){
	    if(c == '\n'){
		*p = '\0';
		*qp++ = cpystr(buf);
		p = buf;
	    }
	    else
	      *p++ = c;
	}

	display_args_err(NULL, q, 0);
	free_list_array(&q);
    }

    ps_global->mangled_screen = 1;
    ps_global->painted_body_on_startup = 0;
    ps_global->painted_footer_on_startup = 0;
    so_give(&store);

    imap_set_passwd(&cert_failure_list, "", "", &hostlist, 0, ok_novalidate, 1);
}


int
answer_cert_failure(int cmd, MSGNO_S *msgmap, SCROLL_S *sparms)
{
    int rv = 1;

    ps_global->next_screen = SCREEN_FUN_NULL;

    switch(cmd){
      case MC_YES :
	*(int *)(sparms->proc.data.p) = 'y';
	break;

      case MC_NO :
	*(int *)(sparms->proc.data.p) = 'n';
	break;

      default:
	alpine_panic("Unexpected command in answer_cert_failure");
	break;
    }

    return(rv);
}


int
oauth2_auth_answer(int cmd, MSGNO_S *msgmap, SCROLL_S *sparms)
{
    int rv = 1, rc;
    AUTH_CODE_S user;
    int q_line, flags;
    /* TRANSLATORS: user needs to input an access code from the server */
    char     *accesscodelabel = _("Copy and Paste Access Code");
    char token[MAILTMPLEN], prompt[MAILTMPLEN];

    ps_global->next_screen = SCREEN_FUN_NULL;

    token[0] = '\0';
    switch(cmd){
      case MC_YES :
	q_line = -(ps_global->ttyo ? ps_global->ttyo->footer_rows : 3);
	flags = OE_APPEND_CURRENT;
	sprintf(prompt, "%s: ", accesscodelabel);
	do {
	   rc = optionally_enter(token, q_line, 0, MAILTMPLEN,
			   prompt, NULL, NO_HELP, &flags);
	} while (rc != 0 && rc != 1);
	user.code = rc == 0 ? cpystr(token) : NULL;
	user.answer = 'e';
	rv = rc == 1 ? 0 : 1;
	break;

      case MC_NO :
	user.code = NULL;
	user.answer = 'e';
	break;

      default:
	alpine_panic("Unexpected command in oauth2_auth_answer");
	break;
    }
    *(AUTH_CODE_S *) sparms->proc.data.p = user;
    return(rv);
}


/*----------------------------------------------------------------------
  This can be used to prevent the flickering of the check_cue char
  caused by numerous (5000+) fetches by c-client.  Right now, the only
  practical use found is newsgroup subsciption.

  check_cue_display will check if this global is set, and won't clear
  the check_cue_char if set.
  ----*/
void
set_read_predicted(int i)
{
    ps_global->read_predicted = i==1;
#ifdef _WINDOWS
    if(!i && F_ON(F_SHOW_DELAY_CUE, ps_global))
      check_cue_display("  ");
#endif
}


/*----------------------------------------------------------------------
   Exported method to retrieve logged in user name associated with stream

   Args: host -- host to find associated login name with.

 Result: 
  ----*/
void *
pine_block_notify(int reason, void *data)
{
    switch(reason){
      case BLOCK_SENSITIVE:		/* sensitive code, disallow alarms */
	break;

      case BLOCK_NONSENSITIVE:		/* non-sensitive code, allow alarms */
	break;

      case BLOCK_TCPWRITE:		/* blocked on TCP write */
      case BLOCK_FILELOCK:		/* blocked on file locking */
#ifdef	_WINDOWS
	if(F_ON(F_SHOW_DELAY_CUE, ps_global))
	  check_cue_display(">");

	mswin_setcursor(MSWIN_CURSOR_BUSY);
#endif
	break;

      case BLOCK_DNSLOOKUP:		/* blocked on DNS lookup */
      case BLOCK_TCPOPEN:		/* blocked on TCP open */
      case BLOCK_TCPREAD:		/* blocked on TCP read */
      case BLOCK_TCPCLOSE:		/* blocked on TCP close */
#ifdef	_WINDOWS
	if(F_ON(F_SHOW_DELAY_CUE, ps_global))
	  check_cue_display("<");

	mswin_setcursor(MSWIN_CURSOR_BUSY);
#endif
	break;

      default :
      case BLOCK_NONE:			/* not blocked */
#ifdef	_WINDOWS
	if(F_ON(F_SHOW_DELAY_CUE, ps_global))
	  check_cue_display(" ");
#endif
	break;

    }

    return(NULL);
}


void
mm_expunged_current(long unsigned int rawno)
{
    /* expunged something we're viewing? */
    if(!ps_global->expunge_in_progress
       && (mn_is_cur(ps_global->msgmap, mn_raw2m(ps_global->msgmap, (long) rawno))
	   && (ps_global->prev_screen == mail_view_screen
	       || ps_global->prev_screen == attachment_screen))){
	ps_global->next_screen = mail_index_screen;
	q_status_message(SM_ORDER | SM_DING , 3, 3,
			 "Message you were viewing is gone!");
    }
}


#ifdef	PASSFILE

/* 
 * Specific functions to support caching username/passwd/host
 * triples on disk for use from one session to the next...
 */

#define	FIRSTCH		0x20
#define	LASTCH		0x7e
#define	TABSZ		(LASTCH - FIRSTCH + 1)

static	int		xlate_key;


/*
 * xlate_in() - xlate_in the given character
 */
char
xlate_in(int c)
{
    register int  eti;

    eti = xlate_key;
    if((c >= FIRSTCH) && (c <= LASTCH)){
        eti += (c - FIRSTCH);
	eti -= (eti >= 2*TABSZ) ? 2*TABSZ : (eti >= TABSZ) ? TABSZ : 0;
        return((xlate_key = eti) + FIRSTCH);
    }
    else
      return(c);
}


/*
 * xlate_out() - xlate_out the given character
 */
char
xlate_out(char c)
{
    register int  dti;
    register int  xch;

    if((c >= FIRSTCH) && (c <= LASTCH)){
        xch  = c - (dti = xlate_key);
	xch += (xch < FIRSTCH-TABSZ) ? 2*TABSZ : (xch < FIRSTCH) ? TABSZ : 0;
        dti  = (xch - FIRSTCH) + dti;
	dti -= (dti >= 2*TABSZ) ? 2*TABSZ : (dti >= TABSZ) ? TABSZ : 0;
        xlate_key = dti;
        return(xch);
    }
    else
      return(c);
}
#endif	/* PASSFILE */


#ifdef	LOCAL_PASSWD_CACHE


int 
line_get(char *tmp, size_t len, char **textp)
{
  char *s;

  tmp[0] = '\0';
  if (*textp == NULL 
	|| (s = strchr(*textp, '\n')) == NULL
	|| (s - *textp) > len - 1)
    return 0;

  *s = '\0';
  if(*(s-1) == '\r')
    *(s-1) = '\0';

  snprintf(tmp, len, "%s\n", *textp);
  tmp[len-1] = '\0';
  *textp = s+1;

  return 1;
}
/*
 * For UNIX:
 * Passfile lines are
 *
 *   passwd TAB user TAB hostname TAB flags [ TAB orig_hostname ] \n
 *
 * In pine4.40 and before there was no orig_hostname, and there still isn't
 * if it is the same as hostname.
 *
 * else for WINDOWS:
 * Use Windows credentials. The TargetName of the credential is
 * UWash_Alpine_<hostname:port>\tuser\taltflag
 * and the blob consists of
 * passwd\torighost (if different from host)
 *
 * We don't use anything fancy we just copy out all the credentials which
 * begin with TNAME and put them into our cache, so we don't lookup based
 * on the TargetName or anything like that. That was so we could re-use
 * the existing code and so that orighost data could be easily used.
 */
int
read_passfile(pinerc, l)
    char       *pinerc;
    MMLOGIN_S **l;
{
#ifdef	WINCRED
# if	(WINCRED > 0)
    LPCTSTR lfilter = TEXT(TNAMESTAR);
    DWORD count, k;
    PCREDENTIAL *pcred;
    char *tmp, *blob, *target = NULL;
    char *host, *user, *sflags, *passwd, *orighost;
    char *ui[5];
    int i, j;

    if(using_passfile == 0)
      return(using_passfile);

    if(!g_CredInited){
	if(init_wincred_funcs() != 1){
	    using_passfile = 0;
	    return(using_passfile);
	}
    }

    dprint((9, "read_passfile\n"));

    using_passfile = 1;

    if(g_CredEnumerateW(lfilter, 0, &count, &pcred)){
	if(pcred){
	    for(k = 0; k < count; k++){

		host = user = sflags = passwd = orighost = NULL;
		ui[0] = ui[1] = ui[2] = ui[3] = ui[4] = NULL;

		target = lptstr_to_utf8(pcred[k]->TargetName);
		tmp = srchstr(target, TNAME);

		if(tmp){
		    tmp += strlen(TNAME);
		    for(i = 0, j = 0; tmp[i] && j < 3; j++){
			for(ui[j] = &tmp[i]; tmp[i] && tmp[i] != '\t'; i++)
			  ;					/* find end of data */

			if(tmp[i])
			  tmp[i++] = '\0';			/* tie off data */
		    }

		    host   = ui[0];
		    user   = ui[1];
		    sflags = ui[2];
		}

		blob = (char *) pcred[k]->CredentialBlob;
		if(blob){
		    for(i = 0, j = 3; blob[i] && j < 5; j++){
			for(ui[j] = &blob[i]; blob[i] && blob[i] != '\t'; i++)
			  ;					/* find end of data */

			if(blob[i])
			  blob[i++] = '\0';			/* tie off data */
		    }

		    passwd   = ui[3];
		    orighost = ui[4];
		}

		if(passwd && host && user){		/* valid field? */
		    STRLIST_S hostlist[2];
		    int	      flags;

		    tmp = sflags ? strchr(sflags, PWDAUTHSEP) : NULL;
		    flags = sflags ? atoi(tmp ? ++tmp : sflags) : 0;
		    hostlist[0].name = host;
		    if(orighost){
			hostlist[0].next = &hostlist[1];
			hostlist[1].name = orighost;
			hostlist[1].next = NULL;
		    }
		    else{
			hostlist[0].next = NULL;
		    }

		    imap_set_passwd(l, passwd, user, hostlist, flags & 0x01, 0, 0);
		}

		if(target)
		  fs_give((void **) &target);
	    }

	    g_CredFree((PVOID) pcred);
	}
    }

    return(1);

# else /* old windows */
    using_passfile = 0;
    return(0);
# endif

#elif	APPLEKEYCHAIN

    char  target[MAILTMPLEN];
    char *tmp, *host, *user, *sflags, *passwd, *orighost;
    char *ui[5];
    int   i, j, k, rc;
    SecKeychainAttributeList attrList;
    SecKeychainSearchRef searchRef = NULL;
    SecKeychainAttribute attrs[] = {
	{ kSecAccountItemAttr, strlen(TNAME), TNAME }
    };

    if(using_passfile == 0)
      return(using_passfile);

    dprint((9, "read_passfile\n"));


    /* search for only our items in the keychain */
    attrList.count = 1;
    attrList.attr = attrs;

    using_passfile = 1;
    if(!(rc=SecKeychainSearchCreateFromAttributes(NULL,
					      kSecGenericPasswordItemClass,
                                              &attrList,
                                              &searchRef))){
	dprint((10, "read_passfile: SecKeychainSearchCreate succeeded\n"));
	if(searchRef){
	    SecKeychainItemRef itemRef = NULL;
	    SecKeychainAttributeInfo info;
	    SecKeychainAttributeList *attrList = NULL;
	    UInt32 blength = 0;
	    char *blob = NULL;
	    char *blobcopy = NULL;	/* NULL terminated copy */
	    
	    UInt32 tags[] = {kSecAccountItemAttr,
			     kSecServiceItemAttr};
	    UInt32 formats[] = {0,0};

	    dprint((10, "read_passfile: searchRef not NULL\n"));
	    info.count = 2;
	    info.tag = tags;
	    info.format = formats;

	    /*
	     * Go through each item we found and put it
	     * into our list.
	     */
	    while(!(rc=SecKeychainSearchCopyNext(searchRef, &itemRef)) && itemRef){
	        dprint((10, "read_passfile: SecKeychainSearchCopyNext got one\n"));
		rc = SecKeychainItemCopyAttributesAndData(itemRef,
						     &info, NULL,
						     &attrList,
						     &blength,
						     (void **) &blob);
		if(rc == 0 && attrList){
		    dprint((10, "read_passfile: SecKeychainItemCopyAttributesAndData succeeded, count=%d\n", attrList->count));

		    blobcopy = (char *) fs_get((blength + 1) * sizeof(char));
		    strncpy(blobcopy, (char *) blob, blength);
		    blobcopy[blength] = '\0';

		    /*
		     * I'm not real clear on how this works. It seems to be
		     * necessary to combine the attributes from two passes
		     * (attrList->count == 2) in order to get the full set
		     * of attributes we inserted into the keychain in the
		     * first place. So, we reset host...orighost outside of
		     * the following for loop, not inside.
		     */
		    host = user = sflags = passwd = orighost = NULL;
		    ui[0] = ui[1] = ui[2] = ui[3] = ui[4] = NULL;

		    for(k = 0; k < attrList->count; k++){

			if(attrList->attr[k].length){
			    strncpy(target,
				    (char *) attrList->attr[k].data,
				    MIN(attrList->attr[k].length,sizeof(target)));
			    target[MIN(attrList->attr[k].length,sizeof(target)-1)] = '\0';
			}

			tmp = target;
			for(i = 0, j = 0; tmp[i] && j < 3; j++){
			    for(ui[j] = &tmp[i]; tmp[i] && tmp[i] != '\t'; i++)
			      ;				/* find end of data */

			    if(tmp[i])
			      tmp[i++] = '\0';		/* tie off data */
			}

			if(ui[0])
			  host   = ui[0];

			if(ui[1])
			  user   = ui[1];

			if(ui[2])
			  sflags = ui[2];

		        for(i = 0, j = 3; blobcopy[i] && j < 5; j++){
			    for(ui[j] = &blobcopy[i]; blobcopy[i] && blobcopy[i] != '\t'; i++)
			      ;					/* find end of data */

			    if(blobcopy[i])
			      blobcopy[i++] = '\0';			/* tie off data */
		        }

			if(ui[3])
			  passwd   = ui[3];
			
			if(ui[4])
			  orighost = ui[4];

			dprint((10, "read_passfile: host=%s user=%s sflags=%s passwd=%s orighost=%s\n", host?host:"", user?user:"", sflags?sflags:"", passwd?passwd:"", orighost?orighost:""));
		    }

		    if(passwd && host && user){		/* valid field? */
			STRLIST_S hostlist[2];
			int	      flags;

			tmp   = sflags ? strchr(sflags, PWDAUTHSEP) : NULL;
			flags = sflags ? atoi(tmp ? ++tmp : sflags) : 0;
			hostlist[0].name = host;
			if(orighost){
			    hostlist[0].next = &hostlist[1];
			    hostlist[1].name = orighost;
			    hostlist[1].next = NULL;
			}
			else{
			    hostlist[0].next = NULL;
			}

			imap_set_passwd(l, passwd, user, hostlist, flags & 0x01, 0, 0);
		    }

		    if(blobcopy)
		      fs_give((void **) & blobcopy);

		    SecKeychainItemFreeAttributesAndData(attrList, (void *) blob);
		}
		else{
		    using_passfile = 0;
		    dprint((10, "read_passfile: SecKeychainItemCopyAttributesAndData failed, rc=%d\n", rc));
		}

	        CFRelease(itemRef);
		itemRef = NULL;
	    }

	    CFRelease(searchRef);
	}
	else{
	    using_passfile = 0;
	    dprint((10, "read_passfile: searchRef NULL\n"));
        }
    }
    else{
	using_passfile = 0;
	dprint((10, "read_passfile: SecKeychainSearchCreateFromAttributes failed, rc=%d\n", rc));
    }

    return(using_passfile);

#else /* PASSFILE */

    char  tmp[MAILTMPLEN], *ui[5];
    int   i, j, n, rv = 0;
    size_t len;
    char *tmptext = NULL;
#ifdef SMIME
    char tmp2[MAILTMPLEN];
    char *text = NULL, *text2 = NULL;
    int encrypted = 0;
#endif /* SMIME */
    FILE *fp;

    if(using_passfile == 0)
      return(using_passfile);

    dprint((9, "read_passfile\n"));

    /* if there's no password to read, bag it!! */
    if(!passfile_name(pinerc, tmp, sizeof(tmp)) || !(fp = our_fopen(tmp, "rb"))){
	using_passfile = 0;
	return(using_passfile);
    };

#ifdef SMIME
    /* the next call initializes the key/certificate pair used to
     * encrypt and decrypt a password file. The details of how this is
     * done is in the file pith/smime.c. During this setup we might call
     * smime_init(), but no matter what happens we must call smime_deinit()
     * there. The reason why this is so is because we can not assume that 
     * the .pinerc file has been read by this time, so this code might not
     * know about the ps_global->smime structure or any of its components,
     * and it shouldn't because it only needs ps_global->pwdcert, so 
     * do not init smime here, because the .pinerc might not have been
     * read and we do not really know where the keys and certificates really
     * are.
     * Remark: setupwdcert will produce a null ps_global->pwdcert only when
     * it is called for the first time and there are certificates at all,
     * or when it is called after the first time and the user refuses to 
     * create a self-signed certificate. In this situation we will just
     * let the user live in an insecure world, but no more passwords will
     * be saved in the password file, and only those found there will be used.
     */
    tmp2[0] = '\0';
    fgets(tmp2, sizeof(tmp2), fp);
    fclose(fp);
    if(strcmp(tmp2, "-----BEGIN PKCS7-----\n")){
       /* there is an already existing password file, that is not encrypted
        * and there is no key to encrypt it yet, go again through setup_pwdcert
	* and encrypt it now.
	*/
       if(tmp2[0]){	/* not empty, UNencrypted password file */
	 if(ps_global->pwdcert == NULL)
            rv = setup_pwdcert(&ps_global->pwdcert);
	 if((rv == 0 || rv == -5) && ps_global->pwdcert == NULL)
	    ps_global->pwdcert = (void *) ALPINE_self_signed_certificate(NULL, 0, ps_global->pwdcertdir, MASTERNAME);
	 if(ps_global->pwdcert == NULL){
	    q_status_message(SM_ORDER, 3, 3, 
		" Failed to create private key. Using UNencrypted Password file. ");
	    save_password = 0;
	 }
	 else{
	    if(rv == 1){
	       q_status_message(SM_ORDER, 3, 3, 
		" Failed to unlock private key. Using UNencrypted Password file. ");
	       save_password = 0;	/* do not save more passwords */
	    }
	 }
	if(ps_global->pwdcert != NULL
	    && encrypt_file((char *)tmp, NULL, (PERSONAL_CERT *)ps_global->pwdcert))
	       encrypted++;
       }
    }
    else {
       if(ps_global->pwdcert == NULL)
         rv = setup_pwdcert(&ps_global->pwdcert);
       encrypted++;
    }

    /* 
     * if password file is encrypted we attemtp to decrypt. We ask the 
     * user for the password to unlock the password file. If the user 
     * enters the password and it unlocks the file, use it and keep saving 
     * passwords in it. If the user enters the wrong passwords and does 
     * not unlock it, we will not see that here, but in decrypt_file, so 
     * the only other possibility is that the user cancels. In that case 
     * we will see i == -1. In that case, we will let the user attempt 
     * manual login to the server they want to login, but passwords will 
     * not be saved so that the password file will not be saved 
     * unencrypted and rewritten again.
     */
    if(encrypted){
	text = text2 = decrypt_file((char *)tmp, &i, (PERSONAL_CERT *)ps_global->pwdcert);
	len = text2 ? strlen(text2) : 0;
	switch(i){
	   case -2: using_passfile = 0;
		    break;

	   case 1 : save_password = 1;
		    using_passfile = 1;
		    break;

	   case -1: save_password = 0;
		    using_passfile = 1;
		    break;

	   default: break;
	}
    }
    else{
       struct stat sbuf;
       if(our_stat(tmp, &sbuf) == 0)
	  len = sbuf.st_size;
       else
	  len = 0;
       fp = our_fopen(tmp, "rb");	/* reopen to read data */
    }
#endif /* SMIME */

    if(using_passfile == 0){
#ifdef SMIME
      if(text) fs_give((void **)&text);
#endif /* SMIME */
      return using_passfile;
    }

    if(len > 0){
      tmptext = fs_get(len + 1);
#ifdef SMIME
      for(n = 0; encrypted ? line_get(tmptext, len + 1, &text2) 
	: (fgets(tmptext, len+1, fp) != NULL); n++){
#else /* SMIME */
      for(n = 0; fgets(tmptext, len+1, fp); n++){
#endif /* SMIME */
	/*** do any necessary DEcryption here ***/
	xlate_key = n;
	for(i = 0; tmptext[i]; i++)
	  tmptext[i] = xlate_out(tmptext[i]);

	if(i && tmptext[i-1] == '\n')
	  tmptext[i-1] = '\0';			/* blast '\n' */

	dprint((10, "read_passfile: %s\n", tmp ? tmp : "?"));
	ui[0] = ui[1] = ui[2] = ui[3] = ui[4] = NULL;
	for(i = 0, j = 0; tmptext[i] && j < 5; j++){
	    for(ui[j] = &tmptext[i]; tmptext[i] && tmptext[i] != '\t'; i++)
	      ;					/* find end of data */

	    if(tmptext[i])
	      tmptext[i++] = '\0';			/* tie off data */
	}

	dprint((10, "read_passfile: calling imap_set_passwd\n"));
	if(ui[0] && ui[1] && ui[2]){		/* valid field? */
	    STRLIST_S hostlist[2];
	    char     *s = ui[3] ? strchr(ui[3], PWDAUTHSEP) : NULL;
	    int	  flags = ui[3] ? atoi(s ? ++s : ui[3]) : 0;

	    hostlist[0].name = ui[2];
	    if(ui[4]){
		hostlist[0].next = &hostlist[1];
		hostlist[1].name = ui[4];
		hostlist[1].next = NULL;
	    }
	    else{
		hostlist[0].next = NULL;
	    }

	    imap_set_passwd(l, ui[0], ui[1], hostlist, flags & 0x01, 0, 0);
	}
      }
    }

    if (tmptext) fs_give((void **) &tmptext);
#ifdef SMIME
    if (text) fs_give((void **)&text);
#else /* SMIME */
    fclose(fp);
#endif /* SMIME */
    return(1);
#endif /* PASSFILE */
}



void
write_passfile(pinerc, l)
    char      *pinerc;
    MMLOGIN_S *l;
{
   char *authend, *authtype;
#ifdef	WINCRED
# if	(WINCRED > 0)
    char  target[MAILTMPLEN];
    char  blob[MAILTMPLEN];
    CREDENTIAL cred;
    LPTSTR ltarget = 0;

    if(using_passfile == 0)
      return;

    dprint((9, "write_passfile\n"));

    for(; l; l = l->next){
	authtype = l->passwd;
	authend = strchr(l->passwd, PWDAUTHSEP);
	if(authend != NULL){
	   *authend = '\0';
	   sprintf(blob, "%s%c%d", authtype, PWDAUTHSEP, l->altflag);
	   *authend = PWDAUTHSEP;
        }
	else
	   sprintf(blob, "%d", l->altflag);

	snprintf(target, sizeof(target), "%s%s\t%s\t%s",
		 TNAME,
		 (l->hosts && l->hosts->name) ? l->hosts->name : "",
		 l->user ? l->user : "",
		 blob);
	ltarget = utf8_to_lptstr((LPSTR) target);

	if(ltarget){
	    snprintf(blob, sizeof(blob), "%s%s%s",
		     l->passwd ? l->passwd : "", 
		     (l->hosts && l->hosts->next && l->hosts->next->name)
			 ? "\t" : "",
		     (l->hosts && l->hosts->next && l->hosts->next->name)
			 ? l->hosts->next->name : "");
	    memset((void *) &cred, 0, sizeof(cred));
	    cred.Flags = 0;
	    cred.Type = CRED_TYPE_GENERIC;
	    cred.TargetName = ltarget;
	    cred.CredentialBlobSize = strlen(blob)+1;
	    cred.CredentialBlob = (LPBYTE) &blob;
	    cred.Persist = CRED_PERSIST_ENTERPRISE;
	    g_CredWriteW(&cred, 0);

	    fs_give((void **) &ltarget);
	}
    }
 #endif	/* WINCRED > 0 */

#elif	APPLEKEYCHAIN
    int   rc;
    char  target[MAILTMPLEN];
    char  blob[MAILTMPLEN];
    SecKeychainItemRef itemRef = NULL;

    if(using_passfile == 0)
      return;

    dprint((9, "write_passfile\n"));

    for(; l; l = l->next){
	authtype = l->passwd;
	authend = strchr(l->passwd, PWDAUTHSEP);
	if(authend != NULL){
	   *authend = '\0';
	   sprintf(blob, "%s%c%d", authtype, PWDAUTHSEP, l->altflag);
	   *authend = PWDAUTHSEP;
        }
	else
	   sprintf(blob, "%d", l->altflag);

	snprintf(target, sizeof(target), "%s\t%s\t%s",
		 (l->hosts && l->hosts->name) ? l->hosts->name : "",
		 l->user ? l->user : "",
		 blob);

	snprintf(blob, sizeof(blob), "%s%s%s",
		 l->passwd ? l->passwd : "", 
		 (l->hosts && l->hosts->next && l->hosts->next->name)
			 ? "\t" : "",
		 (l->hosts && l->hosts->next && l->hosts->next->name)
			 ? l->hosts->next->name : "");

	dprint((10, "write_passfile: SecKeychainAddGenericPassword(NULL, %d, %s, %d, %s, %d, %s, NULL)\n", strlen(target), target, strlen(TNAME), TNAME, strlen(blob), blob));

	rc = SecKeychainAddGenericPassword(NULL,
				  	   strlen(target), target,
					   strlen(TNAME), TNAME,
					   strlen(blob), blob,
					   NULL);
	if(rc==0){
	    dprint((10, "write_passfile: SecKeychainAddGenericPassword succeeded\n"));
	}
	else{
	    dprint((10, "write_passfile: SecKeychainAddGenericPassword returned rc=%d\n", rc));
	}

	if(rc == errSecDuplicateItem){
	    /* fix existing entry */
	    dprint((10, "write_passfile: SecKeychainAddGenericPassword found existing entry\n"));
	    itemRef = NULL;
	    if(!(rc=SecKeychainFindGenericPassword(NULL,
				  	   strlen(target), target,
					   strlen(TNAME), TNAME,
					   NULL, NULL,
					   &itemRef)) && itemRef){

	        rc = SecKeychainItemModifyAttributesAndData(itemRef, NULL, strlen(blob), blob);
		if(!rc){
	            dprint((10, "write_passfile: SecKeychainItemModifyAttributesAndData returned rc=%d\n", rc));
		}
	    }
	    else{
	        dprint((10, "write_passfile: SecKeychainFindGenericPassword returned rc=%d\n", rc));
	    }
	}
    }

#else /* PASSFILE */
    char  tmp[4*MAILTMPLEN], blob[4*MAILTMPLEN];
    int   i, n;
    FILE *fp;
#ifdef SMIME
    char *text = NULL, tmp2[4*MAILTMPLEN];
    int len = 0;
#endif

    if(using_passfile == 0)
      return;

    dprint((9, "write_passfile\n"));

    /* if there's no passfile to read, bag it!! */
    if(!passfile_name(pinerc, tmp, sizeof(tmp)) || !(fp = our_fopen(tmp, "wb"))){
	using_passfile = 0;
        return;
    }

#ifdef SMIME
   strncpy(tmp2, tmp, sizeof(tmp2));
   tmp2[sizeof(tmp2)-1] = '\0';
#endif /* SMIME */

    for(n = 0; l; l = l->next, n++){
	authtype = l->passwd;
	authend = strchr(l->passwd, PWDAUTHSEP);
	if(authend != NULL){
	   *authend = '\0';
	   sprintf(blob, "%s%c%d", authtype, PWDAUTHSEP, l->altflag);
	   *authend = PWDAUTHSEP;
        }
	else
	   sprintf(blob, "%d", l->altflag);

	/*** do any necessary ENcryption here ***/
	snprintf(tmp, sizeof(tmp), "%s\t%s\t%s\t%s%s%s\n", l->passwd, l->user,
		l->hosts->name, blob,
		(l->hosts->next && l->hosts->next->name) ? "\t" : "",
		(l->hosts->next && l->hosts->next->name) ? l->hosts->next->name
							 : "");
	dprint((10, "write_passfile: %s", tmp ? tmp : "?"));
	xlate_key = n;
	for(i = 0; tmp[i]; i++)
	  tmp[i] = xlate_in(tmp[i]);

#ifdef SMIME
	fs_resize((void **)&text, (len + strlen(tmp) + 1)*sizeof(char));
	text[len] = '\0';
	len += strlen(tmp) + 1;
	strncat(text, tmp, strlen(tmp));
#else /* SMIME */
	fputs(tmp, fp);
#endif /* SMIME */
    }

    fclose(fp);
#ifdef SMIME
    if(text != NULL){
       if(ps_global->pwdcert == NULL){
	  q_status_message(SM_ORDER, 3, 3, "Attempting to encrypt password file");
	  i = setup_pwdcert(&ps_global->pwdcert);
	  if((i == 0 || i == -5) && ps_global->pwdcert == NULL)
	    ps_global->pwdcert = (void *) ALPINE_self_signed_certificate(NULL, 0, ps_global->pwdcertdir, MASTERNAME);
       }
       if(ps_global->pwdcert == NULL){	/* we tried but failed	*/
	if(i == -1)
	  q_status_message1(SM_ORDER, 3, 3, "Error: no directory %s to save certificates", ps_global->pwdcertdir);
	else
	  q_status_message(SM_ORDER, 3, 3, "Refusing to write non-encrypted password file");
       }
       else if(encrypt_file((char *)tmp2, text, ps_global->pwdcert) == 0)
	  q_status_message(SM_ORDER, 3, 3, "Failed to encrypt password file");
       fs_give((void **)&text);	/* do not save this text */
    }
#endif /* SMIME */
#endif /* PASSFILE */
}

#endif	/* LOCAL_PASSWD_CACHE */


#if	(WINCRED > 0)
void
erase_windows_credentials(void)
{
    LPCTSTR lfilter = TEXT(TNAMESTAR);
    DWORD count, k;
    PCREDENTIAL *pcred;

    if(!g_CredInited){
	if(init_wincred_funcs() != 1)
	  return;
    }

    if(g_CredEnumerateW(lfilter, 0, &count, &pcred)){
	if(pcred){
	    for(k = 0; k < count; k++)
	      g_CredDeleteW(pcred[k]->TargetName, CRED_TYPE_GENERIC, 0);

	    g_CredFree((PVOID) pcred);
	}
    }
}

void
ask_erase_credentials(void)
{
    if(want_to(_("Erase previously preserved passwords"), 'y', 'x', NO_HELP, WT_NORM) == 'y'){
	erase_windows_credentials();
	q_status_message(SM_ORDER, 3, 3, "All preserved passwords have been erased");
    }
    else
      q_status_message(SM_ORDER, 3, 3, "Previously preserved passwords will not be erased");
}

#endif	/* WINCRED */


#ifdef	LOCAL_PASSWD_CACHE
int
get_passfile_passwd(pinerc, passwd, user, hostlist, altflag)
    char      *pinerc, **passwd, *user;
    STRLIST_S *hostlist;
    int	       altflag;
{
    return get_passfile_passwd_auth(pinerc, passwd, user, hostlist, altflag, NULL);
}

/*
 * get_passfile_passwd_auth - return the password contained in the special passord
 *            cache.  The file is assumed to be in the same directory
 *            as the pinerc with the name defined above.
 */
int
get_passfile_passwd_auth(pinerc, passwd, user, hostlist, altflag, authtype)
    char      *pinerc, **passwd, *user;
    STRLIST_S *hostlist;
    int	       altflag;
    char      *authtype;
{
    dprint((10, "get_passfile_passwd_auth\n"));
    return((passfile_cache || read_passfile(pinerc, &passfile_cache))
	     ? imap_get_passwd_auth(passfile_cache, passwd,
			       user, hostlist, altflag, authtype)
	     : 0);
}

void
free_passfile_cache_work(MMLOGIN_S **pwdcache)
{
  if(pwdcache == NULL || *pwdcache == NULL)
    return;

  if((*pwdcache)->user) fs_give((void **)&(*pwdcache)->user);
//  if((*pwdcache)->passwd) fs_give((void **)&(*pwdcache)->passwd);
  if((*pwdcache)->hosts) free_strlist(&(*pwdcache)->hosts);
  free_passfile_cache_work(&(*pwdcache)->next);
  fs_give((void **)pwdcache);
}


void
free_passfile_cache(void)
{
  if(passfile_cache)
    free_passfile_cache_work(&passfile_cache);
}

int
is_using_passfile(void)
{
    return(using_passfile == 1);
}

/*
 * Just trying to guess the username the user might want to use on this
 * host, the user will confirm.
 */
char *
get_passfile_user(pinerc, hostlist)
    char      *pinerc;
    STRLIST_S *hostlist;
{
    return((passfile_cache || read_passfile(pinerc, &passfile_cache))
	     ? imap_get_user(passfile_cache, hostlist)
	     : NULL);
}


int
preserve_prompt(char *pinerc)
{
  return preserve_prompt_auth(pinerc, NULL);
}

int
preserve_prompt_auth(char *pinerc, char *authtype)
{
#ifdef	WINCRED
# if	(WINCRED > 0)
#define PROMPT_PWD _("Preserve password for next login")
#define PROMPT_OA2 _("Preserve Refresh and Access tokens for next login")
    /* 
     * This prompt was going to be able to be turned on and off via a registry
     * setting controlled from the config menu.  We decided to always use the
     * dialog for login, and there the prompt is unobtrusive enough to always
     * be in there.  As a result, windows should never reach this, but now
     * OS X somewhat uses the behavior just described.
     */
    if(mswin_store_pass_prompt()
       && (want_to(authtype 
		? (strcmp(authtype, OA2NAME) ? PROMPT_PWD : PROMPT_OA2)
		: PROMPT_PWD,
		  'y', 'x', NO_HELP, WT_NORM)
	   == 'y'))
      return(1);
    else
      return(0);
# else
    return(0);
# endif

#elif	APPLEKEYCHAIN
#define PROMPT_PWD _("Preserve password for next login")
#define PROMPT_OA2 _("Preserve Refresh and Access tokens for next login")

    int rc;
    if((rc = macos_store_pass_prompt()) != 0){
        if(want_to(authtype 
		? (strcmp(authtype, OA2NAME) ? PROMPT_PWD : PROMPT_OA2)
		: PROMPT_PWD, 'y', 'x', NO_HELP, WT_NORM)
	   == 'y'){
	    if(rc == -1){
		macos_set_store_pass_prompt(1);
		q_status_message(SM_ORDER, 4, 4,
		   _("Stop \"Preserve passwords?\" prompts by deleting Alpine Keychain entry"));
	    }
	    return(1);
	}
	else if(rc == -1){
	    macos_set_store_pass_prompt(0);
	    q_status_message(SM_ORDER, 4, 4,
		   _("Restart \"Preserve passwords?\" prompts by deleting Alpine Keychain entry"));
	}
	return(0);
    }
    return(0);
#else /* PASSFILE */
#define PROMPT_PWD _("Preserve password on DISK for next login")
#define PROMPT_OA2 _("Preserve Refresh and Access tokens on DISK for next login")

    char tmp[MAILTMPLEN];
    struct stat sbuf;

    if(!passfile_name(pinerc, tmp, sizeof(tmp)) || our_stat(tmp, &sbuf) < 0)
        return 0;

    if(F_OFF(F_DISABLE_PASSWORD_FILE_SAVING,ps_global))
	return(want_to(authtype 
		? (strcmp(authtype, OA2NAME) ? PROMPT_PWD : PROMPT_OA2)
		: PROMPT_PWD, 'y', 'x', NO_HELP, WT_NORM)
	   == 'y');
    return(0);
#endif /* PASSFILE */
}

#endif	/* LOCAL_PASSWD_CACHE */


#ifdef	APPLEKEYCHAIN

/*
 *  Returns:
 *   1 if store pass prompt is set in the "registry" to on
 *   0 if set to off
 *   -1 if not set to anything
 */
int
macos_store_pass_prompt(void)
{
    char *data = NULL;
    UInt32 len = 0;
    int rc = -1;
    int val;

    if(storepassprompt == -1){
	if(!(rc=SecKeychainFindGenericPassword(NULL, 0, NULL,
					       strlen(TNAMEPROMPT),
					       TNAMEPROMPT, &len,
					       (void **) &data, NULL))){
	    val = (len == 1 && data && data[0] == '1');
	}
    }

    if(storepassprompt == -1 && !rc){
	if(val)
	  storepassprompt = 1;
	else
	  storepassprompt = 0;
    }

    return(storepassprompt);
}


void
macos_set_store_pass_prompt(int val)
{
    storepassprompt = val ? 1 : 0;
    
    SecKeychainAddGenericPassword(NULL, 0, NULL, strlen(TNAMEPROMPT),
				  TNAMEPROMPT, 1, val ? "1" : "0", NULL);
}


void
macos_erase_keychain(void)
{
    SecKeychainAttributeList attrList;
    SecKeychainSearchRef searchRef = NULL;
    SecKeychainAttribute attrs1[] = {
	{ kSecAccountItemAttr, strlen(TNAME), TNAME }
    };
    SecKeychainAttribute attrs2[] = {
	{ kSecAccountItemAttr, strlen(TNAMEPROMPT), TNAMEPROMPT }
    };

    dprint((9, "macos_erase_keychain\n"));

    /*
     * Seems like we ought to be able to combine attrs1 and attrs2
     * into a single array, but I couldn't get it to work.
     */

    /* search for only our items in the keychain */
    attrList.count = 1;
    attrList.attr = attrs1;

    if(!SecKeychainSearchCreateFromAttributes(NULL,
					      kSecGenericPasswordItemClass,
                                              &attrList,
                                              &searchRef)){
	if(searchRef){
	    SecKeychainItemRef itemRef = NULL;

	    /*
	     * Go through each item we found and put it
	     * into our list.
	     */
	    while(!SecKeychainSearchCopyNext(searchRef, &itemRef) && itemRef){
	        dprint((10, "read_passfile: SecKeychainSearchCopyNext got one\n"));
		SecKeychainItemDelete(itemRef);
	        CFRelease(itemRef);
	    }

	    CFRelease(searchRef);
	}
    }

    attrList.count = 1;
    attrList.attr = attrs2;

    if(!SecKeychainSearchCreateFromAttributes(NULL,
					      kSecGenericPasswordItemClass,
                                              &attrList,
                                              &searchRef)){
	if(searchRef){
	    SecKeychainItemRef itemRef = NULL;
	    
	    /*
	     * Go through each item we found and put it
	     * into our list.
	     */
	    while(!SecKeychainSearchCopyNext(searchRef, &itemRef) && itemRef){
		SecKeychainItemDelete(itemRef);
	        CFRelease(itemRef);
	    }

	    CFRelease(searchRef);
	}
    }
}

#endif	/* APPLEKEYCHAIN */

#ifdef	LOCAL_PASSWD_CACHE

void
set_passfile_passwd(pinerc, passwd, user, hostlist, altflag, already_prompted)
    char      *pinerc, *passwd, *user;
    STRLIST_S *hostlist;
    int	       altflag, already_prompted;
{
   set_passfile_passwd_auth(pinerc, passwd, user, hostlist, altflag, already_prompted, NULL);
}
/*
 * set_passfile_passwd - set the password file entry associated with
 *            cache.  The file is assumed to be in the same directory
 *            as the pinerc with the name defined above.
 *            already_prompted: 0 not prompted
 *                              1 prompted, answered yes
 *                              2 prompted, answered no
 */
void
set_passfile_passwd_auth(pinerc, passwd, user, hostlist, altflag, already_prompted, authtype)
    char      *pinerc, *passwd, *user;
    STRLIST_S *hostlist;
    int	       altflag, already_prompted;
    char      *authtype;
{
    dprint((10, "set_passfile_passwd_auth\n"));
    if(((already_prompted == 0 && preserve_prompt_auth(pinerc, authtype))
	   || already_prompted == 1)
       && !ps_global->nowrite_password_cache
       && (passfile_cache || read_passfile(pinerc, &passfile_cache))){
	imap_set_passwd_auth(&passfile_cache, passwd, user, hostlist, altflag, 0, 0, authtype);
	write_passfile(pinerc, passfile_cache);
    }
}

void
update_passfile_hostlist(pinerc, user, hostlist, altflag)
    char      *pinerc;
    char      *user;
    STRLIST_S *hostlist;
    int        altflag;
{
  update_passfile_hostlist_auth(pinerc, user, hostlist, altflag, NULL);
}

/*
 * Passfile lines are
 *
 *   passwd TAB user TAB hostname TAB flags [ TAB orig_hostname ] \n
 *
 * In pine4.40 and before there was no orig_hostname.
 * This routine attempts to repair that.
 */
void
update_passfile_hostlist_auth(pinerc, user, hostlist, altflag, authtype)
    char      *pinerc;
    char      *user;
    STRLIST_S *hostlist;
    int        altflag;
    char      *authtype;
{
#ifdef	 WINCRED
    return;
#else /* !WINCRED */
    MMLOGIN_S *l;
    size_t  len    = authtype ? strlen(authtype) : 0;
    size_t  offset = authtype ? 1 : 0;
    
    for(l = passfile_cache; l; l = l->next)
      if(imap_same_host_auth(l->hosts, hostlist, authtype)
	 && *user
	 && !strcmp(user, l->user + len + offset)
	 && l->altflag == altflag){
	  break;
      }
    
    if(l && l->hosts && hostlist && !l->hosts->next && hostlist->next
       && hostlist->next->name
       && !ps_global->nowrite_password_cache){
	l->hosts->next = new_strlist_auth(hostlist->next->name, authtype, PWDAUTHSEP);
	write_passfile(pinerc, passfile_cache);
    }
#endif /* !WINCRED */
}

#endif	/* LOCAL_PASSWD_CACHE */


#if	(WINCRED > 0)
/*
 * Load and init the WinCred structure.
 * This gives us a way to skip the WinCred code
 * if the dll doesn't exist.
 */
int
init_wincred_funcs(void)
{
    if(!g_CredInited)
    {
        HMODULE hmod;

        /* Assume the worst. */
        g_CredInited = -1;

        hmod = LoadLibrary(TEXT("advapi32.dll"));
        if(hmod)
        {
            FARPROC fpCredWriteW;
            FARPROC fpCredEnumerateW;
            FARPROC fpCredDeleteW;
            FARPROC fpCredFree;

            fpCredWriteW     = GetProcAddress(hmod, "CredWriteW");
            fpCredEnumerateW = GetProcAddress(hmod, "CredEnumerateW");
            fpCredDeleteW    = GetProcAddress(hmod, "CredDeleteW");
            fpCredFree       = GetProcAddress(hmod, "CredFree");

            if(fpCredWriteW && fpCredEnumerateW  && fpCredDeleteW && fpCredFree)
            {
                g_CredWriteW     = (CREDWRITEW *)fpCredWriteW;
                g_CredEnumerateW = (CREDENUMERATEW *)fpCredEnumerateW;
                g_CredDeleteW    = (CREDDELETEW *)fpCredDeleteW;
                g_CredFree       = (CREDFREE *)fpCredFree;

                g_CredInited = 1;
            }
        }

	mswin_set_erasecreds_callback(ask_erase_credentials);
    }

    return g_CredInited;
}

#endif	 /* WINCRED */
