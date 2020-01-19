#if	!defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: search.c 1266 2009-07-14 18:39:12Z hubert@u.washington.edu $";
#endif

/*
 * ========================================================================
 * Copyright 2013-2020 Eduardo Chappa
 * Copyright 2006-2008 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 */

/*
 * Program:	Searching routines
 *
 * The functions in this file implement commands that search in the forward
 * and backward directions. There are no special characters in the search
 * strings. Probably should have a regular expression search, or something
 * like that.
 *
 */

#include	"headers.h"

int	eq(UCS, UCS);
int	expandp(UCS *, UCS *, int);
int	readnumpat(char *);
void	get_pat_cases(UCS *, UCS *);
int     srpat(char *, UCS *, size_t, int, int);
int     readpattern(char *, int, int);
int     replace_pat(UCS *, int *, int);
int     replace_all(UCS *, UCS *, int);
void	reverse_line(LINE *);
void	reverse_buffer(void);
void	reverse_ucs4(UCS *);
void	reverse_all(UCS *, int);
void	supdate(UCS *, int);
char   *sucs4_to_utf8_cpystr(UCS *, int);

#define	FWS_RETURN(RV)	{				\
			    thisflag |= CFSRCH;		\
			    curwp->w_flag |= WFMODE;	\
			    sgarbk = TRUE;		\
			    return(RV);			\
			}

/* The search menu leaves a number of keys free, some are taken
 * as subcommands of the search command, and some are taken are
 * editing commands. This leaves the following keys open:
 * ^J, ^N, ^O, ^P, ^R, ^T, ^U, ^V, ^W, ^X and ^Y.
 * Out of these keys, ^J, ^N, ^P and ^X are not defined as commands, however,
 * in some patches ^N, ^P and ^X are defined. ^N is defined as part of
 * an editing command, ^P and ^X are defined to delete paragraphs and to
 * remove text to the end of file, so only ^J is undefined.
 */

#define REPLACE_KEY	2	/* the location of the replace key in the array below */

EXTRAKEYS    menu_srchpat[] = {
	{"^Y", N_("FirstLine"),	    (CTRL|'Y')},
	{"^V", N_("LastLine"), 	    (CTRL|'V')},
	{"^R", N_("No Replace"),    (CTRL|'R')},
	{"^^", N_("Optns Menu"),    (CTRL|'^')},  /* toggle this menu or options menu */
	{"^T", N_("LineNumber"),    (CTRL|'T')},
	{"^W", N_("Start of Para"), (CTRL|'W')},
	{"^O", N_("End of Para"),   (CTRL|'O')},
	{"^U", N_("FullJustify"),   (CTRL|'U')},
	{NULL, NULL, 0},
	{NULL, NULL, 0}
};

#define EXACTSR_KEY     1	/* toggle an exact or approximate search */
#define BGNLINE_KEY	3	/* the location of Bgn Line command  in the array below */
#define ENDLINE_KEY	4	/* the location of End Line command  in the array below */
#define BSEARCH_KEY	5	/* the location of the bsearch key in the array below */
EXTRAKEYS    menu_srchopt[] = {
	{"^^", N_("Orig Menu"),  (CTRL|'^')},	/* toggle original or options menu */
	{"^X", N_("Exact"),      (CTRL|'X')},	/* toggle exact vs non exact */
	{"^R", N_("No Replace"), (CTRL|'R')},	/* toggle replace or not replace */
	{"^V", N_("Bgn Line"),   (CTRL|'V')},	/* toggle Bgn Line or anywhere */
	{"^N", N_("End Line"),   (CTRL|'N')},	/* toggle End Line or anywhere */
	{"^P", N_("BackSearch"), (CTRL|'P')},	/* toggle Backward or forward */
	{NULL, NULL, 0},
	{NULL, NULL, 0},
	{NULL, NULL, 0},
	{NULL, NULL, 0}
};

/*
 * Search forward. Get a search string from the user, and search, beginning at
 * ".", for the string. If found, reset the "." to be just after the match
 * string, and [perhaps] repaint the display. Bound to "C-S".
 */

/*	string search input parameters	*/

#define	PTBEG	1	/* leave the point at the beginning on search */
#define	PTEND	2	/* leave the point at the end on search */

#define NPMT (2*NLINE+32)


static char *SearchHelpText[] = {
/* TRANSLATORS: Some help text that goes together in a group. */
N_("Help for Search Command"),
" ",
N_("        Enter the words or characters you would like to search"),
N_("~        for, then press ~R~e~t~u~r~n.  The search then takes place."),
N_("        When the characters or words that you entered "),
N_("        are found, the buffer will be redisplayed with the cursor "),
N_("        at the beginning of the selected text."),
" ",
N_("        The most recent string for which a search was made is"),
N_("        displayed in the \"Search\" prompt between the square"),
N_("        brackets.  This string is the default search prompt."),
N_("~        Hitting only ~R~e~t~u~r~n or at the prompt will cause the"),
N_("        search to be made with the default value."),
"  ",
N_("        The text search is not case sensitive, and will examine the"),
N_("        entire message."),
"  ",
N_("        Should the search fail, a message will be displayed."),
"  ",
N_("End of Search Help."),
"  ",
NULL
};


/*
 * Compare two characters. The "bc" comes from the buffer. It has it's case
 * folded out. The "pc" is from the pattern.
 */
int
eq(UCS bc, UCS pc)
{
    if ((curwp->w_bufp->b_mode & MDEXACT) == 0){
	if (bc>='a' && bc<='z')
	  bc -= 0x20;

	if (pc>='a' && pc<='z')
	  pc -= 0x20;
    }

    return(bc == pc);
}


int
forwsearch(int f, int n)
{
  int              status, flags;
  int              wrapt = FALSE, wrapt2 = FALSE;
  int              repl_mode = FALSE;
  UCS              defpat[NPAT];
  int              search = FALSE;
  EML              eml;


    /* resolve the repeat count */
    if (n == 0)
      n = 1;

    if (n < 1)			/* search backwards */
      FWS_RETURN(0);

    defpat[0] = '\0';
	/* defaults: usual menu, search forward, not case sensitive */

    flags = SR_ORIGMEN | SR_FORWARD;

    /* exact search is sticky -- that is, once one is done, so will be
     * the next ones. This is consistent with all all searches being
     * case insensitive by default.
     */
    if((curwp->w_bufp->b_mode & MDEXACT) == 0)
	flags |= SR_NOEXACT;
    else
	flags |= SR_EXACTSR;

    /* ask the user for the text of a pattern */
    while(1){

	if (gmode & MDREPLACE)
	  status = srpat("Search", defpat, NPAT, repl_mode, flags);
	else
	  status = readpattern("Search", TRUE, flags);

	switch(status){
	  case TRUE:                         /* user typed something */
	    search = TRUE;
	    break;

	  case HELPCH:			/* help requested */
	    if(Pmaster){
		VARS_TO_SAVE *saved_state;

		saved_state = save_pico_state();
		(*Pmaster->helper)(Pmaster->search_help,
				   _("Help for Searching"), 1);
		if(saved_state){
		    restore_pico_state(saved_state);
		    free_pico_state(saved_state);
		}
	    }
	    else
	      pico_help(SearchHelpText, _("Help for Searching"), 1);

	  case (CTRL|'L'):			/* redraw requested */
	    pico_refresh(FALSE, 1);
	    update();
	    break;
	    

	  case (CTRL|'P'):
	    if(flags & SR_ORIGMEN){
		/* Undefined still */
	    }
	    if(flags & SR_OPTNMEN){
	      if(flags & SR_FORWARD){
		flags &= ~SR_FORWARD;
		flags |=  SR_BACKWRD;
	      } else {
		flags &= ~SR_BACKWRD;
		flags |=  SR_FORWARD;
	      }
	    }
	    break;

	  case  (CTRL|'V'):
	    if(flags & SR_ORIGMEN){
	       gotoeob(0, 1);
	       mlerase();
	       FWS_RETURN(TRUE);
	    } else if (flags & SR_OPTNMEN){
		if(flags & SR_ENDLINE)
		  flags &= ~SR_ENDLINE;
		if(flags & SR_BEGLINE)
		  flags &= ~SR_BEGLINE;
		else
		  flags |= SR_BEGLINE;
	    }
	    break;

	  case  (CTRL|'N'):
	    if(flags & SR_ORIGMEN){
		/* undefined still */
	    } else if (flags & SR_OPTNMEN){
		if(flags & SR_BEGLINE)
		  flags &= ~SR_BEGLINE;
		if(flags & SR_ENDLINE)
		  flags &= ~SR_ENDLINE;
		else
		  flags |= SR_ENDLINE;
	    }
	    break;

	  case (CTRL|'Y'):
	    if(flags & SR_ORIGMEN){
	      gotobob(0, 1);
	      mlerase();
	      FWS_RETURN(TRUE);
	    }

	  case (CTRL|'^'):
	    if (flags & SR_ORIGMEN){
		flags &= ~SR_ORIGMEN;
		flags |=  SR_OPTNMEN;
	    } else {
		flags &= ~SR_OPTNMEN;
		flags |=  SR_ORIGMEN;
	    }
	    break;

	  case (CTRL|'X'):
	    if(flags & SR_OPTNMEN){
	      if (flags & SR_NOEXACT){
		flags &= ~SR_NOEXACT;
		flags |=  SR_EXACTSR;
	      } else {
		flags &= ~SR_EXACTSR;
		flags |=  SR_NOEXACT;
	      }
	      if((curwp->w_bufp->b_mode & MDEXACT) == 0)
		curwp->w_bufp->b_mode |= MDEXACT;
	      else
		curwp->w_bufp->b_mode &= ~MDEXACT;
	    }
	    break;

	  case (CTRL|'T') :
	    if(flags & SR_ORIGMEN){
	      switch(status = readnumpat(_("Search to Line Number : "))){
	        case -1 :
		  emlwrite(_("Search to Line Number Cancelled"), NULL);
		  FWS_RETURN(FALSE);

	        case  0 :
		  emlwrite(_("Line number must be greater than zero"), NULL);
		  FWS_RETURN(FALSE);

	        case -2 :
		  emlwrite(_("Line number must contain only digits"), NULL);
		  FWS_RETURN(FALSE);
		
	        case -3 :
		  continue;

	        default :
		  gotoline(0, status);
		  mlerase();
		  FWS_RETURN(TRUE);
	      }
	    }
	    break;

	  case  (CTRL|'W'):
	    if(flags & SR_ORIGMEN){
		LINE *linep = curwp->w_dotp;
		int   offset = curwp->w_doto;

		gotobop(0, 1);
		gotobol(0, 1);

		/*
		 * if we're asked to backup and we're already
		 *
		 */
		if((lastflag & CFSRCH)
		   && linep == curwp->w_dotp
		   && offset == curwp->w_doto
		   && !(offset == 0 && lback(linep) == curbp->b_linep)){
		    backchar(0, 1);
		    gotobop(0, 1);
		    gotobol(0, 1);
		}
		mlerase();
		FWS_RETURN(TRUE);
	    }
	    break;

	  case  (CTRL|'O'):
	    if(flags & SR_ORIGMEN){
	      if(curwp->w_dotp != curbp->b_linep){
		gotoeop(0, 1);
		forwchar(0, 1);
	      }
	      mlerase();
	      FWS_RETURN(TRUE);
	    }
	    break;

	  case (CTRL|'U'):
	    if(flags & SR_ORIGMEN){
	      fillbuf(0, 1);
	      mlerase();
	      FWS_RETURN(TRUE);
	    }
	    break;

	  case  (CTRL|'R'):        /* toggle replacement option */
	    repl_mode = !repl_mode;
	    break;

	  default:
	    if(status == ABORT)
	      emlwrite(_("Search Cancelled"), NULL);
	    else
	      mlerase();

	    FWS_RETURN(FALSE);
	}

	/* replace option is disabled */
	if (!(gmode & MDREPLACE)){
	    ucs4_strncpy(defpat, pat, NPAT);
	    defpat[NPAT-1] = '\0';
	    break;
	}
	else if (search){  /* search now */
	    ucs4_strncpy(pat, defpat, NPAT);	/* remember this search for the future */
	    pat[NPAT-1] = '\0';
	    break;
	}
    }

    reverse_all(defpat, flags & SR_BACKWRD);

    /*
     * This code is kind of dumb.  What I want is successive C-W 's to 
     * move dot to successive occurrences of the pattern.  So, if dot is
     * already sitting at the beginning of the pattern, then we'll move
     * forward a char before beginning the search.  We'll let the
     * automatic wrapping handle putting the dot back in the right 
     * place...
     */
    status = 0;		/* using "status" as int temporarily! */
    while(1){
	if(defpat[status] == '\0'){
	    forwchar(0, 1);
	    break;
	}

	if(status + curwp->w_doto >= llength(curwp->w_dotp) ||
	   !eq(defpat[status],lgetc(curwp->w_dotp, curwp->w_doto + status).c))
	  break;
	status++;
    }

    /* search for the pattern */
    
    while (n-- > 0) {
	if((status = forscan(&wrapt,defpat, flags, NULL,0,PTBEG)) == FALSE)
	  break;
    }

    /* and complain if not there */
    if (status == FALSE){
      char *utf8;
      UCS x[1];

      x[0] = '\0';

      utf8 = sucs4_to_utf8_cpystr(defpat ? defpat : x, flags & SR_BACKWRD); 
      /* TRANSLATORS: reporting the result of a failed search */
      eml.s = utf8;
      emlwrite(_("\"%s\" not found"), &eml);
      if(utf8)
	fs_give((void **) &utf8);
    }
    else if((gmode & MDREPLACE) && repl_mode == TRUE){
        status = replace_pat(defpat, &wrapt2, flags & SR_BACKWRD);    /* replace pattern */
	if (wrapt == TRUE || wrapt2 == TRUE){
	    eml.s = (status == ABORT) ? "cancelled but wrapped" : "Wrapped";
	    emlwrite("Replacement %s", &eml);
	}
    }
    else if(wrapt == TRUE){
	emlwrite("Search Wrapped", NULL);
    }
    else if(status == TRUE){
	emlwrite("", NULL);
    }

    reverse_all(defpat, flags & SR_BACKWRD);
    if(curwp->w_doto == -1){
      curwp->w_doto  = 0;
      curwp->w_flag |= WFMOVE;
    }
    FWS_RETURN(status);
}


/* Replace a pattern with the pattern the user types in one or more times. */
int
replace_pat(UCS *defpat, int *wrapt, int bsearch)
{
  register         int status;
  UCS              lpat[NPAT], origpat[NPAT];	/* case sensitive pattern */
  EXTRAKEYS        menu_pat[12];
  int              repl_all = FALSE;
  UCS             *b;
  char             utf8tmp[NPMT];
  UCS              prompt[NPMT];
  UCS             *promptp;
  int		   i, flags;

    if(bsearch){
	flags = SR_BACKWRD;
	curwp->w_doto -= ucs4_strlen(defpat) - 1;
    }
    else flags = SR_FORWARD;

    forscan(wrapt, defpat, flags, NULL, 0, PTBEG);    /* go to word to be replaced */

    lpat[0] = '\0';
    memset((void *)&menu_pat, 0, sizeof(menu_pat));
    /* additional 'replace all' menu option */
    menu_pat[0].name  = "^X";
    menu_pat[0].key   = (CTRL|'X');
    menu_pat[0].label = N_("Repl All");
    KS_OSDATASET(&menu_pat[0], KS_NONE);

    while(1) {

	/* we need to reverse the buffer back to its original state, so that 
	 * the user will not see that we reversed it under them. The cursor
	 * is at the beginning of the reverse string, that is at the end
	 * of the string. Move it back to the beginning.
	 */

	reverse_all(defpat, bsearch);		 /* reverse for normal view */
	update();
	(*term.t_rev)(1);
	get_pat_cases(origpat, defpat);
	pputs(origpat, 1);                       /* highlight word */
	(*term.t_rev)(0);

	snprintf(utf8tmp, NPMT, "Replace%s \"", repl_all ? " every" : "");
	b = utf8_to_ucs4_cpystr(utf8tmp);
	if(b){
	    ucs4_strncpy(prompt, b, NPMT);
	    prompt[NPMT-1] = '\0';
	    fs_give((void **) &b);
	}

	promptp = &prompt[ucs4_strlen(prompt)];

	expandp(defpat, promptp, NPMT-(promptp-prompt));
	prompt[NPMT-1] = '\0';
	promptp += ucs4_strlen(promptp);

	b = utf8_to_ucs4_cpystr("\" with");
	if(b){
	    ucs4_strncpy(promptp, b, NPMT-(promptp-prompt));
	    promptp += ucs4_strlen(promptp);
	    prompt[NPMT-1] = '\0';
	    fs_give((void **) &b);
	}

	if(rpat[0] != '\0'){
	    if((promptp-prompt) < NPMT-2){
		*promptp++ = ' ';
		*promptp++ = '[';
		*promptp = '\0';
	    }

	    expandp(rpat, promptp, NPMT-(promptp-prompt));
	    prompt[NPMT-1] = '\0';
	    promptp += ucs4_strlen(promptp);

	    if((promptp-prompt) < NPMT-1){
		*promptp++ = ']';
		*promptp = '\0';
	    }
	}

	if((promptp-prompt) < NPMT-3){
	    *promptp++ = ' ';
	    *promptp++ = ':';
	    *promptp++ = ' ';
	    *promptp = '\0';
	}

	prompt[NPMT-1] = '\0';

	status = mlreplyd(prompt, lpat, NPAT, QDEFLT, menu_pat);

	curwp->w_flag |= WFMOVE;

	reverse_all(defpat, bsearch); /* reverse for internal use */

	switch(status){

	  case TRUE :
	  case FALSE :
	    if(lpat[0]){
	      ucs4_strncpy(rpat, lpat, NPAT); /* remember default */
	      rpat[NPAT-1] = '\0';
	    }
	    else{
	      ucs4_strncpy(lpat, rpat, NPAT); /* use default */
	      lpat[NPAT-1] = '\0';
	    }

	    if (repl_all){
		status = replace_all(defpat, lpat, bsearch);
	    }
	    else{
		if(bsearch)
		  curwp->w_doto -= ucs4_strlen(defpat) - 1;
		chword(defpat, lpat, bsearch);	/* replace word    */
		/* after substitution the cursor is past the end of the
		 * replaced string, so we backdown in backward search,
		 * to make it appear at the beginning of the replaced string.
		 * We make this choice in case the next search is backward,
		 * because if we put the cursor at the end, the next backward
		 * search might hit the substituted string, and we want to
		 * avoid that, because we probably do not want to substitute
		 * the new string, but old text.
		 */
		if(bsearch && (lback(curwp->w_dotp) != curbp->b_linep
				|| curwp->w_doto > 0))
		  curwp->w_doto--;
		supdate(defpat, bsearch);
		status = TRUE;
	    }

	    if(status == TRUE)
	      emlwrite("", NULL);

	    return(status);

	  case HELPCH:                      /* help requested */
	    if(Pmaster){
		VARS_TO_SAVE *saved_state;

		saved_state = save_pico_state();
		(*Pmaster->helper)(Pmaster->search_help,
				   _("Help for Searching"), 1);
		if(saved_state){
		    restore_pico_state(saved_state);
		    free_pico_state(saved_state);
		}
	    }
	    else
	      pico_help(SearchHelpText, _("Help for Searching"), 1);

	  case (CTRL|'L'):			/* redraw requested */
	    pico_refresh(FALSE, 1);
	    update();
	    break;

	  case (CTRL|'X'):        /* toggle replace all option */
	    if (repl_all){
		repl_all = FALSE;
		/* TRANSLATORS: abbreviation for Replace All occurrences */
		menu_pat[0].label = N_("Repl All");
	    }
	    else{
		repl_all = TRUE;
		/* TRANSLATORS: Replace just one occurence */
		menu_pat[0].label = N_("Repl One");
	    }

	    break;

	  default:
	    if(status == ABORT){
	      emlwrite(_("Replacement Cancelled"), NULL);
	      reverse_all(defpat, bsearch); /* undo reverse buffer and pattern */
	      pico_refresh(FALSE, 1);
	      reverse_all(defpat, bsearch); /* reverse buffer and pattern */
	    }
	    else{
		mlerase();
		chword(defpat, origpat, bsearch);
	    }

	    supdate(defpat, bsearch);
	    return(FALSE);
	}
    }
}


/* Since the search is not case sensitive, we must obtain the actual pattern 
   that appears in the text, so that we can highlight (and unhighlight) it
   without using the wrong cases  */
void
get_pat_cases(UCS *realpat, UCS *searchpat)
{
  int i, searchpatlen, curoff;

  curoff = curwp->w_doto;
  searchpatlen = ucs4_strlen(searchpat);

  for (i = 0; i < searchpatlen; i++)
    realpat[i] = lgetc(curwp->w_dotp, curoff++).c;

  realpat[searchpatlen] = '\0';
}
    

/* Ask the user about every occurence of orig pattern and replace it with a 
   repl pattern if the response is affirmative. */   
int
replace_all(UCS *orig, UCS *repl, int bsearch)
{
  register         int status = 0;
  UCS             *b;
  UCS              realpat[NPAT];
  char             utf8tmp[NPMT];
  UCS             *promptp;
  UCS              prompt[NPMT];
  int              wrapt, n = 0;
  LINE		  *stop_line   = curwp->w_dotp;
  int		   stop_offset = curwp->w_doto;
  EML              eml;
  int		   flags;

  /* similar to replace_pat. When we come here, if bsearch is set,
   * the cursor is at the end of the match, so we must bring it back
   * to the beginning.
   */
  if(bsearch){
    flags = SR_BACKWRD;
    curwp->w_doto -= ucs4_strlen(orig) - 1;
    curwp->w_flag |= WFMOVE;
  }
  else
    flags = SR_FORWARD;

  stop_offset = curwp->w_doto;
  while (1)
    if (forscan(&wrapt, orig, flags, stop_line, stop_offset, PTBEG)){
        curwp->w_flag |= WFMOVE;            /* put cursor back */

	reverse_all(orig, bsearch); /* undo reverse buffer and pattern */
        update();
	(*term.t_rev)(1);
	get_pat_cases(realpat, orig);
	pputs(realpat, 1);                       /* highlight word */
	(*term.t_rev)(0);
	fflush(stdout);

	snprintf(utf8tmp, NPMT, "Replace \"");
	b = utf8_to_ucs4_cpystr(utf8tmp);
	if(b){
	    ucs4_strncpy(prompt, b, NPMT);
	    prompt[NPMT-1] = '\0';
	    fs_give((void **) &b);
	}

	promptp = &prompt[ucs4_strlen(prompt)];

	expandp(orig, promptp, NPMT-(promptp-prompt));
	reverse_all(orig, bsearch); /* reverse for internal use */
	prompt[NPMT-1] = '\0';
	promptp += ucs4_strlen(promptp);

	b = utf8_to_ucs4_cpystr("\" with \"");
	if(b){
	    ucs4_strncpy(promptp, b, NPMT-(promptp-prompt));
	    promptp += ucs4_strlen(promptp);
	    prompt[NPMT-1] = '\0';
	    fs_give((void **) &b);
	}

	expandp(repl, promptp, NPMT-(promptp-prompt));
	prompt[NPMT-1] = '\0';
	promptp += ucs4_strlen(promptp);

	if((promptp-prompt) < NPMT-1){
	    *promptp++ = '\"';
	    *promptp = '\0';
	}

	prompt[NPMT-1] = '\0';

	status = mlyesno(prompt, TRUE);		/* ask user */

	if(bsearch){
	   curwp->w_doto -= ucs4_strlen(realpat) - 1;
	   curwp->w_flag |= WFMOVE;
	}
	if (status == TRUE){
	    n++;
	    chword(realpat, repl, bsearch);	/* replace word    */
	    supdate(realpat, bsearch);
	}else{
	    chword(realpat, realpat, bsearch);	/* replace word by itself */
	    supdate(realpat, bsearch);
	    if(status == ABORT){		/* if cancelled return */
		eml.s = comatose(n);
		emlwrite("Replace All cancelled after %s changes", &eml);
		return (ABORT);			/* ... else keep looking */
	    }
	}
    }
    else{
	char *utf8;

	utf8 = sucs4_to_utf8_cpystr(orig, bsearch);
	if(utf8){
	  eml.s = utf8;
	  emlwrite(_("No more matches for \"%s\""), &eml);
	  fs_give((void **) &utf8);
	}
	else
	  emlwrite(_("No more matches"), NULL);

	return (FALSE);
    }
}


/* Read a replacement pattern.  Modeled after readpattern(). */
int
srpat(char *utf8prompt, UCS *defpat, size_t defpatlen, int repl_mode, int flags)
{
	register int s;
	int	     i = 0;
	int	     toggle, bsearch, bol, eol, exact;
	UCS         *b;
	UCS	     prompt[NPMT];
	UCS         *promptp;
	EXTRAKEYS    menu_pat[12];

	bsearch = flags & SR_BACKWRD;
	bol	= flags & SR_BEGLINE;
	eol	= flags & SR_ENDLINE;
	exact   = flags & SR_EXACTSR;
	toggle  = 0;	/* reserved for future use */

	memset(&menu_pat, 0, sizeof(menu_pat));
	/* add exceptions here based on the location of the items in the menu */
	for(i = 0; i < 10; i++){
	    if(flags & SR_ORIGMEN){
	      menu_pat[i].name  = menu_srchpat[10*toggle + i].name;
	      menu_pat[i].label = menu_srchpat[10*toggle + i].label;
	      menu_pat[i].key   = menu_srchpat[10*toggle + i].key;
	      if(toggle == 0){
		if (i == REPLACE_KEY)
		   menu_pat[i].label  = repl_mode ? N_("No Replace")
						  : N_("Replace");
	      }
	    } else if(flags & SR_OPTNMEN){
	      menu_pat[i].name  = menu_srchopt[i].name;
	      menu_pat[i].label = menu_srchopt[i].label;
	      menu_pat[i].key   = menu_srchopt[i].key;
	      switch(i){
		case EXACTSR_KEY:
			menu_pat[i].label = exact ? N_("No Exact")
						  : N_("Exact");
			break;
		case REPLACE_KEY:
			menu_pat[i].label  = repl_mode ? N_("No Replace")
						       : N_("Replace");
			break;
		case BSEARCH_KEY: 
			menu_pat[i].label  = bsearch ? N_("Srch Fwd")
						     : N_("Srch Back");
			break;
		case BGNLINE_KEY:
			menu_pat[i].label  = bol ? N_("Anywhere")
						 : N_("Bgn Line"); 
			break;
		case ENDLINE_KEY:
			menu_pat[i].label  = eol ? N_("Anywhere")
						 : N_("End Line"); 
			break;
		default : break;
	      }
	      if(menu_pat[i].name)
	        KS_OSDATASET(&menu_pat[i], KS_NONE);
	   }
	}
	b = utf8_to_ucs4_cpystr(utf8prompt);
	if(b){
	    ucs4_strncpy(prompt, b, NPMT);
	    prompt[NPMT-1] = '\0';
	    if(bsearch){
	      fs_give((void **) &b);
	      b = utf8_to_ucs4_cpystr(N_(" backward"));
	      if(b) ucs4_strncat(prompt, b, ucs4_strlen(b));
	      prompt[NPMT-1] = '\0';
	    }
	    if(bol){
	      fs_give((void **) &b);
	      b = utf8_to_ucs4_cpystr(N_(" at start of line"));
	      if(b) ucs4_strncat(prompt, b, ucs4_strlen(b));
	      prompt[NPMT-1] = '\0';
	    } else if(eol){
	      fs_give((void **) &b);
	      b = utf8_to_ucs4_cpystr(N_(" at end of line"));
	      if(b) ucs4_strncat(prompt, b, ucs4_strlen(b));
	      prompt[NPMT-1] = '\0';
	    }
	    if(exact){
	      fs_give((void **) &b);
	      b = utf8_to_ucs4_cpystr(N_(" exactly for"));
	      if(b) ucs4_strncat(prompt, b, ucs4_strlen(b));
	      prompt[NPMT-1] = '\0';
	    }
	    if(b) fs_give((void **) &b);
	}

	promptp = &prompt[ucs4_strlen(prompt)];

	if(repl_mode){
	    b = utf8_to_ucs4_cpystr(" (to replace)");
	    if(b){
		ucs4_strncpy(promptp, b, NPMT-(promptp-prompt));
		promptp += ucs4_strlen(promptp);
		prompt[NPMT-1] = '\0';
		fs_give((void **) &b);
	    }
	}

        if(pat[0] != '\0'){
	    if((promptp-prompt) < NPMT-2){
		*promptp++ = ' ';
		*promptp++ = '[';
		*promptp = '\0';
	    }

	    expandp(pat, promptp, NPMT-(promptp-prompt));
	    prompt[NPMT-1] = '\0';
	    promptp += ucs4_strlen(promptp);

	    if((promptp-prompt) < NPMT-1){
		*promptp++ = ']';
		*promptp = '\0';
	    }
	}

	if((promptp-prompt) < NPMT-2){
	    *promptp++ = ':';
	    *promptp++ = ' ';
	    *promptp = '\0';
	}

	prompt[NPMT-1] = '\0';

	s = mlreplyd(prompt, defpat, defpatlen, QDEFLT, menu_pat);

	if (s == TRUE || s == FALSE){	/* changed or not, they're done */
	    if(!defpat[0]){		/* use default */
		ucs4_strncpy(defpat, pat, defpatlen);
		defpat[defpatlen-1] = '\0';
	    }
	    else if(ucs4_strcmp(pat, defpat)){   	      /* Specified */
		ucs4_strncpy(pat, defpat, NPAT);
		pat[NPAT-1] = '\0';
		rpat[0] = '\0';
	    }

	    s = TRUE;			/* let caller know to proceed */
	}

	return(s);
}


/*
 * Read a pattern. Stash it in the external variable "pat". The "pat" is not
 * updated if the user types in an empty line. If the user typed an empty line,
 * and there is no old pattern, it is an error. Display the old pattern, in the
 * style of Jeff Lomicka. There is some do-it-yourself control expansion.
 * change to using <ESC> to delemit the end-of-pattern to allow <NL>s in
 * the search string.
 */

int
readnumpat(char *utf8prompt)
{
    int		 i, n;
    char	 numpat[NPMT];
    EXTRAKEYS    menu_pat[12];

    memset(&menu_pat, 0, 10*sizeof(EXTRAKEYS));
    menu_pat[i = 0].name  = "^T";
    menu_pat[i].label	  = N_("No Line Number");
    menu_pat[i].key	  = (CTRL|'T');
    KS_OSDATASET(&menu_pat[i++], KS_NONE);

    menu_pat[i].name  = NULL;

    numpat[0] = '\0';
    while(1)
      switch(mlreplyd_utf8(utf8prompt, numpat, NPMT, QNORML, menu_pat)){
	case TRUE :
	  if(*numpat){
	      for(i = n = 0; numpat[i]; i++)
		if(strchr("0123456789", numpat[i])){
		    n = (n * 10) + (numpat[i] - '0');
		}
		else
		  return(-2);

	      return(n);
	  }

	case FALSE :
	default :
	  return(-1);

	case (CTRL|'T') :
	  return(-3);

	case (CTRL|'L') :
	case HELPCH :
	  break;
      }
}	    


int
readpattern(char *utf8prompt, int text_mode, int flags)
{
	register int s;
	int	     i;
	int	     toggle, bsearch, bol, eol, exact;
	UCS         *b;
	UCS	     tpat[NPAT+20];
	UCS         *tpatp;
	EXTRAKEYS    menu_pat[12];

	bsearch = flags & SR_BACKWRD;
	bol	= flags & SR_BEGLINE;
	eol	= flags & SR_ENDLINE;
	exact   = flags & SR_EXACTSR;
	toggle  = 0;	/* reserved for future use */

	memset(&menu_pat, 0, sizeof(menu_pat));
	/* add exceptions here based on the location of the items in the menu */
	for(i = 0; i < 10; i++){
	    if(flags & SR_ORIGMEN){
	      menu_pat[i].name  = menu_srchpat[10*toggle + i].name;
	      menu_pat[i].label = menu_srchpat[10*toggle + i].label;
	      menu_pat[i].key   = menu_srchpat[10*toggle + i].key;
	      if(toggle == 0){
		if (i == REPLACE_KEY)
		   memset(&menu_pat[i], 0, sizeof(EXTRAKEYS));
		if (i > REPLACE_KEY && !text_mode)
		   memset(&menu_pat[i], 0, sizeof(EXTRAKEYS));
	      }
	    } else if(flags & SR_OPTNMEN){
	      menu_pat[i].name  = menu_srchopt[i].name;
	      menu_pat[i].label = menu_srchopt[i].label;
	      menu_pat[i].key   = menu_srchopt[i].key;
	      switch(i){
		case EXACTSR_KEY:
			menu_pat[i].label  = exact ? N_("No Exact")
						   : N_("Exact");
			break;
		case BSEARCH_KEY: 
			menu_pat[i].label  = bsearch ? N_("Srch Fwd")
						     : N_("Srch Back");
			break;
		case BGNLINE_KEY:
			menu_pat[i].label  = bol ? N_("Anywhere")
						 : N_("Bgn Line"); 
			break;
		case ENDLINE_KEY:
			menu_pat[i].label  = eol ? N_("Anywhere")
						 : N_("End Line"); 
			break;
		default : break;
	     }
	     if(menu_pat[i].name)
	       KS_OSDATASET(&menu_pat[i], KS_NONE);
	   }
	}

	b = utf8_to_ucs4_cpystr(utf8prompt);
	if(b){
	    ucs4_strncpy(tpat, b, NPAT+20);
	    tpat[NPAT+20-1] = '\0';
	    if(bsearch){
	      fs_give((void **) &b);
	      b = utf8_to_ucs4_cpystr(N_(" backward"));
	      if(b) ucs4_strncat(tpat, b, ucs4_strlen(b));
	      tpat[NPAT+20-1] = '\0';
	    }
	    if(bol){
	      fs_give((void **) &b);
	      b = utf8_to_ucs4_cpystr(N_(" at start of line"));
	      if(b) ucs4_strncat(tpat, b, ucs4_strlen(b));
	      tpat[NPAT+20-1] = '\0';
	    } else if (eol){
	      fs_give((void **) &b);
	      b = utf8_to_ucs4_cpystr(N_(" at end of line"));
	      if(b) ucs4_strncat(tpat, b, ucs4_strlen(b));
	      tpat[NPAT+20-1] = '\0';
	    }
	    if (exact){
	      fs_give((void **) &b);
	      b = utf8_to_ucs4_cpystr(N_(" exactly for"));
	      if(b) ucs4_strncat(tpat, b, ucs4_strlen(b));
	      tpat[NPAT+20-1] = '\0';
	    } 
	    if(b) fs_give((void **) &b);
	}

	tpatp = &tpat[ucs4_strlen(tpat)];

        if(pat[0] != '\0'){
	    if((tpatp-tpat) < NPAT+20-2){
		*tpatp++ = ' ';
		*tpatp++ = '[';
		*tpatp = '\0';
	    }

	    expandp(pat, tpatp, NPAT+20-(tpatp-tpat));
	    tpat[NPAT+20-1] = '\0';
	    tpatp += ucs4_strlen(tpatp);

	    if((tpatp-tpat) < NPAT+20-1){
		*tpatp++ = ']';
		*tpatp = '\0';
	    }
	}

	if((tpatp-tpat) < NPAT+20-3){
	    *tpatp++ = ' ';
	    *tpatp++ = ':';
	    *tpatp++ = ' ';
	    *tpatp = '\0';
	}

	tpat[NPAT+20-1] = '\0';

	s = mlreplyd(tpat, tpat, NPAT, QNORML, menu_pat);

	if ((s == TRUE) && ucs4_strcmp(pat,tpat)){			/* Specified */
	  ucs4_strncpy(pat, tpat, NPAT);
	  pat[NPAT-1] = '\0';
	  rpat[0] = '\0';
	}
	else if (s == FALSE && pat[0] != '\0')	/* CR, but old one */
		s = TRUE;

	return(s);
}

/* given a line, reverse its content */
void
reverse_line(LINE *l)
{
  int i, j, a;
  UCS u;

  if(l == NULL) return;
  j = llength(l) - 1;
  for(i = 0; i < j; i++, j--){
     u             = lgetc(l, j).c;	/* reverse the text */
     lgetc(l, j).c = lgetc(l, i).c;
     lgetc(l, i).c = u;
     a             = lgetc(l, j).a;	/* and the attribute */
     lgetc(l, j).a = lgetc(l, i).a;
     lgetc(l, i).a = a;
  }
}

void
reverse_all(UCS *pat, int bsearch)
{
  if(bsearch != 0){
     reverse_buffer();
     reverse_ucs4(pat);
  }
}

void
reverse_buffer(void)
{
  LINE *l;

 for(l = lforw(curbp->b_linep); l != curbp->b_linep; l = lforw(l))
    reverse_line(l);

  /* reverse links in buffer */
  l = curbp->b_linep;
  do {
    lforw(l) = lback(l);
    l = lforw(l);
  } while(l != curbp->b_linep);

  l = curbp->b_linep;
  do {
     lback(lforw(l)) = l;
     l = lforw(l);
  } while (l != curbp->b_linep);

  curwp->w_doto = llength(curwp->w_dotp) - 1 - curwp->w_doto;
}



/* given a UCS4 string reverse its content */
void
reverse_ucs4(UCS *s)
{
  int i, j;
  UCS u;

  j = ucs4_strlen(s) - 1;
  for(i = 0; i < j; i++, j--){
     u    = s[j];
     s[j] = s[i];
     s[i] = u;
  }
}


/* search forward for a <patrn>.
 * A backward search is a forward search in backward lines with backward
 * patterns
 */
int
forscan(int *wrapt,	/* boolean indicating search wrapped */
	UCS *patrn,	/* string to scan for */
	int flags,      /* direction and position */
	LINE *limitp,	/* stop searching if reached */
	int limito,	/* stop searching if reached */
	int leavep)	/* place to leave point
				PTBEG = beginning of match
				PTEND = at end of match		*/

{
    LINE *curline;	/* current line during scan */
    int curoff;		/* position within current line */
    LINE *lastline;	/* last line position during scan */
    int lastoff;	/* position within last line */
    UCS c;		/* character at current position */
    LINE *matchline;	/* current line during matching */
    int matchoff;	/* position in matching line */
    UCS *patptr;	/* pointer into pattern */
    int stopoff;	/* offset to stop search */
    LINE *stopline;	/* line to stop search */
    int ftest;		/* position of first character of test */
    int bsearch;
    int bol;
    int eol;

    bsearch = flags & SR_BACKWRD;
    bol	= flags & SR_BEGLINE;
    eol	= flags & SR_ENDLINE;
    *wrapt = FALSE;

    /* if bsearch is set we return the match at the beginning of the
     * matching string, so we make this algorithm return the end of
     * the string, so that when we reverse we be at the beginning.
     */
    if(bsearch)
	leavep = leavep == PTBEG ? PTEND : PTBEG;

    /*
     * the idea is to set the character to end the search at the 
     * next character in the buffer.  thus, let the search wrap
     * completely around the buffer.
     * 
     * first, test to see if we are at the end of the line, 
     * otherwise start searching on the next character. 
     */
     if(curwp->w_doto == llength(curwp->w_dotp)){
	/*
	 * dot is not on end of a line
	 * start at 0 offset of the next line
	 */
	stopoff = curoff  = 0;
	stopline = curline = lforw(curwp->w_dotp);
	if (curwp->w_dotp == curbp->b_linep)
	  *wrapt = TRUE;
     }
     else{
	stopoff = curoff  = curwp->w_doto;
	stopline = curline = curwp->w_dotp;
     }

    /* scan each character until we hit the head link record */

    /*
     * maybe wrapping is a good idea
     */
    while (curline){

	if(curline == curbp->b_linep)
	  *wrapt = TRUE;

	/* save the current position in case we need to
	   restore it on a match			*/

	lastline = curline;
	lastoff = curoff;

	/* get the current character resolving EOLs */
	if (curoff == llength(curline)) {	/* if at EOL */
	    curline = lforw(curline); /* skip to next line */
	    curoff  = 0;
	    c = '\n';			/* and return a <NL> */
	}
	else if(curoff == -1){
	  stopoff = curoff = 0;
	  continue;
	  c = '\n';
	}
	else
	    c = lgetc(curline, curoff++).c;	/* get the char */

	if(bol)
	   ftest = bsearch == 0 ? 1 : llength(curline) - ucs4_strlen(patrn) + 1;
	else if (eol)
	   ftest = bsearch == 0 ? llength(curline) - ucs4_strlen(patrn) + 1 : 1;
	/* test it against first char in pattern */
	if (eq(c, patrn[0]) != FALSE 		/* if we find it..*/
	       && ((bol == 0 && eol == 0)	/* ...and if it is anywhere */
	            || (bol != 0		/* ...or is at the begin or line */
		   	&& ((bsearch == 0 && curoff == ftest)	/* and search forward and found at beginning of line */
			    || (bsearch != 0 && curoff == ftest))) /* or search backward and found at end of line */
	            || (eol != 0		/* ...or is at the end or line */
		   	&& ((bsearch == 0 && curoff == ftest)	/* and search forward and found at beginning of line */
			    || (bsearch != 0 && curoff == ftest))) /* or search backward and found at end of line */
		  )){
	    /* setup match pointers */
	    matchline = curline;
	    matchoff = curoff;
	    patptr = &patrn[0];

	    /* scan through patrn for a match */
	    while (*++patptr != '\0') {
		/* advance all the pointers */
		if (matchoff >= llength(matchline)) {
		    /* advance past EOL */
		    matchline = lforw(matchline);
		    matchoff  = 0;
		    c = '\n';
		} else
		  c = lgetc(matchline, matchoff++).c;

		if(matchline == limitp && matchoff == limito)
		  return(FALSE);

		/* and test it against the pattern */
		if (eq(*patptr, c) == FALSE)
		  goto fail;
	    }

	    /* A SUCCESSFUL MATCH!!! */
	    /* reset the global "." pointers */
	    if (leavep == PTEND) {	/* at end of string */
		curwp->w_dotp = matchline;
		curwp->w_doto = matchoff - 1;
	    }
	    else {		/* at beginning of string */
		curwp->w_dotp = lastline;
		curwp->w_doto = lastoff;
	    }

	    curwp->w_flag |= WFMOVE; /* flag that we have moved */
	    return(TRUE);
	}

fail:;			/* continue to search */
	if(((curline == stopline) && (curoff == stopoff))
	   || (curline == limitp && curoff == limito))
	  break;			/* searched everywhere... */
    }
    /* we could not find a match */

    return(FALSE);
}



/* 	expandp:	expand control key sequences for output		*/
int
expandp(UCS *srcstr,		/* string to expand */
	UCS *deststr,		/* destination of expanded string */
	int maxlength)		/* maximum chars in destination */
{
	UCS c;		/* current char to translate */

	/* scan through the string */
	while ((c = *srcstr++) != 0) {
		if (c == '\n') {		/* its an EOL */
			*deststr++ = '<';
			*deststr++ = 'N';
			*deststr++ = 'L';
			*deststr++ = '>';
			maxlength -= 4;
		} else if (c < 0x20 || c == 0x7f) {	/* control character */
			*deststr++ = '^';
			*deststr++ = c ^ 0x40;
			maxlength -= 2;
		} else if (c == '%') {
			*deststr++ = '%';
			*deststr++ = '%';
			maxlength -= 2;
		} else {			/* any other character */
			*deststr++ = c;
			maxlength--;
		}

		/* check for maxlength */
		if (maxlength < 4) {
			*deststr++ = '$';
			*deststr = '\0';
			return(FALSE);
		}
	}

	*deststr = '\0';
	return(TRUE);
}


/* 
 * chword() - change the given word, wp, pointed to by the curwp->w_dot 
 *            pointers to the word in cb
 * if bsearch is set, then cb is supposed to come unreversed, while
 * the buffer is supposed to be reversed, so we must reverse cb before
 * inserting it.
 */
void
chword(UCS *wb, UCS *cb, int bsearch)
{
    UCS *u;
    ldelete(ucs4_strlen(wb), NULL);	/* not saved in kill buffer */
    if(bsearch) reverse_ucs4(cb);
    for(u = cb; *u != '\0'; u++)
      linsert(1, *u);
    if(bsearch) reverse_ucs4(cb);

    curwp->w_flag |= WFEDIT;
}

void
 supdate(UCS *pat, int bsearch)
{
  reverse_all(pat, bsearch); /* undo reverse buffer and pattern */
  update();
  reverse_all(pat, bsearch); /* reverse buffer and pattern */
}

char *
sucs4_to_utf8_cpystr(UCS *orig, int bsearch)
{
  char *utf8;
  if(bsearch) reverse_ucs4(orig);
  utf8 = ucs4_to_utf8_cpystr(orig);
  if(bsearch) reverse_ucs4(orig);
  return utf8;
}
