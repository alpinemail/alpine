#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: color.c 761 2007-10-23 22:35:18Z hubert@u.washington.edu $";
#endif

/*
 * ========================================================================
 * Copyright 2006 University of Washington
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
    *
    *  These routines themselves aren't necessarily OS-specific, they
    *  are all called from within pico, pine and webpine.
    * 
    *  They used to be in pico source (osdep/unix, mswin.c), but considering
    *  webpine uses color as well and it should *not* have to be linked
    *  against libpico and considering pico uses these routines but should
    *  not have to link against libpith (and in turn c-client) we put them
    *  in pith/osdep which should only have to link against system libraries
    *  and thus be include freely in all of pine, pico and webpine.
    */  


#include <system.h>
#include "./color.h"
#include "./collate.h"


/*
 * new_color_pair - allocate a new color pair structure assigning 
 *                  given foreground and background color strings
 */
COLOR_PAIR *
new_color_pair(char *fg, char *bg)
{
    COLOR_PAIR *ret;

    if((ret = (COLOR_PAIR *) malloc(sizeof(*ret))) != NULL){
	memset(ret, 0, sizeof(*ret));
	if(fg){
	    strncpy(ret->fg, fg, MAXCOLORLEN);
	    ret->fg[MAXCOLORLEN] = '\0';
	}

	if(bg){
	    strncpy(ret->bg, bg, MAXCOLORLEN);
	    ret->bg[MAXCOLORLEN] = '\0';
	}
    }

    return(ret);
}


/*
 * free_color_pair - release resources associated with given
 *                   color pair structure
 */
void
free_color_pair(COLOR_PAIR **cp)
{
    if(cp && *cp){
	free(*cp);
	*cp = NULL;
    }
}


/*
 * Just like pico_set_color except it doesn't set the color, it just
 * returns the value. Assumes def of PSC_NONE, since otherwise we always
 * succeed and don't need to call this.
 */
int
pico_is_good_colorpair(COLOR_PAIR *cp)
{
    return(cp && pico_is_good_color(cp->fg) && pico_is_good_color(cp->bg));
}


COLOR_PAIR *
pico_set_colorp(COLOR_PAIR *col, int flags)
{
    return(pico_set_colors(col ? col->fg : NULL, col ? col->bg : NULL, flags));
}


  /* 
   * Extended Justification support also does not belong here
   * but otherwise webpine will not build, so we move everything
   * here. Hopefully this will be the permanent place for these
   * routines. These routines used to be in pico/word.c
   */
#define NSTRING 256
#include "../../include/general.h"

/* Support of indentation of paragraphs */
#define is_indent_char(c)  (((c) == '.' || (c) == '}' || (c) == RPAREN || \
			     (c) == '*' || (c) == '+' || is_a_digit(c) || \
			     ISspace(c) || (c) == '-' || \
			     (c) == ']') ? 1 : 0)
#define allowed_after_digit(c,word,k)  ((((c) == '.' && \
			     allowed_after_period(next((word),(k))))  ||\
				(c) == RPAREN || (c) == '}' || (c) == ']' ||\
				  ISspace(c) ||  is_a_digit(c) || \
				  ((c) == '-' ) && \
				    allowed_after_dash(next((word),(k)))) \
				? 1 : 0)
#define allowed_after_period(c)	 (((c) == RPAREN || (c) == '}' || (c) == ']' ||\
				   ISspace(c) || (c) == '-' || \
				   is_a_digit(c)) ? 1 : 0)
#define allowed_after_parenth(c)  (ISspace(c) ? 1 : 0)
#define allowed_after_space(c)	  (ISspace(c) ? 1 : 0)
#define allowed_after_braces(c)	  (ISspace(c) ? 1 : 0)
#define allowed_after_star(c)	 ((ISspace(c) || (c) == RPAREN ||\
                                       (c) == ']' || (c) == '}') ? 1 : 0)
#define allowed_after_dash(c)	  ((ISspace(c) || is_a_digit(c)) ? 1 : 0)
#define EOLchar(c)		  (((c) == '.' || (c) == ':' || (c) == '?' ||\
					(c) == '!') ? 1 : 0)


/* Extended justification support */
#define is_cquote(c) ((c) == '>' || (c) == '|' || (c) == ']' || (c) == ':')
#define is_cword(c)  ((((c) >= 'a') && ((c) <= 'z')) ||  \
                     (((c) >= 'A') && ((c) <= 'Z')) || \
                     (((c) >= '0') && ((c) <= '9')) || \
                      ((c) == ' ') || ((c) == '?') || \
                      ((c) == '@') || ((c) == '.') || \
                      ((c) == '!') || ((c) == '\'') || \
                      ((c) == ',') || ((c) == '\"') ? 1 : 0)
#define isaquote(c)   ((c) == '\"' || (c) == '\'')
#define is8bit(c)     ((((int) (c)) & 0x80) ? 1 : 0)
#define iscontrol(c)  (iscntrl(((int) (c)) & 0x7f) ? 1 : 0)
#define forbidden(c)  (((c) == '\"') || ((c) == '\'') || ((c) == '$') ||\
                       ((c) == ',')  || ((c) == '.')  || ((c) == '-') ||\
                       ((c) == LPAREN) || ((c) == '/')|| ((c) == '`') ||\
                       ((c) == '{') || ((c) == '\\') || (iscontrol((c))) ||\
                       (((c) >= '0')  && ((c) <= '9')) || ((c) == '?'))
#define is_cletter(c)  ((((c) >= 'a') && ((c) <= 'z'))) ||\
                       ((((c) >= 'A') && ((c) <= 'Z'))||\
                      is8bit(c))
#define is_cnumber(c) ((c) >= '0' && (c) <= '9')
#define allwd_after_word(c) (((c) == ' ') || ((c) == '>') || is_cletter(c))
#define allwd_after_qsword(c)  (((c) != '\\') && ((c) != RPAREN))
#define before(word,i) (((i) > 0) ? (word)[(i) - 1] : 0)
#define next(w,i) ((((w)[(i)]) != 0) ? ((w)[(i) + 1]) : 0)
#define now(w,i)  ((w)[(i)])
#define is_qsword(c)  (((c) == ':') || ((c) == RPAREN) ? 1 : 0)
#define is_colon(c)   (((c) == ':') ? 1 : 0)
#define is_rarrow(c)  (((c) == '>') ? 1 : 0)
#define is_tilde(c)   (((c) == '~') ? 1 : 0)
#define is_dash(c)    (((c) == '-') ? 1 : 0)
#define is_pound(c)   (((c) == '#') ? 1 : 0)
#define is_a_digit(c) ((((c) >= '0') && ((c) <= '9')) ? 1 : 0)
#define is_allowed(c)  (is_cquote(c) || is_cword(c) || is_dash(c) || \
                       is_pound(c))
#define qs_allowed(a)  (((a)->qstype != qsGdb) && ((a)->qstype != qsProg))

/* Internal justification functions */
QSTRING_S *is_quote(char **, char *, int);
QSTRING_S *qs_normal_part(QSTRING_S *);
QSTRING_S *qs_remove_trailing_spaces(QSTRING_S *);
QSTRING_S *trim_qs_from_cl(QSTRING_S *, QSTRING_S *, QSTRING_S *);
QSTRING_S *fix_qstring(QSTRING_S *, QSTRING_S *, QSTRING_S *);
QSTRING_S *fix_qstring_allowed(QSTRING_S *, QSTRING_S *, QSTRING_S *);
QSTRING_S *qs_add(char **, char *, QStrType, int, int, int, int);
QSTRING_S *remove_qsword(QSTRING_S *);
QSTRING_S *do_raw_quote_match(char **, char *, char *, char *, QSTRING_S **, QSTRING_S **);
void	 free_qs(QSTRING_S **);
int      word_is_prog(char *);
int      qstring_is_normal(QSTRING_S *);
int      exists_good_part(QSTRING_S *);
int      strcmp_qs(char *, char *);
int      count_levels_qstring(QSTRING_S *);
int      same_qstring(QSTRING_S *, QSTRING_S *);
int	 isaword(char *,int ,int);
int	 isamailbox(char *,int ,int);
int	 double_check_qstr(char *);

int
word_is_prog(char *word)
{
  static char *list1[] = {"#include",
			"#define",
			"#ifdef",
			"#ifndef",
			"#elif",
			"#if",
			NULL};
  static char *list2[] = {"#else",
			"#endif",
			 NULL};
  int i, j = strlen(word), k, rv = 0;

  for(i = 0; rv == 0 && list1[i] && (k = strlen(list1[i])) && k < j; i++)
     if(!strncmp(list1[i], word, k) && ISspace(word[k]))
       rv++;

     if(rv)
       return rv;

   for(i = 0; rv == 0 && list2[i] && (k = strlen(list2[i])) && k <= j; i++)
     if(!strncmp(list2[i], word, k) && (!word[k] || ISspace(word[k])))
       rv++;

   return rv;
}

/*
 * This function creates a qstring pointer with the information that
 * is_quote handles to it.
 * Parameters:
 * qs         - User supplied quote string
 * word       - The line of text that the user is trying to read/justify
 * beginw     - Where we need to start copying from
 * endw       - Where we end copying
 * offset     - Any offset in endw that we need to account for
 * typeqs     - type of the string to be created
 * neednext   - boolean, indicating if we need to compute the next field
 *              of leave it NULL 
 * 
 * It is a mistake to call this function if beginw >= endw + offset.
 * Please note the equality sign in the above inequality (this is because
 * we always assume that qstring->value != "").
 */ 
QSTRING_S *
qs_add(char **qs, char word[NSTRING], QStrType typeqs, int beginw, int endw, 
	int offset, int neednext)
{
    QSTRING_S *qstring, *nextqs;
    int i;
 
    qstring = (QSTRING_S *) malloc (sizeof(QSTRING_S));
    memset (qstring, 0, sizeof(QSTRING_S));
    qstring->qstype = qsNormal;

    if (beginw == 0){
	beginw = endw + offset;
	qstring->qstype = typeqs;
    }

    nextqs = neednext ? is_quote(qs, word+beginw, 1) : NULL;

    qstring->value = (char *) malloc((beginw+1)*sizeof(char));
    strncpy(qstring->value, word, beginw);
    qstring->value[beginw] = '\0';

    qstring->next = nextqs;

    return qstring;
}

int
qstring_is_normal(QSTRING_S *cl)
{ 
   for (;cl && (cl->qstype == qsNormal); cl = cl->next);
   return cl ? 0 : 1;
}

/*
 * Given a quote string, this function returns the part that is the leading
 * normal part of it. (the normal part is the part that is tagged qsNormal,
 * that is to say, the one that is not controversial at all (like qsString
 * for example).
 */
QSTRING_S *
qs_normal_part(QSTRING_S *cl)
{

  if (!cl)            /* nothing in, nothing out */
     return cl;

  if (cl->qstype != qsNormal)
     free_qs(&cl);

  if (cl)
     cl->next = qs_normal_part(cl->next);

  return cl;
}

/*
 * this function removes trailing spaces from a quote string, but leaves the
 * last one if there are trailing spaces
 */ 
QSTRING_S *
qs_remove_trailing_spaces(QSTRING_S *cl)
{
  QSTRING_S *rl = cl;
  if (!cl)            /* nothing in, nothing out */
     return cl;

  if (cl->next)
     cl->next = qs_remove_trailing_spaces(cl->next);
  else{
    if (value_is_space(cl->value))
       free_qs(&cl);
    else{
       int i, l;
       i = l = strlen(cl->value) - 1;
       while (cl->value && cl->value[i]
        && ISspace(cl->value[i]))
           i--;
        i += (i < l) ? 2 : 1;
        cl->value[i] = '\0';
    }
  }
  return cl;
}

/*
 * This function returns if two strings are the same quote string.
 * The call is not symmetric. cl must preceed the line nl. This function
 * should be called for comparing the last part of cl and nl.
 */
int
strcmp_qs(char *valuecl, char *valuenl)
{
   int j;

   for (j = 0; valuecl[j] && (valuecl[j] == valuenl[j]); j++);
   return !strcmp(valuecl, valuenl)
	 || (valuenl[j] && value_is_space(valuenl+j)
			&& value_is_space(valuecl+j)
			&& strlenis(valuecl+j) >= strlenis(valuenl+j))
	 || (!valuenl[j] && value_is_space(valuecl+j));
}

int
count_levels_qstring(QSTRING_S *cl)
{
  int count;
  for (count = 0; cl ; count++, cl = cl->next);

  return count;
}

int
value_is_space(char *value)
{
  for (; value && *value && ISspace(*value); value++);

  return value && *value ? 0 : 1;
}

void
free_qs(QSTRING_S **cl)
{
  if (!(*cl))
    return;

  if ((*cl)->next)
    free_qs(&((*cl)->next));

  (*cl)->next = (QSTRING_S *) NULL;

  if ((*cl)->value)
     free((void *)(*cl)->value);
   (*cl)->value = (char *) NULL;
   free((void *)(*cl));
   *cl = (QSTRING_S *) NULL;
}

/*
 * This function returns the number of agreements between
 * cl and nl. The call is not symmetric. cl must be the line
 * preceding nl.
 */
int
same_qstring(QSTRING_S *cl, QSTRING_S *nl)
{
   int same = 0, done = 0;

   for (;cl && nl && !done; cl = cl->next, nl = nl->next)
       if (cl->qstype == nl->qstype
         && (!strcmp(cl->value, nl->value)
           || (!cl->next && strcmp_qs(cl->value, nl->value))))
	same++;
      else
	done++;
   return same;
}

QSTRING_S *
trim_qs_from_cl(QSTRING_S *cl, QSTRING_S *nl, QSTRING_S *pl)
{
    QSTRING_S *cqstring = pl ? pl : nl;
    QSTRING_S *tl = pl ? pl : nl;
    int p, c;

    if (qstring_is_normal(tl))
	return tl;

    p = same_qstring(pl ? pl : cl, pl ? cl : nl);

    for (c = 1; c < p; c++, cl = cl->next, tl = tl->next);

    /*
     * cl->next and tl->next differ, it may be because cl->next does not
     * exist or tl->next does not exist or simply both exist but are
     * different. In this last case, it may be that cl->next->value is made
     * of spaces. If this is the case, tl advances once more.
     */

    if (tl->next){
	if (cl && cl->next && value_is_space(cl->next->value))
	   tl = tl->next;
	if (tl->next)
	   free_qs(&(tl->next));
    }

    if (!p)
       free_qs(&cqstring);

    return cqstring;
}

/* This function trims cl so that it returns a real quote string based
 * on information gathered from the previous and next lines. pl and cl are
 * also trimmed, but that is done in another function, not here.
 */
QSTRING_S *
fix_qstring(QSTRING_S *cl, QSTRING_S *nl, QSTRING_S *pl)
{
   QSTRING_S *cqstring = cl, *nqstring = nl, *pqstring = pl;
   int c, n;

   if (qstring_is_normal(cl))
     return cl;

   c = count_levels_qstring(cl);
   n = same_qstring(cl,nl);

   if (!n){  /* no next line or no agreement with next line */
      int p = same_qstring(pl, cl); /* number of agreements between pl and cl */
      QSTRING_S *tl;              /* test line */

      /*
       * Here p <= c, so either p < c or p == c. If p == c, we are done,
       * and return cl. If not, there are two cases, either p == 0 or
       * 0 < p < c. In the first case, we do not have enough evidence
       * to return anything other than the normal part of cl, in the second
       * case we can only return p levels of cl.
       */

   if (p == c)
	tl = cqstring;
   else{
      if (p){
	   for (c = 1; c < p; c++)
	      cl = cl->next;
	   free_qs(&(cl->next));
	   tl = cqstring;
      }
      else{
	   int done = 0;
	   QSTRING_S *al = cl;  /* another line */ 
	/*
	 * Ok, we really don't have enough evidence to return anything,
	 * different from the normal part of cl, but it could be possible
	 * that we may want to accept the not-normal part, so we better
	 * make an extra test to determine what needs to be freed
	 */
	  while (pl && cl && cl->qstype == pl->qstype
		    && !strucmp(cl->value, pl->value)){
		cl = cl->next;
		pl = pl->next;
	  }
          if (pl && cl && cl->qstype == pl->qstype
                       && strcmp_qs(pl->value, cl->value))
               cl = cl->next;  /* next level differs only in spaces */
          while (!done){
               while (cl && cl->qstype == qsNormal)
                   cl = cl->next;
               if (cl){
                  if ((cl->qstype == qsString)
                      && (cl->value[strlen(cl->value) - 1] == '>'))
                     cl = cl->next;
                  else done++;
               }
               else done++;
          }
          if (al == cl){
             free_qs(&(cl));
             tl = cl;
          }
          else {
             while (al && (al->next != cl))
                al = al->next;
             cl = al;
             if (cl && cl->next)
                free_qs(&(cl->next));
             tl = cqstring;
          }
       }
      }
      return tl;
   }
   if (n + 1 < c){  /* if there are not enough agreements */
      int p = same_qstring(pl, cl); /* number of agreement between pl and cl */
      QSTRING_S *tl; /* test line */
       /*
        * There's no way we can use cl in this case, but we can use
        * part of cl, this is if pl does not have more agreements
        * with cl.
        */ 
      if (p == c)
       tl = cqstring;
      else{
       int m = p < n ? n : p;
       for (c = 1; c < m; c++){
         pl = pl ? pl->next : (QSTRING_S *) NULL;
         nl = nl ? nl->next : (QSTRING_S *) NULL;
         cl = cl->next;
       }
       if (p == n && pl && pl->next && nl && nl->next
          && ((cl->next->qstype == pl->next->qstype)
             || (cl->next->qstype == nl->next->qstype))
          && (strcmp_qs(cl->next->value, pl->next->value)
             || strcmp_qs(pl->next->value, cl->next->value)
             || strcmp_qs(cl->next->value, nl->next->value)
             || strcmp_qs(nl->next->value, cl->next->value)))
         cl = cl->next;        /* next level differs only in spaces */
       if (cl->next)
          free_qs(&(cl->next));
       tl = cqstring;
      }
      return tl;
   }
   if (n + 1 == c){
      int p = same_qstring(pl, cl);
      QSTRING_S *tl; /* test line */

      /*
       * p <= c, so p <= n+1, which means p < n + 1 or p == n + 1.
       * If p < n + 1, then p <= n.
       * so we have three possibilities:
       *       p == n + 1 or p == n or p < n.
       * In the first case we copy p == n + 1 == c levels, in the second
       * and third case we copy n levels, and check if we can copy the
       * n + 1 == c level.
       */
      if (p == n + 1)      /* p == c, in the above sense of c */
       tl = cl;          /* use cl, this is enough evidence */
      else{
       for (c = 1; c < n; c++)
         cl = cl->next;
       /*
        * Here c == n, we only have one more level of cl, and at least one
        * more level of nl
        */
       if (cl->next->qstype == qsNormal)
          cl = cl->next;
       if (cl->next)
          free_qs(&(cl->next));
       tl = cqstring;
      }
      return tl;
   }
   if (n == c)  /* Yeah!!! */
     return cqstring;
}

QSTRING_S *
fix_qstring_allowed(QSTRING_S *cl, QSTRING_S *nl, QSTRING_S *pl)
{
  if(!cl)
    return (QSTRING_S *) NULL;

  if (qs_allowed(cl))
      cl->next = fix_qstring_allowed(cl->next, (nl ? nl->next : NULL),
                       (pl ? pl->next : NULL));
  else
     if((nl && cl->qstype == nl->qstype) || (pl && cl->qstype == pl->qstype)
      || (!nl && !pl))
      free_qs(&cl);
  return cl;
}

/*
 * This function flattens the quote string returned to us by is_quote. A
 * crash in this function implies a bug elsewhere.
 */
void
flatten_qstring(QSTRING_S *qs, char *buff, int bufflen)
{ 
   int i, j; 
   if(!buff || bufflen <= 0)
     return;

   for (i = 0; qs; qs = qs->next)
     for (j = 0; i < bufflen - 1
               &&  (qs->value[j]) && (buff[i++] = qs->value[j]); j++);
  buff[i] = '\0';
}

extern int list_len;


int
double_check_qstr(char *q)
{
  if(!q || !*q)
    return 0;

  return (*q == '#') ? 1 : 0;
}

/*
 * Given a string, we return the position where the function thinks that
 * the quote string is over, if you are ever thinking of fixing something,
 * you got to the right place. Memory freed by caller. Experience shows
 * that it only makes sense to initialize memory when we need it, not at
 * the start of this function.
 */
QSTRING_S *
is_quote (char **qs,char *word, int been_here)
{
   int i = 0, j, nxt, prev, finished = 0, offset;
   unsigned char c;
   QSTRING_S *qstring = (QSTRING_S *) NULL;

   if (word == NULL || word[0] == '\0')
      return (QSTRING_S *) NULL;

   while (!finished){
       /*
        * Before we apply our rules, let's advance past the quote string
        * given by the user, this will avoid not recognition of the
        * user's indent string and application of the arbitrary rules
        * below. Notice that this step may bring bugs into this
        * procedure, but these bugs will only appear if the indent string
        * is really really strange and the text to be justified
        * cooperates a lot too, so in general this will not be a problem.
        * If you are concerned about this bug, simply remove the
        * following lines after this comment and before the "switch"
        * command below and use a more normal quote string!.
        */
       for(j = 0; j < list_len; j++){
	  if(!double_check_qstr(qs[j])){
	    i += advance_quote_string(qs[j], word, i);
	    if (!word[i]) /* went too far? */
	      return qs_add(qs, word, qsNormal, 0, i, 0, 0);
	  }
	  else
	    break;
       }

      switch (c = (unsigned char) now(word,i)){
       case NBSP:
       case TAB :
       case ' ' : { QSTRING_S *nextqs, *d;

                   for (; ISspace(word[i]); i++); /* FIX ME */
                   nextqs = is_quote(qs,word+i, 1);
                 /*
                  * Merge qstring and nextqs, since this is an artificial
                  * separation, unless nextqs is of different type.
                  * What this means in practice is that if
                  * qs->qstype == qsNormal and qs->next != NULL, then
                  * qs->next->qstype != qsNormal.
                  *
                  * Can't use qs_add to merge because it could lead
                  * to an infinite loop (e.g a line "^ ^").
                  */
                   i += nextqs && nextqs->qstype == qsNormal
                       ? strlen(nextqs->value) : 0;
                   qstring = (QSTRING_S *) malloc (sizeof(QSTRING_S));
                   memset (qstring, 0, sizeof(QSTRING_S));
                   qstring->value = (char *) malloc((i+1)*sizeof(char));
                   strncpy(qstring->value, word, i);
                   qstring->value[i] = '\0';
                   qstring->qstype   = qsNormal;
		   if(nextqs && nextqs->qstype == qsNormal){
			d = nextqs->next;
			nextqs->next = NULL;
			qstring->next = d;
			free_qs(&nextqs);
		   }
		   else
		     qstring->next     = nextqs;

		   return qstring;
		 }
                break;
       case RPAREN:            /* parenthesis ')' */
                    if ((i != 0) || ((i == 0) && been_here))
                       i++;
                    else
                       if (i == 0)
                          return qs_add(qs, word, qsChar, i, i, 1, 1);
                       else
                          finished++;
                   break;

       case ':':                       /* colon */
       case '~': nxt = next(word,i);
                 if ((is_tilde(c) && (nxt == '/'))
                       || (is_colon(c) && !is_cquote(nxt)
                                       && !is_cword(nxt) && nxt != RPAREN))
                    finished++;
                 else if (is_cquote(c)
                       || is_cquote(nxt)
                       || (c != '~' && nxt == RPAREN)
                       || (i != 0 && ISspace(nxt))
                       || is_cquote(prev = before(word,i))
                       || (ISspace(prev) && !is_tilde(c))
                       || (is_tilde(c) && nxt != '/'))
                     i++;
                 else if (i == 0 && been_here)
                      return qs_add(qs, word, qsChar, i, i, 1, 1);
                 else
                      finished++;
                break;

       case '<' :
       case '=' :
       case '-' : offset = is_cquote(nxt = next(word,i)) ? 2
                            : (nxt == c && is_cquote(next(word,i+1))) ? 3 : -1;

                  if (offset > 0)
                      return qs_add(qs, word, qsString, i, i, offset, 1);
                  else
                      finished++;
                break;

       case '[' :
       case '+' :      /* accept +>, *> */
       case '*' :  if (is_rarrow(nxt = next(word, i)) || /* stars */
                     (ISspace(nxt) && is_rarrow(next(word,i+1))))
                        i++;
                   else
                      finished++;
                break;

       case '^' :
       case '!' :
       case '%' : if (next(word,i) != c)
                     return qs_add(qs, word, qsChar, i, i+1, 0, 1);
                  else
                     finished++;
                break;

       case '_' : if(ISspace(next(word, i)))
                       return qs_add(qs, word, qsChar, i, i+1, 0, 1);
                  else
                     finished++;
                  break;

       case '#' : { QStrType qstype = qsChar;
                    if((nxt = next(word, i)) != c){
                       if(isdigit((int) nxt))
                         qstype = qsGdb;
                       else
                         if(word_is_prog(word))
                            qstype = qsProg;
                       return qs_add(qs, word, qstype, i, i+1, 0, 1);
                    }
                    else
                       finished++;
                    break;
                  }

         default:
           if (is_cquote(c))
              i++;
           else if (is_cletter(c)){
               for (j = i; (is_cletter(nxt = next(word,j)) || is_cnumber(nxt))
                           && !(ISspace(nxt));j++);
                 /*
                  * The whole reason why we are splitting the quote
                  * string is so that we will be able to accept quote
                  * strings that are strange in some way. Here we got to
                  * a point in which a quote string might exist, but it
                  * could be strange, so we need to create a "next" field
                  * for the quote string to warn us that something
                  * strange is coming. We need to confirm if this is a
                  * good choice later. For now we will let it pass.
                  */
                 if (isaword(word,i,j) || isamailbox(word,i,j)){
                   int offset;
                   QStrType qstype;

                   offset = (is_cquote(c = next(word,j))
                            || (c == RPAREN)) ? 2
                               : ((ISspace(c)
                                    && is_cquote(next(word,j+1))) ? 3 : -1);

                   qstype = (is_cquote(c) || (c == RPAREN))
                     ? (is_qsword(c) ? qsWord : qsString)
                     : ((ISspace(c) && is_cquote(next(word,j+1)))
                        ? (is_qsword(next(word,j+1))
                           ? qsWord : qsString)
                                 : qsString);

                   /*
                    * qsWords are valid quote strings only when
                    * they are followed by text.
                    */
                   if (offset > 0 && qstype == qsWord &&
                       !allwd_after_qsword(now(word,j + offset)))
                       offset = -1;

                   if (offset > 0)
                       return qs_add(qs, word, qstype, i, j, offset, 1);
                 }
                 finished++;
           }
           else{
	       if(i > 0)
		return qs_add(qs, word, qsNormal, 0, i, 0, 1);
	       else if(!forbidden(c))
                  return qs_add(qs, word, qsChar, 0, 1, 0, 1);
               else    /* chao pescao */
                  finished++;
           }
       break;
      }  /* End Switch */
    }  /* End while */
    if (i > 0)
       qstring = qs_add(qs, word, qsNormal, 0, i, 0, 0);
    return qstring;
}

int
isaword(char word[NSTRING], int i, int j)
{
  return i <= j && is_cletter(word[i]) ?
          (i < j ? isaword(word,i+1,j) : 1) : 0;
}

int
isamailbox(char word[NSTRING], int i, int j)
{
  return i <= j && (is_cletter(word[i]) || is_a_digit(word[i])
                 || word[i] == '.')
       ? (i < j ? isamailbox(word,i+1,j) : 1) : 0;
}

/*
   This routine removes the last part that is qsword or qschar that is not
   followed by a normal part. This means that if a qsword or qschar is
   followed by a qsnormal (or qsstring), we accept the qsword (or qschar)
   as part of a quote string.
 */
QSTRING_S *
remove_qsword(QSTRING_S *cl)
{
     QSTRING_S *np = cl;
     QSTRING_S *cp = np;               /* this variable trails cl */

     while(1){
        while (cl && cl->qstype == qsNormal)
            cl = cl->next;

        if (cl){
         if (((cl->qstype == qsWord) || (cl->qstype == qsChar))
               && !exists_good_part(cl)){
             if (np == cl)     /* qsword or qschar at the beginning */
                free_qs(&cp);
             else{
                while (np->next != cl)
                    np = np->next;
                free_qs(&(np->next));
            }
            break;
         }
         else
            cl = cl->next;
        }
        else
         break;
    }
    return cp;
}

int
exists_good_part (QSTRING_S *cl)
{
   return (cl ? (((cl->qstype != qsWord) && (cl->qstype != qsChar)
                 && qs_allowed(cl) && !value_is_space(cl->value))
              ? 1 : exists_good_part(cl->next))
	      : 0);
}

int
line_isblank(char **q, char *GLine, char *NLine, char *PLine, int buflen)
{
    int n = 0;
    QSTRING_S *cl;
    char qstr[NSTRING];

    cl = do_raw_quote_match(q, GLine, NLine, PLine, NULL, NULL);

    flatten_qstring(cl, qstr, NSTRING);

    free_qs(&cl);

    for(n = strlen(qstr); n < buflen && GLine[n]; n++)
       if(!ISspace((unsigned char) GLine[n]))
         return(FALSE);

    return(TRUE);
}

QSTRING_S *
do_raw_quote_match(char **q, char *GLine, char *NLine, char *PLine, QSTRING_S **nlp, QSTRING_S **plp)
{
   QSTRING_S *cl, *nl = NULL, *pl = NULL;
   char nbuf[NSTRING], pbuf[NSTRING], buf[NSTRING];
   int emptypl = 0, emptynl = 0;

   if (!(cl = is_quote(q, GLine, 0)))  /* if nothing in, nothing out */
      return cl;

   nl = is_quote(q, NLine, 0);         /* Next Line     */
   if (nlp) *nlp = nl;
   pl = is_quote(q, PLine, 0);         /* Previous Line */
   if (plp) *plp = pl;
   /*
    * If there's nothing in the preceeding or following line
    * there is not enough information to accept it or discard it. In this
    * case it's likely to be an isolated line, so we better accept it
    * if it does not look like a word.
    */ 
   flatten_qstring(pl, pbuf, NSTRING);
   emptypl = (!PLine || !PLine[0] ||
               (pl && value_is_space(pbuf)) && !PLine[strlen(pbuf)]) ? 1 : 0;
   if (emptypl){
      flatten_qstring(nl, nbuf, NSTRING);
      emptynl = (!NLine || !NLine[0] ||
               (nl && value_is_space(nbuf) && !NLine[strlen(nbuf)])) ? 1 : 0;
      if (emptynl){
       cl = remove_qsword(cl);
       if((cl = fix_qstring_allowed(cl, NULL, NULL)) != NULL)
          cl = qs_remove_trailing_spaces(cl);
       free_qs(&nl);
       free_qs(&pl);
       if(nlp) *nlp = NULL;
       if(plp) *plp = NULL;

       return cl;
      }
   }

   /*
    * If either cl, nl or pl contain suspicious characters that may make
    * them (or not) be quote strings, we need to fix them, so that the
    * next pass will be done correctly.
    */

   cl = fix_qstring(cl, nl, pl);
   nl = trim_qs_from_cl(cl, nl, NULL);
   pl = trim_qs_from_cl(cl, NULL, pl);
   if((cl = fix_qstring_allowed(cl, nl, pl)) != NULL){
     nl = trim_qs_from_cl(cl, nl, NULL);
     pl = trim_qs_from_cl(cl, NULL, pl);
   }
   else{
     free_qs(&nl);
     free_qs(&pl);
   }
   if(nlp) 
      *nlp = nl;
   else
     free_qs(&nl);
   if(plp)
     *plp = pl;
   else
     free_qs(&pl);
   return cl;
}

QSTRING_S *
do_quote_match(char **q, char *GLine, char *NLine, char *PLine, char *rqstr, 
int rqstrlen, int plb)
{
    QSTRING_S *cl, *nl = NULL, *pl = NULL;
    int c, n, p,i, j, NewP, NewC, NewN, clength, same = 0;
    char nbuf[NSTRING], pbuf[NSTRING], buf[NSTRING];

    if(rqstr)
      *rqstr = '\0';

    /* if nothing in, nothing out */
    cl = do_raw_quote_match(q, GLine, NLine, PLine, &nl, &pl);
    if(cl == NULL){
      free_qs(&nl);
      free_qs(&pl);
      return cl;
    }

    flatten_qstring(cl, rqstr, rqstrlen);
    flatten_qstring(cl,  buf, NSTRING);
    flatten_qstring(nl, nbuf, NSTRING);
    flatten_qstring(pl, pbuf, NSTRING);

    /*
     * Once upon a time, is_quote used to return the length of the quote
     * string that it had found. One day, not long ago, black hand came
     * and changed all that, and made is_quote return a quote string
     * divided in several fields, making the algorithm much more
     * complicated. Fortunately black hand left a few comments in the
     * source code to make it more understandable. Because of this change
     * we need to compute the lengths of the quote strings separately
     */
     c =  buf &&  buf[0] ? strlen(buf)  : 0;
     n = nbuf && nbuf[0] ? strlen(nbuf) : 0;
     p = pbuf && pbuf[0] ? strlen(pbuf) : 0;
     /*
      * When quote strings contain only blank spaces (ascii code 32) the
      * above count is equal to the length of the quote string, but if
      * there are TABS, the length of the quote string as seen by the user
      * is different than the number that was just computed.  Because of
      * this we demand a recount (hmm.. unless you are in Florida, where
      * recounts are forbidden)
      */
     NewP = strlenis(pbuf);
     NewC = strlenis(buf);
     NewN = strlenis(nbuf);

     /*
      * For paragraphs with spaces in the first line, but no space in the
      * quote string of the second line, we make sure we choose the quote
      * string without a space at the end of it.
      */
     if ((NLine && !NLine[0])
       && ((PLine && !PLine[0])
            || (((same = same_qstring(pl, cl)) != 0)
                       && (same != count_levels_qstring(cl)))))
       cl = qs_remove_trailing_spaces(cl);
     else
       if (NewC > NewN){
       int agree = 0;
         for (j = 0; (j < n) && (GLine[j] == NLine[j]); j++);
       clength = j;
       /* clength is the common length in which Gline and Nline agree */
       /* j < n means that they do not agree fully */
       /* GLine = "   \tText"
          NLine = "   Text" */
       if(j == n)
          agree++;
       if (clength < n){ /* see if buf and nbuf are padded with spaces and tabs */
          for (i = clength; i < n && ISspace(NLine[i]); i++);
          if (i == n){/* padded NLine until the end of spaces? */
             for (i = clength; i < c && ISspace(GLine[i]); i++);
               if (i == c) /* Padded CLine until the end of spaces? */
                  agree++;
          }
       }
       if (agree){
	  for (j = clength; j < c && ISspace(GLine[j]); j++);
	  if (j == c){
      /*
       * If we get here, it means that the current line has the same
       * quote string (visually) than the next line, but both of them
       * are padded with different amount of TABS or spaces at the end.
       * The current line (GLine) has more spaces/TABs than the next
       * line. This is the typical situation that is found at the
       * begining of a paragraph. We need to check this, however, by
       * checking the previous line. This avoids that we confuse
       * ourselves with being in the last line of a paragraph.
       * Example when it should not free_qs(cl)
       * "    Text in Paragraph 1" (PLine)
       * "    Text in Paragraph 1" (GLine)
       * "  Other Paragraph Number 2" (NLine)
       *
       * Example when it should free_qs(cl):
       * ":) "                (PLine) p = 3, j = 3
       * ":)   Text"          (GLine) c = 5
       * ":) More text"       (NLine) n = 3
       *
       * Example when it should free_qs(cl):
       * ":) "                (PLine) p =  3, j = 3
       * ":) > > >   Text"    (GLine) c = 11
       * ":) > > > More text" (NLine) n =  9
       *
       * Example when it should free_qs(cl):
       * ":) :) "             (PLine) p =  6, j = 3
       * ":) > > >   Text"    (GLine) c = 11
       * ":) > > > More text" (NLine) n =  9
       *
       * Example when it should free_qs(cl):
       * ":) > > >     "      (PLine) p = 13, j = 11
       * ":) > > >   Text"    (GLine) c = 11
       * ":) > > > More text" (NLine) n =  9
       *
       * The following example is very interesting. The "Other Text"
       * line below should free the quote string an make it equal to the
       * quote string of the line below it, but any algorithm trying
       * to advance past that line should make it stop there, so
       * we need one more check, to check the raw quote string and the
       * processed quote string at the same time.
       * FREE qs in this example.
       * "   Some Text"       (PLine) p = 3, j = 0
       * "\tOther Text"       (GLine) c = 1
       * "   More Text"       (NLine) n = 3
       *
       */
           for (j = 0; (j < p) && (GLine[j] == PLine[j]); j++);
            if ((p != c || j != p) && NLine[n])
               if(!get_indent_raw_line(q, PLine, nbuf, NSTRING, p, plb)
                 || NewP + strlenis(nbuf) != NewC){
                 free_qs(&cl);
                 free_qs(&pl);
                 return nl;
               }
            }
         }
       }

     free_qs(&nl);
     free_qs(&pl);

     return cl;
}

/*
 * Given a line, an initial position, and a quote string, we advance the
 * current line past the quote string, including arbitraty spaces
 * contained in the line, except that it removes trailing spaces. We do
 * not handle TABs, if any, contained in the quote string. At least not
 * yet.
 *
 * Arguments: q - quote string
 *          l - a line to process
 *          i - position in the line to start processing. i = 0 is the
 *              begining of that line.
 */
int
advance_quote_string(char *q, char l[NSTRING], int i)
{
    int n = 0, j = 0, is = 0, es = 0;
    int k, m, p, adv;
    char qs[NSTRING] = {'\0'};
    if(!q || !*q)
      return(0);
    for (p = strlen(q); (p > 0) && (q[p - 1] == ' '); p--, es++);
    if (!p){  /* string contains only spaces */
       for (k = 0; ISspace(l[i + k]); k++);
       k -= k % es;
       return k;
    }
    for (is = 0; ISspace(q[is]); is++); /* count initial spaces */ 
    for (m = 0 ; is + m < p ; m++)
      qs[m] = q[is + m];   /* qs = quote string without any space at the end */
                     /* advance as many spaces as there are at the begining */
    for (k = 0; ISspace(l[i + j]); k++, j++);
                      /* now find the visible string in the line */
    for (m = 0; qs[m] && l[i + j] == qs[m]; m++, j++);
    if (!qs[m]){      /* no match */
      /*
       * So far we have advanced at least "is" spaces, plus the visible
       * string "qs". Now we need to advance the trailing number of
       * spaces "es". If we can do that, we have found the quote string.
       */
      for (p = 0; ISspace(l[i + j + p]); p++);
      adv = advance_quote_string(q, l, i + j + ((p < es) ? p : es));
      n = ((p < es) ? 0 : es) + k + m + adv;
    }
    return n;
}

/*
 * This function returns the effective length in screen of the quote
 * string. If the string contains a TAB character, it is added here, if
 * not, the length returned is the length of the string
 */
int strlenis(char *qstr)
{
  int i, rv = 0; 
  for (i = 0; qstr && qstr[i]; i++)
       rv += ((qstr[i] == TAB) ? (~rv & 0x07) + 1 : 1);
  return rv;
}

int
is_indent (char word[NSTRING], int plb)
{
  int i = 0, finished = 0, c, nxt, j, k, digit = 0, bdigits = -1, alpha = 0;

   if (!word || !word[0])
      return i;

   for (i = 0, j = 0; ISspace(word[i]); i++, j++);
   while ((i < NSTRING - 2) && !finished){
      switch (c = now(word,i)){
          case NBSP:
          case TAB :
          case ' ' : for (; ISspace(word[i]); i++);
                     if (!is_indent_char(now(word,i)))
                       finished++;
                  break;

           case '+' :
           case '.' :
           case ']' :
           case '*' :
           case '}' :
           case '-' :
           case RPAREN:
                  nxt = next(word,i);
                  if ((c == '.' && allowed_after_period(nxt) && alpha)
                       || (c == '*' && allowed_after_star(nxt))
                       || (c == '}' && allowed_after_braces(nxt))
                       || (c == '-' && allowed_after_dash(nxt))
                       || (c == '+' && allowed_after_dash(nxt))
                       || (c == RPAREN && allowed_after_parenth(nxt))
                       || (c == ']' && allowed_after_parenth(nxt)))
                     i++;
                  else
                     finished++;
                  break;

            default : if (is_a_digit(c) && plb){
                        if (bdigits < 0)
                           bdigits = i;  /* first digit */
                        for (k = i; is_a_digit(now(word,k)); k++);
                        if (k - bdigits > 2){ /* more than 2 digits? */
                           i = bdigits; /* too many! */
                           finished++;
                        }
                        else{
                           if(allowed_after_digit(now(word,k),word,k)){
                             alpha++;
                             i = k;
                           }
                           else{
                             i = bdigits;
                             finished++;
                           }
                        }
                      }
                      else
                        finished++;
                   break;

      }
   }
   if (i == j)
      i = 0;  /* there must be something more than spaces in an indent string */
   return i;
}

int
get_indent_raw_line(char **q, char *GLine, char *buf, int buflen, int k, int plb)
{
     int i, j;
     char testline[1024];

     if(k > 0){
	for(j = 0; GLine[j] != '\0'; j++){
	   testline[j] = GLine[j];
	   testline[j+1] = '\0';
	   if(strlenis(testline) >= strlenis(buf))
	     break;
	}
	k = ++j;     /* reset k */
     }
     i = is_indent(GLine+k, plb);

     for (j = 0; j < i && j < buflen && (buf[j] = GLine[j + k]); j++);
     buf[j] = '\0';

     return i;
}

/* support for remembering quote strings across messages */
char **allowed_qstr = NULL;
int list_len = 0;

void
free_allowed_qstr(void)
{
  int i;
  char **q = allowed_qstr;

  if(q == NULL)
    return;

  for(i = 0; i < list_len; i++)
    fs_give((void **)&q[i]);

  fs_give((void **)q);
  list_len = 0;
}

void
add_allowed_qstr(void *q, int type)
{
  int i;

  if(allowed_qstr == NULL){
     allowed_qstr =  malloc(sizeof(char *));
     list_len = 0;
  }

  if(type == 0){
    allowed_qstr[list_len] = malloc((1+strlen((char *)q))*sizeof(char));
    strcpy(allowed_qstr[list_len], (char *)q);
  }
  else
    allowed_qstr[list_len] = (char *) ucs4_to_utf8_cpystr((UCS *)q);

  fs_resize((void **)&allowed_qstr, (++list_len + 1)*sizeof(char *));
  allowed_qstr[list_len] = NULL;
}

void
record_quote_string (QSTRING_S *qs)
{
  int i, j, k;

  for(; qs && qs->value; qs = qs->next){
    j = 0;
    for (; ;){
       k = j;
       for(i = 0; i < list_len; i++){
          j += advance_quote_string(allowed_qstr[i], qs->value, j);
          for(; ISspace(qs->value[j]); j++);
       }
       if(k == j)
	 break;
    }
    if(qs->value[j] != '\0')
	add_allowed_qstr((void *)(qs->value + j), 0);
  }
}

/* type utf8: code 0; ucs4: code 1. */
char **
default_qstr(void *q, int type)
{
  if(allowed_qstr == NULL)
    add_allowed_qstr(q, type);

  return allowed_qstr;
}

