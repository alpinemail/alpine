/*
 * ========================================================================
 * Copyright 2006-2008 University of Washington
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

#include "headers.h"
#include "xoauth2conf.h"
#include "keymenu.h"
#include "status.h"
#include "confscroll.h"
#include "init.h"
#include "../pith/state.h"
#include "../pith/conf.h"
#include "../pith/list.h"
#include "../pith/mailcmd.h"

extern OAUTH2_S alpine_oauth2_list[];

XOAUTH2_INFO_S xoauth_default[] = {
  { GMAIL_NAME, GMAIL_ID, GMAIL_SECRET, GMAIL_TENANT, NULL, NULL},
  { OUTLOOK_NAME, OUTLOOK_ID, OUTLOOK_SECRET, OUTLOOK_TENANT, NULL, NULL},
  { YAHOO_NAME, YAHOO_ID, YAHOO_SECRET, YAHOO_TENANT, NULL, NULL},
  { YANDEX_NAME, YANDEX_ID, YANDEX_SECRET, YANDEX_TENANT, NULL, NULL},
  { NULL, NULL, NULL, NULL, NULL, NULL}
};

typedef enum {Xname = 0, Xid, Xsecret, Xtenant, Xuser, XFlow, Xend} XTYPES;

typedef struct xoauh2_info_val_s {
  char *screen_name;
  char *pinerc_name;
} XOAUTH2_INFO_VAL_S;

/* the order here must match the order in XTYPES above */
XOAUTH2_INFO_VAL_S x_default[] = {
   {NULL, 		"/NAME="},
   {"Client-Id",	"/ID="},
   {"Client-Secret",	"/SECRET="},
   {"Tenant",		"/TENANT="},
   {"Username",		"/USER="},
   {"Auth Flow",	"/Flow="},
   {NULL, 		NULL}
};

#define XNAME	x_default[Xname].pinerc_name
#define XID	x_default[Xid].pinerc_name
#define XSECRET	x_default[Xsecret].pinerc_name
#define XTENANT	x_default[Xtenant].pinerc_name
#define XUSER	x_default[Xuser].pinerc_name
#define XFLOW	x_default[XFlow].pinerc_name

#define XOAUTH2_CLIENT_ID	x_default[Xid].screen_name
#define XOAUTH2_CLIENT_SECRET	x_default[Xsecret].screen_name
#define XOAUTH2_TENANT		x_default[Xtenant].screen_name
#define XOAUTH2_USERS		x_default[Xuser].screen_name
#define XOAUTH2_FLOW		x_default[XFlow].screen_name

char *list_to_array(char **);
char **array_to_list(char *);
void write_xoauth_configuration(struct variable  *, struct variable **, EditWhich);
char **xoauth2_conf_dedup_and_merge(char ***);
int  same_xoauth2_info(XOAUTH2_INFO_S, XOAUTH2_INFO_S);
XOAUTH2_INFO_S *xoauth_info_choice(XOAUTH2_INFO_S **, char *);
int xoauth2_info_tool(struct pine *, int, CONF_S **, unsigned int);

int
same_xoauth2_info(XOAUTH2_INFO_S x, XOAUTH2_INFO_S y)
{
   int rv = 0;
   if(x.name && y.name && !strcmp(x.name, y.name)
	&& x.client_id && y.client_id && !strcmp(x.client_id, y.client_id)
	&& ((!x.client_secret && !y.client_secret)
		|| (x.client_secret && y.client_secret && !strcmp(x.client_secret, y.client_secret)))
	&& ((!x.tenant && !y.tenant) || (x.tenant && y.tenant && !strcmp(x.tenant, y.tenant))))
	rv = 1;
   return rv;
}

char *
list_to_array(char **list)
{
   char *rv;
   int i;
   size_t n;

   if(list == NULL || *list == NULL) return NULL;

   for(i = 0, n = 0; list[i] != NULL; i++)
      n += strlen(list[i]) + 1;

   rv = fs_get(n*sizeof(char));
   *rv = '\0';
   for(i = 0; list[i] != NULL; i++){
      strcat(rv, list[i]);
      if(list[i+1] != NULL) strcat(rv, ",");
   }
   return rv;
}


char **array_to_list(char *array)
{
   int i;
   char *u;

   if(array == NULL || *array == '\0') return NULL;

   for(u = array, i = 0; u  && *u; u++)
       if(*u == ',') i++;

   return parse_list(array, i+1, 0,NULL);
}

char *
xoauth_config_line(XOAUTH2_INFO_S *x)
{
  size_t n;
  char *rv;
  int i;

  if(x == NULL) return NULL;

  n = strlen(XNAME) + strlen(x->name) + strlen(XID) + strlen(x->client_id)
	+ strlen(x->client_secret ? XSECRET : "") + strlen(x->client_secret ? x->client_secret : "")
	+ strlen(x->tenant ? XTENANT : "") + strlen(x->tenant ? x->tenant : "")
	+ strlen(XUSER) + strlen(x->users ? x->users : "")
	+ strlen(XFLOW) + strlen(x->flow ? x->flow : "")
	+ 2 + 3 + (x->client_secret ? 3 : 0) + (x->tenant ? 3 : 0)
	+ 3 + (x->flow ? 3 : 0) + 1;
  rv = fs_get(n*sizeof(char));
  sprintf(rv, "%s\"%s\" %s\"%s\"", XNAME, x->name, XID, x->client_id);
  if(x->client_secret)
     sprintf(rv + strlen(rv), " %s\"%s\"", XSECRET, x->client_secret);
  if(x->tenant)
     sprintf(rv + strlen(rv), " %s\"%s\"", XTENANT, x->tenant);
  sprintf(rv + strlen(rv), " %s\"%s\"", XUSER, x->users ? x->users : "");
  if(x->flow)
     sprintf(rv + strlen(rv), " %s\"%s\"", XFLOW, x->flow ? x->flow : "");
  return rv;
}

int
xoauth2_info_tool(struct pine *ps, int cmd, CONF_S **cl, unsigned int flags)
{
   int rv = 0;

   switch(cmd){
      case MC_CHOICE:
	*((*cl)->d.x.selected) = (*cl)->d.x.pat;
	rv = simple_exit_cmd(flags);

      case MC_EXIT:
	rv = simple_exit_cmd(flags);
	break;

      default:
	rv = -1;
   }

   if(rv > 0)
     ps->mangled_body = 1;

   return rv;
}

XOAUTH2_INFO_S *
xoauth_info_choice(XOAUTH2_INFO_S **xinfo, char *user)
{
   int i, n, rv;
   if(!ps_global->ttyo){
	char *s;
	char prompt[1024];
	char reply[1024];
	int sel;
	for(i = n = 0; xinfo[i] != NULL; i++)
	   n += strlen(xinfo[i]->client_id); + 5;	/* number, parenthesis, space */
	n += strlen(xinfo[0]->name) + strlen(user);
	n += 1024;	/* large enough to display to lines of 80 characters in UTF-8 */
	s = fs_get(n*sizeof(char));
	sprintf(s, _("Alpine cannot determine which client-id to use for the username <%s> for your %s account. "), user, xinfo[0]->name);
	sprintf(s + strlen(s), _("Please select the client-id to use from the following list.\n\n"));
	for(i = 0; xinfo[i]; i++)
	   sprintf(s + strlen(s), " %d) %.70s\n", i+1, xinfo[i]->client_id);
	sprintf(s + strlen(s), "%s", "\n\n");

	display_init_err(s, 0);

	strncpy(prompt, _("Enter your selection number: "), sizeof(prompt));
	prompt[sizeof(prompt)-1] = '\0';

	do{
	   rv = optionally_enter(reply, 0, 0, sizeof(reply), prompt, NULL, NO_HELP, 0);
	   sel = atoi(reply) - 1;
	   rv = (sel >= 0 && sel < i) ? 0 : -1;
	} while (rv != 0);
	return copy_xoauth2_info(xinfo[rv]);
   }
   else{
      CONF_S  *ctmp = NULL, *first_line = NULL;
      XOAUTH2_INFO_S *x_sel = NULL;
      OPT_SCREEN_S   screen;
      char tmp[1024];

      dprint((9, "xoauth2 select client-id screen"));
      ps_global->next_screen = SCREEN_FUN_NULL;

      memset(&screen, 0, sizeof(screen));

      for(i = 0; i < sizeof(tmp) && i < ps_global->ttyo->screen_cols; i++)
	  tmp[i] = '-';
      tmp[i] = '\0';

      new_confline(&ctmp);
      ctmp->flags |= CF_NOSELECT;
      ctmp->value = cpystr(tmp);

      new_confline(&ctmp);
      ctmp->flags |= CF_NOSELECT;
      ctmp->value = cpystr(_("Select a Client-ID to use with this account"));

      new_confline(&ctmp);
      ctmp->flags |= CF_NOSELECT;
      ctmp->value = cpystr(tmp);

      new_confline(&ctmp);
      ctmp->flags |= CF_NOSELECT | CF_B_LINE;

      sprintf(tmp, _("Alpine cannot determine which client-id to use for the username <%s>"), user);
      new_confline(&ctmp);
      ctmp->flags |= CF_NOSELECT;
      ctmp->value = cpystr(tmp);

      sprintf(tmp, _("for your %s account. Please select the client-id to use from the following list.\n\n"), xinfo[0]->name);
      new_confline(&ctmp);
      ctmp->flags |= CF_NOSELECT;
      ctmp->value = cpystr(tmp);

      new_confline(&ctmp);
      ctmp->flags |= CF_NOSELECT | CF_B_LINE;

      for(i = 0; xinfo[i] != NULL; i++){
	new_confline(&ctmp);
        if(!first_line)
          first_line = ctmp;

        ctmp->value        = cpystr(xinfo[i]->client_id);
        ctmp->d.x.selected = &x_sel;
        ctmp->d.x.pat      = copy_xoauth2_info(xinfo[i]);
        ctmp->keymenu      = &xoauth2_id_select_km;
        ctmp->help         = NO_HELP;
        ctmp->help_title   = NULL;
        ctmp->tool         = xoauth2_info_tool;
        ctmp->flags        = CF_STARTITEM;
        ctmp->valoffset    = 4;
      }
     (void)conf_scroll_screen(ps_global, &screen, first_line, _("SELECT CLIENT_ID"),
                             _("xoauth2"), 0, NULL);
      return x_sel;
   }
   return NULL;
}

/* Get the client-id, etc. for server "name" associated to user "user" */
XOAUTH2_INFO_S *
oauth2_get_client_info(unsigned char *name, char *user)
{
  int i, j, matches;
  char ***alval, **lval;
  XOAUTH2_INFO_S *x, **xinfo;

  if(name == NULL || *name == '\0' || user == NULL || *user == '\0')
    return NULL;

  matches = 0;
  /* first count how many servers  */
  lval = ps_global->vars[V_XOAUTH2_INFO].current_val.l;
  for(i = 0; lval && lval[i]; i++){
     x = xoauth_parse_client_info(lval[i]);
     if(x && x->name && name && !strcmp(x->name, name))
	matches++;
     free_xoauth2_info(&x);
  }

  /* if nothing, use the default value */
  for(i = 0; xoauth_default[i].name != NULL && strcmp(xoauth_default[i].name, name); i++);
  if(xoauth_default[i].name) matches++;

  if(matches == 0) return NULL;
  if(matches == 1) return copy_xoauth2_info(&xoauth_default[i]);

  /* more than one match, see if it is a duplicate client-id entry */
  xinfo = fs_get((matches + 1)*sizeof(XOAUTH2_INFO_S *));
  memset((void *)xinfo, 0, (matches + 1)*sizeof(XOAUTH2_INFO_S *));
  matches = 0;	/* restart the recount, it might go lower! */
  for(i = 0; lval && lval[i]; i++){
     x = xoauth_parse_client_info(lval[i]);
     if(x && x->name && name && !strcmp(x->name, name)){
	for(j = 0; xinfo && xinfo[j] && !same_xoauth2_info(*x, *xinfo[j]); j++);
	if(!xinfo[j]) xinfo[matches++] = copy_xoauth2_info(x);
     }
     free_xoauth2_info(&x);
  }
  for(i = 0; xoauth_default[i].name != NULL && strcmp(xoauth_default[i].name, name); i++);
  for(j = 0; xinfo && xinfo[j] && !same_xoauth2_info(xoauth_default[i], *xinfo[j]); j++);
  if(!xinfo[j]) xinfo[matches++] = copy_xoauth2_info(&xoauth_default[i]);

  /* if after removing the duplicate entries, we only have one, use it */
  if(matches == 1){
     x = copy_xoauth2_info(xinfo[0]);
     free_xoauth2_info(&xinfo[0]);
     fs_give((void **) xinfo);
     return x;
  }

  /* we have more than one match, now check if any of them matches the given user */
  matches = 0;
  for(i = 0; xinfo && xinfo[i]; i++){
      lval = array_to_list(xinfo[i]->users);
      for(j = 0; lval && lval[j] && strucmp(lval[j], user); j++);
      if(lval && lval[j]){
	 matches++;
	 free_xoauth2_info(&x);
	 x = copy_xoauth2_info(xinfo[i]);
      }
      if(lval) free_list_array(&lval);
  }

  /* only one server matches the username */
  if(matches == 1){
     for(i = 0; xinfo[i] != NULL; i++)
         free_xoauth2_info(&xinfo[i]);
     fs_give((void **) xinfo);
     return x;
  }

  free_xoauth2_info(&x);
  /* We either have no matches, or have more than one match!
   * in either case, let the user pick what they want */
   x = xoauth_info_choice(xinfo, user);
   for(i = 0; xinfo[i] != NULL; i++)
      free_xoauth2_info(&xinfo[i]);
   fs_give((void **) xinfo);

   /* Once the user chose a client-id, save it so we do not ask again */
   if(x != NULL){
      int n = x->users ? strlen(x->users) + 1 : 0;
      char ***alval, **l;

      fs_resize((void **) &x->users, (n + strlen(user) + 1)*sizeof(char));
      x->users[n > 0 ? n - 1 : 0] = '\0';
      if(n > 0) strcat(x->users, ",");
      strcat(x->users, user);
      alval = ALVAL(&ps_global->vars[V_XOAUTH2_INFO], Main);
      lval = *alval;

      for(n = 0; lval && lval[n]; n++);
      fs_resize((void **) &lval, (n+2)*sizeof(char *));
      lval[n] = xoauth_config_line(x);
      lval[n+1] = NULL;
      *alval = xoauth2_conf_dedup_and_merge(&lval);
      set_current_val(&ps_global->vars[V_XOAUTH2_INFO], FALSE, FALSE);
      write_pinerc(ps_global, Main, WRP_NONE);
   }

   return x;
}

/* write vlist to v 
 * Each vlist member is of type "p", while "v" is of type "l", so we
 * each entry in "l" by using each of the "p" entries.
 */
void
write_xoauth_configuration(struct variable  *v, struct variable **vlist, EditWhich ew)
{
  int i, k, m, n;
  XOAUTH2_INFO_S *x = NULL, *y;
  char ***alval, **lval, **l;
  char *p;

  for (i = 0, n = 0; vlist[i] != NULL; i++)	/* count number of lines we need */
      if(!strcmp(vlist[i]->name, XOAUTH2_USERS))
	n++;
  lval = fs_get((n+1)*sizeof(char *));
  memset((void *) lval, 0, (n+1)*sizeof(char *));

  m = -1;
  alval  = ALVAL(v, ew);
  for (i = 0, k = 0; vlist[i] != NULL; i++){
      if(x == NULL){
	 x = new_xoauth2_info();
	 x->name = cpystr(vlist[i]->descrip);	/* hack! but makes life so much easier! */
	 for(m = 0; xoauth_default[m].name != NULL
		    && strcmp(xoauth_default[m].name, x->name); m++);
      }
      if (x->client_id == NULL && !strcmp(vlist[i]->name, XOAUTH2_CLIENT_ID)){
	 p = PVAL(vlist[i], ew);
	 if (p == NULL) p = vlist[i]->current_val.p;
	 if(p != NULL)
	    x->client_id = cpystr(p);
	 continue;
      }
      if (x->client_secret == NULL
	  && m >= 0
	  && xoauth_default[m].client_secret
	  && !strcmp(vlist[i]->name, XOAUTH2_CLIENT_SECRET)){
	 p = PVAL(vlist[i], ew);
	 if (p == NULL) p = vlist[i]->current_val.p;
	 if(p != NULL)
	    x->client_secret = cpystr(p);
	 continue;
      }
      if (x->tenant == NULL
	  && m >= 0
	  && xoauth_default[m].tenant
	  && !strcmp(vlist[i]->name, XOAUTH2_TENANT)){
	 p = PVAL(vlist[i], ew);
	 if (p == NULL) p = vlist[i]->current_val.p;
	 if(p != NULL)
	    x->tenant = cpystr(p);
	 continue;
      }
      if (x->flow == NULL && !strcmp(vlist[i]->name, XOAUTH2_FLOW)){
	 p = PVAL(vlist[i], ew);
	 if (p == NULL) p = vlist[i]->current_val.p;
	 if(p != NULL)
	    x->flow = cpystr(p);
	 continue;
      }
      if (x->users == NULL && !strcmp(vlist[i]->name, XOAUTH2_USERS)){
	 l = LVAL(vlist[i], ew);
	 x->users = list_to_array(l);
      }
      /* don't let it get to here until we are done! */
      lval[k++] = xoauth_config_line(x);
	/* get ready for next run */
      free_xoauth2_info(&x);
      m = -1;
  }
  if(k > 0){
     lval[k] = NULL;
     if(*alval) free_list_array(alval);
     *alval = lval;
  }
  else
     *alval = NULL;
  set_current_val(&ps_global->vars[V_XOAUTH2_INFO], FALSE, FALSE);
}


/* parse line of the form
  /NAME="text" /ID="text" /TENANT="text" /SECRET="text" /USER="text"
 */
XOAUTH2_INFO_S *
xoauth_parse_client_info(char *lvalp)
{
  char *s, *t, c;
  XOAUTH2_INFO_S *x;

  if (lvalp == NULL) return NULL;

  x = new_xoauth2_info();
  if((s = strstr(lvalp, XNAME)) != NULL){
	s += strlen(XNAME);
	if(*s == '"') s++;
	for(t = s; *t && *t != '"' && *t != ' '; t++);
	c = *t;
	*t = '\0';
	if (*s) x->name = cpystr(s);
	*t = c;
  } else x->name = NULL;

  if((s = strstr(lvalp, XID)) != NULL){
	s += strlen(XID);
	if(*s == '"') s++;
	for(t = s; *t && *t != '"' && *t != ' '; t++);
	c = *t;
	*t = '\0';
	if (*s) x->client_id = cpystr(s);
	*t = c;
  } else x->client_id = NULL;

  if((s = strstr(lvalp, XTENANT)) != NULL){
	s += strlen(XTENANT);
	if(*s == '"') s++;
	for(t = s; *t && *t != '"' && *t != ' '; t++);
	c = *t;
	*t = '\0';
	if (*s) x->tenant = cpystr(s);
	*t = c;
  } else x->tenant = NULL;

  if((s = strstr(lvalp, XSECRET)) != NULL){
	s += strlen(XSECRET);
	if(*s == '"') s++;
	for(t = s; *t && *t != '"' && *t != ' '; t++);
	c = *t;
	*t = '\0';
	if (*s) x->client_secret = cpystr(s);
	*t = c;
  } else x->client_secret = NULL;

  if((s = strstr(lvalp, XFLOW)) != NULL){
	s += strlen(XFLOW);
	if(*s == '"') s++;
	for(t = s; *t && *t != '"' && *t != ' '; t++);
	c = *t;
	*t = '\0';
	if(*s)	x->flow = cpystr(s);
	*t = c;
  } else x->flow = NULL;

  if((s = strstr(lvalp, XUSER)) != NULL){
	s += strlen(XUSER);
	if(*s == '"') s++;
	for(t = s; *t && *t != '"' && *t != ' '; t++);
	c = *t;
	*t = '\0';
	if(*s)	x->users = cpystr(s);
	*t = c;
  } else x->users = NULL;

  return x;
}

char **
xoauth2_conf_dedup_and_merge(char ***alval)
{
   int i, j, k, l, n, m;
   char **lval, **rv;
   XOAUTH2_INFO_S *x, *y;

   if(alval == NULL || *alval == NULL || **alval == NULL)
      return NULL;

   lval = *alval;
   for(i = 0; lval[i] != NULL; i++);	/* count how many entries */

   rv = fs_get((i+1)*sizeof(char *));
   memset((void *)rv, 0, (i+1)*sizeof(char *));

   for (i = 0;  lval[i] != NULL; i++){
       x = xoauth_parse_client_info(lval[i]);
       for (j = 0; rv[j] != NULL; j++){
           y = xoauth_parse_client_info(rv[j]);
	   /* check if this is the same data. If so, merge the users into one and discard the old data */
	   if(same_xoauth2_info(*x, *y)){
	      char **l1, **l2, **l3;
	      int k, n;
	      /* merge user1 with user2, save in x->users */
	      l1 = array_to_list(x->users);
	      l2 = array_to_list(y->users);

	      for(n = 0; l1 && l1[n]; n++);
	      for(m = 0; l2 && l2[m]; m++, n++);
	      l3 = fs_get((n+1)*sizeof(char*));
	      memset((void *) l3, 0, (n+1)*sizeof(char *));

	      for(l = 0, n = 0; l1 && l1[l]; l++){
		  for(k = 0; l1 && l1[j] && l3[k] && strucmp(l1[l], l3[k]); k++);
		  if(l3[k] == NULL && l1 && l1[l] != NULL)
		     l3[n++] = cpystr(l1[l]);
	      }
	      for(l = 0; l2 && l2[l]; l++){
		  for(k = 0; l2 && l2[l] && l3[k] && strucmp(l2[l], l3[k]); k++);
		  if(l3[k] == NULL && l2 && l2[l] != NULL)
		     l3[n++] = cpystr(l2[l]);
	      }
	      l3[n++] = NULL;
	      if(x->users) fs_give((void **) &x->users);
	      x->users = list_to_array(l3);
	      fs_give((void **) &rv[j]);
	      rv[j] = xoauth_config_line(x);

	      if(l1) free_list_array(&l1);
	      if(l2) free_list_array(&l2);
	      if(l3) free_list_array(&l3);
	      free_xoauth2_info(&y);
	      break;
	   }
	   free_xoauth2_info(&y);
       }
       if(rv[j] == NULL) rv[j] = cpystr(lval[i]);
   }
   return rv;
}

/*
 * X = new value, Y = default configuration
 */
void
write_xoauth_conf_entry(XOAUTH2_INFO_S *x, XOAUTH2_INFO_S *y, CONF_S **cl, CONF_S **clb, CONF_S **fline,
	struct variable ***varlistp, int *pp, int ln, int key)
{
   CONF_S *ctmpb = *clb;
   struct variable **varlist;
   int i, p = *pp;
   char tmp[1024], tmp2[16];

   sprintf(tmp2, "%d", key);
   varlist = *varlistp;

   new_confline(cl)->var = NULL;
   if(fline && !*fline) *fline = *cl;
   (*cl)->flags    |= CF_NOSELECT;
   (*cl)->help      = NO_HELP;
   (*cl)->valoffset = 1;
   (*cl)->value     = cpystr(x->name);
   (*cl)->varname   = NULL;
   (*cl)->varnamep  = ctmpb = *cl;

   /* Setup client-id variable */
   varlist[p] = fs_get(sizeof(struct variable));
   memset((void *) varlist[p], 0, sizeof(struct variable));
   varlist[p]->name = cpystr(XOAUTH2_CLIENT_ID);
   varlist[p]->is_used = 1;
   varlist[p]->is_user = 1;
   varlist[p]->main_user_val.p = x->client_id && y->client_id
		&& strcmp(x->client_id, y->client_id) ? cpystr(x->client_id) : NULL;
   varlist[p]->global_val.p = y->client_id ? cpystr(y->client_id) : NULL;
   varlist[p]->dname   = cpystr(tmp2);		/* hack, but makes life easier! */
   varlist[p]->descrip = cpystr(x->name);	/* hack, but makes life easier! */
   set_current_val(varlist[p], FALSE, FALSE);

   /* Write client-id variable */
   new_confline(cl)->var = varlist[p];
   utf8_snprintf(tmp, sizeof(tmp), "   %-*.100w =", ln, XOAUTH2_CLIENT_ID);
   tmp[sizeof(tmp)-1] = '\0';
   (*cl)->varname   = cpystr(tmp);
   (*cl)->varmem    = p++;
   (*cl)->valoffset = ln + 3 + 3;
   (*cl)->value     = pretty_value(ps_global, *cl);
   (*cl)->keymenu   = &config_xoauth2_text_keymenu;
   (*cl)->help      = h_config_xoauth2_client_id;
   (*cl)->tool      = text_tool;
   (*cl)->varnamep  = ctmpb;

   /* Set up client-secret variable */
   if(x->client_secret){
     varlist[p] = fs_get(sizeof(struct variable));
     memset((void *) varlist[p], 0, sizeof(struct variable));
     varlist[p]->name = cpystr(XOAUTH2_CLIENT_SECRET);
     varlist[p]->is_used = 1;
     varlist[p]->is_user = 1;
     varlist[p]->main_user_val.p = y->client_secret
		&& strcmp(x->client_secret, y->client_secret)
		? cpystr(x->client_secret) : NULL;
     varlist[p]->global_val.p = y->client_secret ? cpystr(y->client_secret) : NULL;
     varlist[p]->dname   = cpystr(tmp2);	/* hack, but makes life easier! */
     varlist[p]->descrip = cpystr(x->name);	/* hack, but makes life easier! */
     set_current_val(varlist[p], FALSE, FALSE);

     /* Write client-secret variable */
     new_confline(cl)->var = varlist[p];
     utf8_snprintf(tmp, sizeof(tmp), "   %-*.100w =", ln, XOAUTH2_CLIENT_SECRET);
     tmp[sizeof(tmp)-1] = '\0';
     (*cl)->varname   = cpystr(tmp);
     (*cl)->varmem    = p++;
     (*cl)->valoffset = ln + 3 + 3;
     (*cl)->value     = pretty_value(ps_global, *cl);
     (*cl)->keymenu   = &config_xoauth2_text_keymenu;
     (*cl)->help      = h_config_xoauth2_client_secret;
     (*cl)->tool      = text_tool;
     (*cl)->varnamep  = ctmpb;
   }

   /* Set up tenant variable */
   if(x->tenant){
     varlist[p] = fs_get(sizeof(struct variable));
     memset((void *) varlist[p], 0, sizeof(struct variable));
     varlist[p]->name = cpystr(XOAUTH2_TENANT);
     varlist[p]->is_used = 1;
     varlist[p]->is_user = 1;
     varlist[p]->main_user_val.p = y->tenant && strcmp(x->tenant, y->tenant)
		? cpystr(x->tenant) : NULL;
     varlist[p]->global_val.p = y->tenant ? cpystr(y->tenant) : NULL;
     varlist[p]->dname   = cpystr(tmp2);	/* hack, but makes life easier! */
     varlist[p]->descrip = cpystr(x->name);	/* hack, but makes life easier! */
     set_current_val(varlist[p], FALSE, FALSE);

     /* Write client-secret variable */
     new_confline(cl)->var = varlist[p];
     utf8_snprintf(tmp, sizeof(tmp), "   %-*.100w =", ln, XOAUTH2_TENANT);
     tmp[sizeof(tmp)-1] = '\0';
     (*cl)->varname   = cpystr(tmp);
     (*cl)->varmem    = p++;
     (*cl)->valoffset = ln + 3 + 3;
     (*cl)->value     = pretty_value(ps_global, *cl);
     (*cl)->keymenu   = &config_xoauth2_text_keymenu;
     (*cl)->help      = h_config_xoauth2_tenant;
     (*cl)->tool      = text_tool;
     (*cl)->varnamep  = ctmpb;
   }

   /* Set up flow variable */
   if(x->flow){
     varlist[p] = fs_get(sizeof(struct variable));
     memset((void *) varlist[p], 0, sizeof(struct variable));
     varlist[p]->name = cpystr(XOAUTH2_FLOW);
     varlist[p]->is_used = 1;
     varlist[p]->is_user = 1;
     varlist[p]->main_user_val.p = cpystr(x->flow);
     varlist[p]->global_val.p = cpystr(x->flow);
     varlist[p]->dname   = cpystr(tmp2);	/* hack, but makes life easier! */
     varlist[p]->descrip = cpystr(x->name);	/* hack, but makes life easier! */
     set_current_val(varlist[p], FALSE, FALSE);

     /* Write client-secret variable */
     new_confline(cl)->var = varlist[p];
     utf8_snprintf(tmp, sizeof(tmp), "   %-*.100w =", ln, XOAUTH2_FLOW);
     tmp[sizeof(tmp)-1] = '\0';
     (*cl)->varname   = cpystr(tmp);
     (*cl)->varmem    = p++;
     (*cl)->valoffset = ln + 3 + 3;
     (*cl)->value     = pretty_value(ps_global, *cl);
     (*cl)->keymenu   = &config_xoauth2_text_keymenu;
     (*cl)->help      = h_config_xoauth2_flow;
     (*cl)->tool      = text_tool;
     (*cl)->varnamep  = ctmpb;
   }

   /* Setup users variable */
   varlist[p] = fs_get(sizeof(struct variable));
   memset((void *) varlist[p], 0, sizeof(struct variable));
   varlist[p]->name = cpystr(XOAUTH2_USERS);
   varlist[p]->is_used = 1;
   varlist[p]->is_user = 1;
   varlist[p]->is_list = 1;
   varlist[p]->main_user_val.l = x->users ? array_to_list(x->users) : NULL;
   varlist[p]->dname   = cpystr(tmp2);		/* hack, but makes life easier! */
   varlist[p]->descrip = cpystr(x->name);	/* hack, but makes life easier! */
   set_current_val(varlist[p], FALSE, FALSE);

   /* Write user variable */
   new_confline(cl)->var = varlist[p];
   utf8_snprintf(tmp, sizeof(tmp), "   %-*.100w =", ln, XOAUTH2_USERS);
   tmp[sizeof(tmp)-1] = '\0';
   (*cl)->varname   = cpystr(tmp);
   (*cl)->valoffset = ln + 3 + 3;
   (*cl)->keymenu   = &config_xoauth2_wshuf_keymenu;
   (*cl)->help      = h_config_xoauth2_username;
   if(x->users){
      int z;
      for(z = 0; varlist[p]->main_user_val.l[z]; z++){
	if(z) new_confline(cl);
	(*cl)->var       = varlist[p];
	(*cl)->varmem    = z;
	(*cl)->valoffset = ln + 3 + 3;
	(*cl)->value     = pretty_value(ps_global, *cl);
	(*cl)->keymenu   = &config_xoauth2_wshuf_keymenu;
	(*cl)->tool      = text_tool;
	(*cl)->varnamep  = ctmpb = *cl;
      }
   }
   else {
	(*cl)->varmem = 0;
	(*cl)->value = pretty_value(ps_global, *cl);
	(*cl)->keymenu = &config_xoauth2_wshuf_keymenu;
	(*cl)->tool    = text_tool;
	(*cl)->varnamep  = ctmpb = *cl;
   }
   p++;
   *pp = p;
   *varlistp = varlist;
   *clb = ctmpb;

   /* Separate servers with a blank line */
   new_confline(cl);
   (*cl)->flags    |= CF_NOSELECT | CF_B_LINE;
}

/*----------------------------------------------------------------------
  Screen to add client_id and client_secret for a service

  ---*/
void
alpine_xoauth2_configuration(struct pine *ps, int edit_exceptions)
{
    struct variable **varlist = NULL;
    char	    tmp[MAXPATH+1], *pval, **lval, ***alval;
    char	    *s, *extraname = NULL;
    char	    *name, *id, *tenant, *secret, **user;
    char	    *name_lval, *id_lval, *tenant_lval, *secret_lval, *user_lval,
		    *id_def, *tenant_def, *secret_def;
    int		    i, j, k, l, p, q, ln = 0, readonly_warning = 0, pos, count_vars;
    XTYPES	    m;
    CONF_S	   *ctmpa = NULL, *ctmpb, *first_line;
    FEATURE_S	   *feature;
    PINERC_S       *prc = NULL;
    OPT_SCREEN_S    screen;
    int             expose_hidden_config, add_hidden_vars_title = 0;
    SAVED_CONFIG_S *vsave;
    XOAUTH2_INFO_S  x, *y;

    dprint((3, "--  alpine_xoauth2_configuration --\n"));

    expose_hidden_config = F_ON(F_EXPOSE_HIDDEN_CONFIG, ps_global);
    ew = edit_exceptions ? ps_global->ew_for_except_vars : Main;

    if(ps->restricted)
      readonly_warning = 1;
    else{
	switch(ew){
	  case Main:
	    prc = ps->prc;
	    break;
	  case Post:
	    prc = ps->post_prc;
	    break;
	  default:
	    break;
	}

	readonly_warning = prc ? prc->readonly : 1;
    }

    ps->next_screen = SCREEN_FUN_NULL;

    mailcap_free(); /* free resources we won't be using for a while */

    pos = -1;
    for(ln = 0, m = Xid; m < Xend; m++){
	i = strlen(x_default[m].screen_name);
	if(ln < i) ln = i;
    }

    alval = ALVAL(&ps->vars[V_XOAUTH2_INFO], ew);
    lval = *alval = xoauth2_conf_dedup_and_merge(alval);
    set_current_val(&ps_global->vars[V_XOAUTH2_INFO], FALSE, FALSE);
    write_pinerc(ps_global, ew, WRP_NONE);

    do {
        ctmpa = first_line = NULL;

        for(i = 0, count_vars = 0; xoauth_default[i].name != NULL; i++){
	   /* always start with the default configuration */
	   for(k = 0, q = 0; lval && lval[k]; k++){
		y = xoauth_parse_client_info(lval[k]);
		if(same_xoauth2_info(xoauth_default[i], *y))
		   break;
		free_xoauth2_info(&y);
	   }
	   if(lval == NULL || lval[k] == NULL){
		count_vars += 3;
		if(xoauth_default[i].client_secret) count_vars++;
		if(xoauth_default[i].tenant) count_vars++;
	   }
	   for(k = 0; lval && lval[k]; k++){
	      y = xoauth_parse_client_info(lval[k]);
	      if(y && (!y->name || strcmp(y->name, xoauth_default[i].name))){
		free_xoauth2_info(&y);
		continue;
	      }
	      count_vars += 3;
	      if(xoauth_default[i].client_secret != NULL) count_vars++;
	      if(xoauth_default[i].tenant != NULL) count_vars++;
	      free_xoauth2_info(&y);
	   }
	}

	for(i = 0; varlist && varlist[i]; i++){
	    free_variable_values(varlist[i]);
	    if(varlist[i]->descrip) fs_give((void **) &varlist[i]->descrip);
	    if(varlist[i]->dname) fs_give((void **) &varlist[i]->dname);
	    fs_give((void **) &varlist[i]);
	}
	if(varlist) fs_give((void **) varlist);

	varlist = fs_get((count_vars + 1)*sizeof(struct variable *));
	memset((void *) varlist, 0, (count_vars +1)*sizeof(struct variable *));

        for(i = 0, p = 0; xoauth_default[i].name != NULL; i++){
	   /* always start with the default configuration */
	   for(k = 0, q = 0; lval && lval[k]; k++){
		y = xoauth_parse_client_info(lval[k]);
		if(same_xoauth2_info(xoauth_default[i], *y))
		   break;
		free_xoauth2_info(&y);
	   }
	   if(lval == NULL || lval[k] == NULL){
	       OAUTH2_S *oa2list;
	       for(oa2list = alpine_oauth2_list; oa2list && oa2list->name; oa2list++){
		  if(oa2list->hide) continue;
		  if(!strcmp(oa2list->name,xoauth_default[i].name)){
		     xoauth_default[i].flow = cpystr(oa2list->server_mthd[0].name ? "Authorize"
                      : (oa2list->server_mthd[1].name ? "Device" : "Unknown"));
		     write_xoauth_conf_entry(&xoauth_default[i], &xoauth_default[i], &ctmpa, &ctmpb,
						&first_line, &varlist, &p, ln, -i-1);
		     fs_give((void **) &xoauth_default[i].flow);
		     break;	/* just one entry, set the default to the first entry */
		  }
	       }
	   }
	   for(k = 0, q = 0; lval && lval[k]; k++){
	      OAUTH2_S *oa2list, *oa2;

	      y = xoauth_parse_client_info(lval[k]);
	      if(y && (!y->name || strcmp(y->name, xoauth_default[i].name))){
		free_xoauth2_info(&y);
		continue;
	      }
	      if(y->client_id == NULL)
		 y->client_id = cpystr(xoauth_default[i].client_id);
	      if(y->client_secret == NULL && xoauth_default[i].client_secret != NULL)
		 y->client_secret = cpystr(xoauth_default[i].client_secret);
	      if(y->tenant == NULL && xoauth_default[i].tenant != NULL)
		 y->tenant = cpystr(xoauth_default[i].tenant);
	      for(oa2 = NULL, oa2list = alpine_oauth2_list; oa2 == NULL && oa2list; oa2list++)
		 if(!strcmp(oa2list->name, y->name)) oa2 = oa2list;
	      if(oa2 && y->flow == NULL)
		y->flow = cpystr(oa2->server_mthd[0].name ? "Authorize"
                      : (oa2->server_mthd[1].name ? "Device" : "Unknown"));
	      if(oa2 && !oa2->hide)
		write_xoauth_conf_entry(y, &xoauth_default[i], &ctmpa, &ctmpb, &first_line, &varlist, &p, ln, k);
	      free_xoauth2_info(&y);
	   }
	}

	vsave = save_config_vars(ps, expose_hidden_config);
	first_line = pos < 0 ? first_sel_confline(first_line) : set_confline_number(first_line, pos);
	pos = -1;
	memset(&screen, 0, sizeof(screen));
	screen.ro_warning = readonly_warning;
	/* TRANSLATORS: Print something1 using something2.
	"configuration" is something1 */
	switch(conf_scroll_screen(ps, &screen, first_line, "XOAUTH2 Alpine Info",
				      _("configuration"), 0, &pos)){
	      case 0:
		break;

	      case 1:
		write_xoauth_configuration(&ps->vars[V_XOAUTH2_INFO], varlist, ew);
		write_pinerc(ps, ew, WRP_NONE);
		break;

	      case 4:				/* add a service */
		{char service[MAILTMPLEN+1];
		 char prompt[MAILTMPLEN+1];
		 int flags = OE_DISALLOW_HELP;
		 strncpy(prompt, _("Enter service name: "), sizeof(prompt));
		 prompt[sizeof(prompt) - 1] = '\0';
		 service[0] = '\0';
		 if(optionally_enter(service,
                        -(ps_global->ttyo ? FOOTER_ROWS(ps_global) : 3),
                         0, sizeof(service), prompt, NULL, NO_HELP, &flags) == 0){
		    for(i = 0; xoauth_default[i].name != NULL && strucmp(xoauth_default[i].name, service); i++);
		    if(xoauth_default[i].name == NULL)
			q_status_message1(SM_ORDER, 3, 3, _("Service %s not known"), service);
		    else{
			char **list;
			ClearScreen();
			ps_global->mangled_screen = 1;
			for(j = 0; lval && lval[j]; j++);
			list = fs_get((j+2)*sizeof(char *));
			memset((void *)list, 0, (j+2)*sizeof(char *));
			list[0] = xoauth_config_line(&xoauth_default[i]);
			for(i = 0; lval && lval[i]; i++)
			   list[i+1] = cpystr(lval[i]);
			if(lval) free_list_array(&lval);
			*alval = lval = list;
			for(i = 0; varlist && varlist[i]; i++){
			   free_variable_values(varlist[i]);
			   if(varlist[i]->descrip) fs_give((void **) &varlist[i]->descrip);
			   if(varlist[i]->dname) fs_give((void **) &varlist[i]->dname);
			   fs_give((void **) &varlist[i]);
			}
			if(varlist) fs_give((void **) varlist);
		    }
		 }
		}
		break;

	      case 5:				/* delete a service */
		{ int m, key;
		  XOAUTH2_INFO_S *x;
		  char question[MAILTMPLEN];

		   for(i = 0, m = 1, j = 0; varlist[i] && m < pos;)
			if(!varlist[i]->is_list){
			   i++; m++;
			} else {
			    if(varlist[i]->current_val.l[j++]) m++;
			    else{
				j = 0; m += 2; i++;
			    }
			}
		   key = atoi(varlist[i]->dname);	/* this hack avoids we rebuild varlist again */
		   if(key >= 0){
			x = xoauth_parse_client_info(lval[key]);
			snprintf(question, sizeof(question), _("Delete this configuration for %s "), x->name);
			free_xoauth2_info(&x);
			if(want_to(question, 'n', 'n', NO_HELP, WT_NORM) != 'y')
			   break;
		        for(i = key; lval && lval[i] && lval[i+1]; i++){
			   fs_give((void **) &lval[i]);
			   lval[i] = cpystr(lval[i+1]);
			}
			fs_give((void **) &lval[i]);
		   }
		   else {
			q_status_message(SM_ORDER, 3, 3, _("Cannot delete default configuration"));
			break;
		   }
		   if(lval && lval[0] == NULL)
		     free_list_array(&lval);
		   *alval = lval;
		   pos = 1;	/* reset at the top */
		   for(i = 0; varlist && varlist[i]; i++){
		       free_variable_values(varlist[i]);
		       if(varlist[i]->descrip) fs_give((void **) &varlist[i]->descrip);
		       if(varlist[i]->dname) fs_give((void **) &varlist[i]->dname);
		       fs_give((void **) &varlist[i]);
		   }
		   if(varlist) fs_give((void **) varlist);
		}
		break;

	      case 10:
		revert_to_saved_config(ps, vsave, expose_hidden_config);
		if(prc)
		  prc->outstanding_pinerc_changes = 0;
		break;
      
	      default:
		q_status_message(SM_ORDER,7,10,
		    "conf_scroll_screen bad ret, not supposed to happen");
		break;
	}
    } while (pos >= 0);

#ifdef _WINDOWS
    mswin_set_quit_confirm (F_OFF(F_QUIT_WO_CONFIRM, ps_global));
#endif
}
