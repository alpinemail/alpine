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
#include "xoauth2.h"
#include "keymenu.h"
#include "status.h"
#include "confscroll.h"
#include "../pith/state.h"
#include "../pith/conf.h"
#include "../pith/list.h"

extern OAUTH2_S alpine_oauth2_list[];

XOAUTH2_INFO_S xoauth_default[] = {
  { GMAIL_NAME, GMAIL_ID, GMAIL_SECRET},
#if 0
  { OUTLOOK_NAME, OUTLOOK_ID, OUTLOOK_SECRET},
#endif
  { NULL, NULL, NULL}
};


#define NXSERVERS (sizeof(xoauth_default)/sizeof(xoauth_default[0])-1)
#define XOAUTH2_CLIENT_ID       _("Client-Id")
#define XOAUTH2_CLIENT_SECRET   _("Client-Secret")
#define XNAME			"/NAME="
#define XID			"/ID="
#define XSECRET			"/SECRET="

void write_xoauth_configuration(struct variable  *, struct variable **, EditWhich);

char *
xoauth_config_line(char *server, char *id, char *secret)
{
  size_t n;
  char *rv;

  n = strlen(XNAME) + strlen(XID) + strlen(XSECRET) 
	    + strlen(server) + strlen(id) + strlen(secret) + 9;
  rv = fs_get(n*sizeof(char));
  sprintf(rv, "%s\"%s\" %s\"%s\" %s\"%s\"", XNAME, server, XID, id, 
						XSECRET, secret);
  return rv;
}

/* call this function when id and secret are unknown.
 * precedence is as follows:
 * If the user has configured something, return that;
 * else if we are already using a value, return that;
 * else return default values.
 */
void
oauth2_get_client_info(char *name, char **id, char **secret)
{
  int i;
  char **lval, *name_lval, *idp, *secretp;

  *id = *secret = NULL;

  /* first check the value configured by the user */
  lval = ps_global->vars[V_XOAUTH2_INFO].current_val.l;
  for(i = 0; lval && lval[i]; i++){
     xoauth_parse_client_info(lval[i], &name_lval, &idp, &secretp);
     if(name_lval && !strcmp(name_lval, name)){
	*id = idp ? cpystr(idp) : NULL;
	*secret = secretp ? cpystr(secretp) : NULL;
     }
     if(name_lval) fs_give((void **) &name_lval);
     if(idp) fs_give((void **) &idp);
     if(secretp) fs_give((void **) &secretp);
     break;
  }

  if(*id && **id && *secret && **secret) return;

  /* if not, now see if we already have a value set, and use that */
  for(i = 0; alpine_oauth2_list[i].name != NULL; i++){
     if(!strcmp(alpine_oauth2_list[i].name, name)){
        *id = alpine_oauth2_list[i].param[OA2_Id].value 
		? cpystr(alpine_oauth2_list[i].param[OA2_Id].value) : NULL;
        *secret = alpine_oauth2_list[i].param[OA2_Secret].value
		? cpystr(alpine_oauth2_list[i].param[OA2_Secret].value) : NULL;
	break;
     }
  }

  if(*id && **id && *secret && **secret) return;

  /* if nothing, use the default value */
  for(i = 0; xoauth_default[i].name != NULL; i++)
     if(!strcmp(xoauth_default[i].name, name)){
        *id = cpystr(xoauth_default[i].client_id);
        *secret = cpystr(xoauth_default[i].client_secret);
	break;
     }
}

/* write vlist to v 
 * Each vlist member is of type "p", while "v" is of type "l", so we
 * each entry in "l" by using each of the "p" entries.
 */
void
write_xoauth_configuration(struct variable  *v, struct variable **vlist, EditWhich ew)
{
  int i, j, k;
  size_t n;
  char ***alval, **lval, *p, *q, *l;

  alval  = ALVAL(v, ew);
  for (i = 0, k = 0; vlist[i] != NULL;){
      if(PVAL(vlist[i], ew)){
	j = i/2;	/* this is the location in the alpine_oauth2_list array */
	i = 2*j;	/* reset i */
	p = PVAL(vlist[i], ew);
	if(p == NULL) p = vlist[i]->current_val.p;
	q = PVAL(vlist[i+1], ew);
	if(q == NULL) q = vlist[i+1]->current_val.p;
	if(k == 0) lval = fs_get((NXSERVERS +1)*sizeof(char *));
	lval[k++] = xoauth_config_line(alpine_oauth2_list[j].name, p, q);
	if(alpine_oauth2_list[j].param[OA2_Id].value)
	   fs_give((void **) &alpine_oauth2_list[j].param[OA2_Id].value);
	if(alpine_oauth2_list[j].param[OA2_Secret].value)
	   fs_give((void **) &alpine_oauth2_list[j].param[OA2_Secret].value);
	alpine_oauth2_list[j].param[OA2_Id].value = cpystr(p);
	alpine_oauth2_list[j].param[OA2_Secret].value = cpystr(q);
	i += 2;
      }
      else i++;
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
  /NAME="text" /ID="text" /SECRET="text"
 */
void
xoauth_parse_client_info(char *lvalp, char **namep, char **idp, char **secretp)
{
  char *s, *t, c;
  *namep = *idp = *secretp = NULL;

  if (lvalp == NULL) return;

  if((s = strstr(lvalp, XNAME)) != NULL){
	s += strlen(XNAME);
	if(*s == '"') s++;
	for(t = s; *t && *t != '"' && *t != ' '; t++);
	c = *t;
	*t = '\0';
	*namep = cpystr(s);
	*t = c;
  }

  if((s = strstr(lvalp, XID)) != NULL){
	s += strlen(XID);
	if(*s == '"') s++;
	for(t = s; *t && *t != '"' && *t != ' '; t++);
	c = *t;
	*t = '\0';
	*idp = cpystr(s);
	*t = c;
  }

  if((s = strstr(lvalp, XSECRET)) != NULL){
	s += strlen(XSECRET);
	if(*s == '"') s++;
	for(t = s; *t && *t != '"' && *t != ' '; t++);
	c = *t;
	*t = '\0';
	*secretp = cpystr(s);
	*t = c;
  }
}


/*----------------------------------------------------------------------
  Screen to add client_id and client_secret for a service

  ---*/
void
alpine_xoauth2_configuration(struct pine *ps, int edit_exceptions)
{
    struct variable gmail_client_id_var, gmail_client_secret_var;
#if 0
    struct variable outlook_client_id_var, outlook_client_secret_var;
#endif
    struct variable *varlist[2*NXSERVERS + 1];
    char	    tmp[MAXPATH+1], *pval, **lval;
    char	    *id, *secret;
    char	    *name_lval, *id_lval, *id_conf, *id_def, *secret_lval, *secret_conf, *secret_def;
    int		    i, j, k, l, ln = 0, readonly_warning = 0, pos;
    CONF_S	   *ctmpa = NULL, *ctmpb, *first_line = NULL;
    FEATURE_S	   *feature;
    PINERC_S       *prc = NULL;
    OPT_SCREEN_S    screen;
    int             expose_hidden_config, add_hidden_vars_title = 0;
    SAVED_CONFIG_S *vsave;

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

    varlist[0] = &gmail_client_id_var;
    varlist[1] = &gmail_client_secret_var;
#if 0
    varlist[2] = &outlook_client_id_var;
    varlist[3] = &outlook_client_secret_var;
#endif
    varlist[2*NXSERVERS] = NULL;

    for(i = 0; i < 2*NXSERVERS; i++)
      memset((void *) varlist[i], 0, sizeof(struct variable));

    pos = -1;
    do {
        ctmpa = first_line = NULL;

        ln = strlen(XOAUTH2_CLIENT_ID);
        i = strlen(XOAUTH2_CLIENT_SECRET);
        if(ln < i) ln = i;

	lval  = LVAL(&ps->vars[V_XOAUTH2_INFO], ew);

        for(i = 0, l = 0; alpine_oauth2_list[i].name != NULL; i++){
	   id_conf = id_def = secret_conf = secret_def = NULL;
	   name_lval = id_lval = secret_lval = NULL;

	   id_conf = alpine_oauth2_list[i].param[OA2_Id].value;
	   secret_conf = alpine_oauth2_list[i].param[OA2_Secret].value;

	   for(j = 0; xoauth_default[j].name != NULL; j++)
	      if(!strcmp(alpine_oauth2_list[i].name, xoauth_default[j].name))
		break;

	   if(xoauth_default[j].name != NULL){
	     id_def = xoauth_default[j].client_id;
	     secret_def = xoauth_default[j].client_secret;
	   }

	   /* fix this: the purpose is to search for the name in lval */
	   for(k = 0; lval && lval[k]; k++){
	      xoauth_parse_client_info(lval[k], &name_lval, &id_lval, &secret_lval);
	      if(name_lval && !strcmp(name_lval, alpine_oauth2_list[i].name))
		break;
	      if (name_lval) fs_give((void **) &name_lval);
	      if (id_lval) fs_give((void **) &id_lval);
	      if (secret_lval) fs_give((void **) &secret_lval);
	   }

	   /* Here we have three values. The one being used by c-client in
	    * id_conf, secret_conf. The default value in Alpine, obtained
	    * by the programmer by registering Alpine, and the value
	    * configured in Alpine by the user in id_lval, and secret_lval.
	    *
	    * The rules are:
	    *  1. If id_lval && secret_lval are not null, we use those.
	    *  2. else we use the default values.
	    */
	    id = id_lval ? id_lval : id_def;
	    secret = secret_lval ? secret_lval : secret_def;

	   new_confline(&ctmpa)->var = NULL;
	   if(!first_line) first_line = ctmpa;

	   /*  Write Name of provider first */
	   ctmpa->flags	    |= CF_NOSELECT;
	   ctmpa->help	     = NO_HELP;
	   ctmpa->valoffset  = 1;
	   ctmpa->value	     = cpystr(alpine_oauth2_list[i].name);
	   ctmpa->varname  = NULL;
           ctmpa->varnamep = ctmpb = ctmpa;


	   /* Setup client-id variable */
	   varlist[l]->name = cpystr(XOAUTH2_CLIENT_ID);
	   varlist[l]->is_used = 1;
	   varlist[l]->is_user = 1;
	   varlist[l]->main_user_val.p = strcmp(id, id_def)? cpystr(id) : NULL;
	   varlist[l]->global_val.p = cpystr(id_def);
	   set_current_val(varlist[l], FALSE, FALSE);

	   /* Write client-id variable */
	   new_confline(&ctmpa)->var = varlist[l];
	   utf8_snprintf(tmp, sizeof(tmp), "   %-*.100w =", ln, XOAUTH2_CLIENT_ID);
	   tmp[sizeof(tmp)-1] = '\0';
	   ctmpa->varname   = cpystr(tmp);
	   ctmpa->varmem    = l++;
	   ctmpa->valoffset = ln + 3 + 3;
	   ctmpa->value     = pretty_value(ps, ctmpa);
	   ctmpa->keymenu   = &config_text_keymenu;
	   ctmpa->help      = h_config_xoauth2_client_id;
	   ctmpa->tool      = text_tool;
	   ctmpa->varnamep  = ctmpb;

	   /* Set up client-secret variable */
	   varlist[l]->name = cpystr(XOAUTH2_CLIENT_SECRET);
	   varlist[l]->is_used = 1;
	   varlist[l]->is_user = 1;
	   varlist[l]->main_user_val.p = strcmp(secret, secret_def) ? cpystr(secret) : NULL;
	   varlist[l]->global_val.p = cpystr(secret_def);
	   set_current_val(varlist[l], FALSE, FALSE);

	   /* Write client-secret variable */
	   new_confline(&ctmpa)->var = varlist[l];
	   utf8_snprintf(tmp, sizeof(tmp), "   %-*.100w =", ln, XOAUTH2_CLIENT_SECRET);
	   tmp[sizeof(tmp)-1] = '\0';
	   ctmpa->varname   = cpystr(tmp);
	   ctmpa->varmem    = l++;
	   ctmpa->valoffset = ln + 3 + 3;
	   ctmpa->value     = pretty_value(ps, ctmpa);
	   ctmpa->keymenu   = &config_text_keymenu;
	   ctmpa->help      = h_config_xoauth2_client_secret;
	   ctmpa->tool      = text_tool;
	   ctmpa->varnamep  = ctmpb;

	   /* Separate servers with a blank line */
	   new_confline(&ctmpa);
	   ctmpa->flags    |= CF_NOSELECT | CF_B_LINE;

	   /* clean up the house */
	   if(id_lval) fs_give((void **) &id_lval);
	   if(secret_lval) fs_give((void **) &secret_lval);
	   if(name_lval) fs_give((void **) &name_lval);
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

