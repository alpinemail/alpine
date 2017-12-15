/*
 * ========================================================================
 * Copyright 2013-2017 Eduardo Chappa
 * Copyright 2008 University of Washington
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

#include "titlebar.h"

static struct headerentry headents_templ[]={
  /* TRANSLATORS: these are the headings for setting up a collection of
     folders, PATH is a filesystem path, VIEW is sort of a technical
     term that can be used to restrict the View to fewer folders */
  {"Nickname  : ",  N_("Nickname"),  h_composer_cntxt_nick, 12, 0, NULL,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, KS_NONE},
  {"Server    : ",  N_("Server"),  h_composer_cntxt_server, 12, 0, NULL,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, KS_NONE},
  {"Path      : ",  N_("Path"),  h_composer_cntxt_path, 12, 0, NULL,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, KS_NONE},
  {"View      : ",  N_("View"),  h_composer_cntxt_view, 12, 0, NULL,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, KS_NONE},
  {NULL, NULL, NO_HELP, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, KS_NONE}
};
#define	AC_NICK	0
#define	AC_SERV	1
#define	AC_PATH	2
#define	AC_VIEW	3

void
ical_compose_reply(char *url)
{


//char *
//context_edit_screen(struct pine *ps, char *func, char *def_nick,
//		    char *def_serv, char *def_path, char *def_view)
//{
    int	       editor_result, i, j;
    char       servpart[MAILTMPLEN], new_cntxt[MAILTMPLEN];
    char       pathpart[MAILTMPLEN], allbutnick[MAILTMPLEN];
    char       tmp[MAILTMPLEN], *nick, *serv, *path, *view,
	      *return_cntxt = NULL, *val, *p;
    char       nickpmt[100], servpmt[100], pathpmt[100], viewpmt[100];
    int        indent;
    PICO       pbf;
    STORE_S   *msgso;
    NETMBX     mb;

    standard_picobuf_setup(&pbf);
    pbf.pine_flags   |= P_NOBODY;
    pbf.exittest      = exit_collection_add;
    pbf.canceltest    = (func && !strucmp(func, "EDIT")) ? cancel_collection_edit
							 : cancel_collection_add;
    pbf.pine_anchor   = set_titlebar(_("CALENDAR EVENT"), 
				      ps_global->mail_stream,
				      ps_global->context_current,
				      ps_global->cur_folder,ps_global->msgmap, 
				      0, FolderName, 0, 0, NULL);

    /* An informational message */
    if((msgso = so_get(PicoText, NULL, EDIT_ACCESS)) != NULL){
	pbf.msgtext = (void *) so_text(msgso);
	so_puts(msgso,
       _("\n   Fill in the fields above to add a Folder Collection to your"));
	so_puts(msgso,
       _("\n   COLLECTION LIST screen."));
	so_puts(msgso,
       _("\n   Use the \"^G\" command to get help specific to each item, and"));
	so_puts(msgso,
       _("\n   use \"^X\" when finished."));
    }


    pbf.headents = (struct headerentry *)fs_get((sizeof(headents_templ)
						  /sizeof(struct headerentry))
						 * sizeof(struct headerentry));
    memset((void *) pbf.headents, 0,
	   (sizeof(headents_templ)/sizeof(struct headerentry))
	   * sizeof(struct headerentry));

    for(i = 0; headents_templ[i].prompt; i++)
      pbf.headents[i] = headents_templ[i];

    indent = utf8_width(_("Nickname")) + 2;

    nick = cpystr(def_nick ? def_nick : "");
    pbf.headents[AC_NICK].realaddr = &nick;
    pbf.headents[AC_NICK].maxlen   = strlen(nick);
    utf8_snprintf(nickpmt, sizeof(nickpmt), "%-*.*w: ", indent, indent, _("Nickname"));
    pbf.headents[AC_NICK].prompt   = nickpmt;
    pbf.headents[AC_NICK].prwid    = indent+2;

    serv = cpystr(def_serv ? def_serv : "");
    pbf.headents[AC_SERV].realaddr = &serv;
    pbf.headents[AC_SERV].maxlen   = strlen(serv);
    utf8_snprintf(servpmt, sizeof(servpmt), "%-*.*w: ", indent, indent, _("Server"));
    pbf.headents[AC_SERV].prompt   = servpmt;
    pbf.headents[AC_SERV].prwid    = indent+2;

    path = cpystr(def_path ? def_path : "");
    pbf.headents[AC_PATH].realaddr = &path;
    pbf.headents[AC_PATH].maxlen   = strlen(path);
    pbf.headents[AC_PATH].bldr_private = (void *) 0;
    utf8_snprintf(pathpmt, sizeof(pathpmt), "%-*.*w: ", indent, indent, _("Path"));
    pbf.headents[AC_PATH].prompt   = pathpmt;
    pbf.headents[AC_PATH].prwid    = indent+2;

    view = cpystr(def_view ? def_view : "");
    pbf.headents[AC_VIEW].realaddr = &view;
    pbf.headents[AC_VIEW].maxlen   = strlen(view);
    utf8_snprintf(viewpmt, sizeof(viewpmt), "%-*.*w: ", indent, indent, _("View"));
    pbf.headents[AC_VIEW].prompt   = viewpmt;
    pbf.headents[AC_VIEW].prwid    = indent+2;

    /*
     * If this is new context, setup to query IMAP server
     * for location of personal namespace.
     */
    if(!(def_nick || def_serv || def_path || def_view)){
	pbf.headents[AC_SERV].builder	      = build_namespace;
	pbf.headents[AC_SERV].affected_entry = &pbf.headents[AC_PATH];
	pbf.headents[AC_SERV].bldr_private   = (void *) 0;
    }

    /* pass to pico and let user change them */
    editor_result = pico(&pbf);

    if(editor_result & COMP_GOTHUP){
	hup_signal();
    }
    else{
	fix_windsize(ps_global);
	init_signals();
    }

    if(editor_result & COMP_CANCEL){
	cmd_cancelled(func);
    }
    else if(editor_result & COMP_EXIT){
	servpart[0] = pathpart[0] = new_cntxt[0] = allbutnick[0] = '\0';
	if(serv && *serv){
	    if(serv[0] == '{'  && serv[strlen(serv)-1] == '}'){
		strncpy(servpart, serv, sizeof(servpart)-1);
		servpart[sizeof(servpart)-1] = '\0';
	    }
	    else
	      snprintf(servpart, sizeof(servpart), "{%s}", serv);

	    if(mail_valid_net_parse(servpart, &mb)){
		if(!struncmp(mb.service, "nntp", 4)
		   && (!path || strncmp(path, "#news.", 6)))
		  strncat(servpart, "#news.", sizeof(servpart)-1-strlen(servpart));
	    }
	    else
	      alpine_panic("Unexpected invalid server");
	}
	else
	  servpart[0] = '\0';

	servpart[sizeof(servpart)-1] = '\0';

	new_cntxt[0] = '\0';
	if(nick && *nick){
	    val = quote_if_needed(nick);
	    if(val){
		strncpy(new_cntxt, val, sizeof(new_cntxt)-2);
		new_cntxt[sizeof(new_cntxt)-2] = '\0';
		if(val != nick)
		  fs_give((void **)&val);
	    
		strncat(new_cntxt, " ", sizeof(new_cntxt)-strlen(new_cntxt)-1);
		new_cntxt[sizeof(new_cntxt)-1] = '\0';
	    }
	}

	p = allbutnick;
	sstrncpy(&p, servpart, sizeof(allbutnick)-1-(p-allbutnick));
	allbutnick[sizeof(allbutnick)-1] = '\0';

	if(path){
	    val = quote_brackets_if_needed(path);
	    if(val){
		strncpy(pathpart, val, sizeof(pathpart)-1);
		pathpart[sizeof(pathpart)-1] = '\0';
		if(val != path)
		  fs_give((void **)&val);
	    }

	    if(pbf.headents[AC_PATH].bldr_private != (void *) 0){
		strncat(pathpart, (char *) pbf.headents[AC_PATH].bldr_private,
			sizeof(pathpart)-strlen(pathpart)-1);
		pathpart[sizeof(pathpart)-1] = '\0';
	    }
	}

	sstrncpy(&p, pathpart, sizeof(allbutnick)-1-(p-allbutnick));
	allbutnick[sizeof(allbutnick)-1] = '\0';

	if(view[0] != '[' && sizeof(allbutnick)-1-(p-allbutnick) > 0){
	    *p++ = '[';
	    *p = '\0';
	}

	sstrncpy(&p, view, sizeof(allbutnick)-1-(p-allbutnick));
	allbutnick[sizeof(allbutnick)-1] = '\0';
	if((j=strlen(view)) < 2 || (view[j-1] != ']' &&
	   sizeof(allbutnick)-1-(p-allbutnick) > 0)){
	    *p++ = ']';
	    *p = '\0';
	}

	val = quote_if_needed(allbutnick);
	if(val){
	    strncat(new_cntxt, val, sizeof(new_cntxt)-1-strlen(new_cntxt));
	    new_cntxt[sizeof(new_cntxt)-1] = '\0';

	    if(val != allbutnick)
	      fs_give((void **)&val);
	}

	return_cntxt = cpystr(new_cntxt);
    }

    for(i = 0; headents_templ[i].prompt; i++)
      fs_give((void **) pbf.headents[i].realaddr);

    if(pbf.headents[AC_PATH].bldr_private != (void *) 0)
      fs_give(&pbf.headents[AC_PATH].bldr_private);

    fs_give((void **) &pbf.headents);

    standard_picobuf_teardown(&pbf);

    if(msgso)
      so_give(&msgso);

    return(return_cntxt);
}

