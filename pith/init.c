#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: init.c 769 2007-10-24 00:15:40Z hubert@u.washington.edu $";
#endif

/*
 * ========================================================================
 * Copyright 2013-2018 Eduardo Chappa
 * Copyright 2006-2007 University of Washington
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
     init.c
     Routines for pine start up and initialization
  ====*/


#include "../pith/headers.h"
#include "../pith/init.h"
#include "../pith/conf.h"
#include "../pith/status.h"
#include "../pith/folder.h"
#include "../pith/readfile.h"
#include "../pith/pattern.h"

/*
 * Internal prototypes
 */
int	 compare_sm_files(const qsort_t *, const qsort_t *);

#ifdef ALPINE_USE_CONFIG_DIR
#include "../pith/tempfile.h"
#include "../pith/remote.h"
int	 create_root_path(char *);
int	 transfer_to_config_dir(char *);
int	 transfer_copy_file(char *, char *, int *);
int	 transfer_copy_link(char *, char *, int *);
int	 transfer_copy_dir(char *, char *, int *);
#endif /* ALPINE_USE_CONFIG_DIR */


/*----------------------------------------------------------------------
    Sets  login, full_username and home_dir

   Args: ps -- The Pine structure to put the user name, etc in

  Result: sets the fullname, login and home_dir field of the pine structure
          returns 0 on success, -1 if not.
  ----*/

int
init_username(struct pine *ps)
{
    char *expanded;
    int	  rv;

    rv       = 0;
    expanded = NULL;
#if defined(DOS) || defined(OS2)
    if(ps->COM_USER_ID)
      expanded = expand_variables(tmp_20k_buf, SIZEOF_20KBUF,
				  ps->COM_USER_ID, 0);
    
    if(!expanded && ps->vars[V_USER_ID].post_user_val.p)
      expanded = expand_variables(tmp_20k_buf, SIZEOF_20KBUF,
				  ps->vars[V_USER_ID].post_user_val.p, 0);

    if(!expanded && ps->vars[V_USER_ID].main_user_val.p)
      expanded = expand_variables(tmp_20k_buf, SIZEOF_20KBUF,
				  ps->vars[V_USER_ID].main_user_val.p, 0);

    if(!expanded)
      ps->blank_user_id = 1;

    ps->VAR_USER_ID = cpystr(expanded ? expanded : "");
#else
    ps->VAR_USER_ID = cpystr(ps->ui.login);
    if(!ps->VAR_USER_ID[0]){
        fprintf(stderr, "Who are you? (Unable to look up login name)\n");
        rv = -1;
    }
#endif

    expanded = NULL;
    if(ps->vars[V_PERSONAL_NAME].is_fixed){
	if(ps->FIX_PERSONAL_NAME){
            expanded = expand_variables(tmp_20k_buf, SIZEOF_20KBUF,
					ps->FIX_PERSONAL_NAME, 0);
	}
	if(ps->vars[V_PERSONAL_NAME].main_user_val.p ||
	   ps->vars[V_PERSONAL_NAME].post_user_val.p){
	    ps_global->give_fixed_warning = 1;
	    ps_global->fix_fixed_warning = 1;
	}
	else if(ps->COM_PERSONAL_NAME)
	  ps_global->give_fixed_warning = 1;
    }
    else{
	if(ps->COM_PERSONAL_NAME)
	  expanded = expand_variables(tmp_20k_buf, SIZEOF_20KBUF,
				      ps->COM_PERSONAL_NAME, 0);

	if(!expanded && ps->vars[V_PERSONAL_NAME].post_user_val.p)
	  expanded = expand_variables(tmp_20k_buf, SIZEOF_20KBUF,
			      ps->vars[V_PERSONAL_NAME].post_user_val.p, 0);

	if(!expanded && ps->vars[V_PERSONAL_NAME].main_user_val.p)
	  expanded = expand_variables(tmp_20k_buf, SIZEOF_20KBUF,
			      ps->vars[V_PERSONAL_NAME].main_user_val.p, 0);
    }

    if(!expanded){
	expanded = ps->ui.fullname;
#if defined(DOS) || defined(OS2)
	ps->blank_personal_name = 1;
#endif
    }

    ps->VAR_PERSONAL_NAME = cpystr(expanded ? expanded : "");

    dprint((1, "Userid: %s\nFullname: \"%s\"\n",
               ps->VAR_USER_ID, ps->VAR_PERSONAL_NAME));
    return(rv);
}


/*----------------------------------------------------------------------
    Sets  home_dir

   Args: ps -- The Pine structure to put the user name, etc in

  Result: sets the home_dir field of the pine structure
          returns 0 on success, -1 if not.
  ----*/

int
init_userdir(struct pine *ps)
{
    char fld_dir[MAXPATH+1];

    if(strlen(ps->home_dir) + strlen(ps->VAR_MAIL_DIRECTORY)+2 > MAXPATH){
        printf(_("Folders directory name is longer than %d\n"), MAXPATH);
        printf(_("Directory name: \"%s/%s\"\n"),ps->home_dir,
               ps->VAR_MAIL_DIRECTORY);
        return(-1);
    }
#if defined(DOS) || defined(OS2)
    if(ps->VAR_MAIL_DIRECTORY[1] == ':'){
	strncpy(fld_dir, ps->VAR_MAIL_DIRECTORY, sizeof(fld_dir)-1);
	fld_dir[sizeof(fld_dir)-1] = '\0';
    }
    else
#endif
    build_path(fld_dir, ps->home_dir, ps->VAR_MAIL_DIRECTORY, sizeof(fld_dir));
    ps->folders_dir = cpystr(fld_dir);

    return(0);
}

/*----------------------------------------------------------------------
  Make sure the default save folders exist in the default
  save context.
  ----*/
void
display_init_err(char *s, int err)
{
#ifdef	_WINDOWS
    mswin_messagebox(s, err);
#else
    int n = 0;

    if(err)
      fputc(BELL, stdout);

    for(; *s; s++)
      if(++n > 60 && isspace((unsigned char)*s)){
	  n = 0;
	  fputc('\n', stdout);
	  while(*(s+1) && isspace((unsigned char)*(s+1)))
	    s++;
      }
      else
	fputc(*s, stdout);

    fputc('\n', stdout);
#endif
}

#ifdef ALPINE_USE_CONFIG_DIR
/* these are used to report configuration directory creation problems */
CONF_TXT_T init_config_exists[] =	"The \"%s\" subdirectory already exists, but it is not writable by Alpine so Alpine cannot run.  Please correct the permissions and restart Alpine.";

CONF_TXT_T init_config_file[] =	"Alpine requires a directory called \"%s\" from where it will read and will write its configuration, and usualy creates it.  You already have a regular file by that name which means Alpine cannot create the directory.  Please move or remove it and start Alpine again.";

CONF_TXT_T init_config_create[] =	"Creating subdirectory \"%s\" where Alpine will store its configuration and supporting files.";

int
create_root_path(char *path)
{
  char *s, *t, *root_dir;
  struct stat sbuf;

  if(path == NULL || *path == '\0')
    return -1;

  root_dir = path;
  t = path + strlen(path) - 1;
  while(*root_dir != '\0' 
	&& stat(root_dir, &sbuf) < 0){
     s = strrchr(root_dir, C_FILESEP);
     if(s != NULL)
       *s = '\0';
  }
  root_dir += strlen(root_dir);
  *root_dir = C_FILESEP;
  while(root_dir < t){
     if(*root_dir == '\0'){
	if(stat(path, &sbuf) < 0
	   && create_mail_dir(path) < 0)
	  return -1;
        *root_dir = C_FILESEP;
     }
     else
	root_dir++;
  }
  return 0;
}

int
transfer_copy_link(char *dest_file, char *orig_file, int *change)
{
  if(create_root_path(dest_file) == 0){
     if(our_copy_link(dest_file, orig_file) == 0){
        if(change) (*change)++;
	return 0;
     }
  }
  return -1;
}

int
transfer_copy_dir(char *dest_file, char *orig_file, int *change)
{
  if(create_root_path(dest_file) == 0){
     if(our_copy_dir(dest_file, orig_file) == 0){
        if(change) (*change)++;
	return 0;
     }
  }
  return -1;
}

int
transfer_copy_file(char *dest_file, char *orig_file, int *change)
{
  if(create_root_path(dest_file) == 0){
     int script;
     script = dest_file[strlen(orig_file)-1] == '|' ? 1 : 0;
     if(script){
	orig_file[strlen(orig_file)-1] == '\0';
	dest_file[strlen(dest_file)-1] == '\0';
     }
     if(our_copy(dest_file, orig_file) == 0){
	struct stat sbuf;
        if(change) (*change)++;
	if(script == 0 
	   || (our_stat(orig_file, &sbuf) == 0
	       && our_chmod(dest_file, sbuf.st_mode & ~077) == 0))
	  return 0;
     }
  }
  return -1;
}

/* We transfer tfile to dest_dir 
 * return value: -1 on error,
 *                0 no error.
 *
 * Do not call unless ps->using_config_dir > 0.
 */
int
transfer_config_file(TRANSFER_S dest_file, char *dest_dir, int *change)
{
  int i;
  char orig_file[MAXPATH+1], orig_path[MAXPATH+1], dest_path[MAXPATH+1], *target_filename;
  struct stat sbuf_orig, sbuf_dest;

  if(dest_file.tname == NULL || is_absolute_path(dest_file.tname))
    return 0;

  /* construct origin */
  sprintf(orig_file, "%s%s", dest_file.prepend, dest_file.tname);
  orig_file[sizeof(orig_file)-1] = '\0';
  build_path(orig_path, ps_global->home_dir, orig_file, sizeof(orig_path));

  /* if origin does not exist, consider it transferred */
  if(our_stat(orig_path, &sbuf_orig) < 0)
    return 0;

  target_filename = target_transfer_filename(orig_file);

  if(dest_file.subdir != NULL)
    build_path2(dest_path, dest_dir, dest_file.subdir, target_filename, sizeof(dest_path));
  else
    build_path(dest_path, dest_dir, target_filename, sizeof(dest_path));

  fs_give((void **) &target_filename);

  if(our_stat(dest_path, &sbuf_dest) < 0){    /* destination does not exist */
    switch(sbuf_orig.st_mode & S_IFMT){
	case S_IFREG:	/* regular file */
		return transfer_copy_file(dest_path,orig_path, change);

	case S_IFDIR:	/* Directory? */
		return transfer_copy_dir(dest_path, orig_path, change);

	case S_IFLNK: 	/* symbolic link? */
		return transfer_copy_link(dest_path, orig_path, change);

	default:	/* we do not copy anything else at this time */
		return -1;
    }
  } 
  /* else do not overwrite a file/directory that already exists 
   * in the destination. Consider it transfered.
   */
  return 0;
}

TRANSFER_S
transfer_list_from_token(char *token)
{
  int i;

  if(ps_global->using_config_dir)
     for (i = 0; transfer_list[i].tname != NULL
		&& strcmp(transfer_list[i].tname, token) != 0; i++);
  else
     for (i = 0; transfer_list[i].tname != NULL; i++);

  return transfer_list[i];
}

/* 
 * We attempt to transfer all files. We do not stop for errors.
 *
 * return value: -1 on some error, 
 *                0 no errors.
 */
int
transfer_to_config_dir(char *dest_dir)
{
 int i, rv = 0;

 for (i = 0; transfer_list[i].tname != NULL; i++)
   rv += transfer_config_file(transfer_list[i], dest_dir, NULL);

 return rv;
}

/* this functions takes a relative path and unhides its path, by
 * switching any /. to / and removing a leading . too in a copy of
 * the original filename. Memory freed by caller.
 */
char *
target_transfer_filename(char *filename)
{
  char *f = NULL, *s, *u;

  if(filename == NULL)
    return f;

  f = cpystr(filename);

  if(is_absolute_path(f))
    return f;

  for(s = u = f; *u != '\0'; u++){
     if(u == f && *u == '.')
	continue;
     if(*u == C_FILESEP){
	if(*(u+1) == '.')
	  *s++ = *u++;
	else
	  *s++ = *u;
     } else
     *s++ = *u;
  }
  *s = '\0';

  return f;
}

int
rd_transfer_metadata(char *orig_data, char *dest_dir)
{
    char *tempfile;
    FILE *fp_old = NULL, *fp_new = NULL;
    char *p = NULL, *pinerc_dir = NULL;
    char *filename= NULL;
    char *head, *tail;
    char  line[MAILTMPLEN], location[MAXPATH+1];
    int   fd, rv = 0, change = 0;
    TRANSFER_S transfer_this;

    if(orig_data == NULL || *orig_data == '\0')
      return 0;

    dprint((7, "Transfer remote metadata \n"));

    transfer_this.tname         = orig_data;
    transfer_this.is_exact_name = 1;
    transfer_this.prepend       = "";
    transfer_this.subdir        = REMOTE_SUBDIR;
    filename = target_transfer_filename(orig_data);

    if(transfer_config_file(transfer_this, dest_dir, &change) == 0){
      if(filename != NULL && change){
        set_variable(V_REMOTE_ABOOK_METADATA, filename, 1, 0, Main);
        if(ps_global->prc)
	  ps_global->prc->outstanding_pinerc_changes = 1;
      }
    }
    else
      rv += -1;

    build_path2(location, ps_global->config_dir, REMOTE_SUBDIR, filename, sizeof(location));

    if(!(tempfile = tempfile_in_same_dir(location, "am", &pinerc_dir)))
      goto io_err;

    if((fd = our_open(tempfile, O_TRUNC|O_WRONLY|O_CREAT|O_BINARY, 0600)) >= 0)
      fp_new = fdopen(fd, "w");
    
    if(pinerc_dir)
      fs_give((void **)&pinerc_dir);

    fp_old = our_fopen(location, "rb");

    if(fp_new && fp_old){
	/*
	 * Write the header line.
	 */
	if(fprintf(fp_new, "%s %s Pine Metadata\n",
		   PMAGIC, METAFILE_VERSION_NUM) == EOF)
	  goto io_err;

	while((p = fgets(line, sizeof(line), fp_old)) != NULL){
	    int add_line = -1;
	    /*
	     * Skip the header line and any lines that don't begin
	     * with a "{".
	     */
	    if(line[0] != '{')
	      continue;

	    if((tail = strchr(p, '\t')) != NULL){
		char *fname = tail+1;
		TRANSFER_S transfer_this;
		int move_this = 0;

		head = tail;
		tail = strchr(fname, '\t');
		if(tail != NULL){
		  *tail = '\0';
		   if(*fname){
		     transfer_this.tname         = fname;
		     transfer_this.is_exact_name = 1;
		     transfer_this.prepend       = "";
		     transfer_this.subdir        = REMOTE_SUBDIR;
		     add_line = transfer_config_file(transfer_this, dest_dir, NULL);
		     if(*fname == '.') move_this++;
		   }
		  *tail = '\t';
		  if(move_this){
		    char *q;
		    for(q = fname + 1; *q != '\0'; q++)
			*(q-1) = *q;
		    *(q-1) = '\0';
		  }
		}
	    }
	    
	    /* add this line to new version of file */
	    if(add_line == 0 && fputs(p, fp_new) == EOF)
	      goto io_err;
	}
    }

    if(fclose(fp_new) == EOF){
	fp_new = NULL;
	goto io_err;
    }

    if(fclose(fp_old) == EOF){
	fp_old = NULL;
	goto io_err;
    }

    if(rename_file(tempfile, location) < 0)
      goto io_err;

    if(tempfile)
      fs_give((void **)&tempfile);
    
    if(filename)
      fs_give((void **)&filename);
    
    return rv;

io_err:
    dprint((2, "io_err in rd_write_metadata(%s), tempfile=%s: %s\n",
	    orig_data ? orig_data : "<NULL>", tempfile ? tempfile : "<NULL>",
	    error_description(errno)));
    q_status_message2(SM_ORDER, 3, 5,
		    "Trouble updating metafile %s, continuing (%s)",
		    orig_data ? orig_data : "<NULL>", error_description(errno));
    if(tempfile){
	our_unlink(tempfile);
	fs_give((void **)&tempfile);
    }
    if(orig_data)
      fs_give((void **)&orig_data);
    if(fp_old)
      (void)fclose(fp_old);
    if(fp_new)
      (void)fclose(fp_new);
    if(filename)
      fs_give((void **)&filename);

    return rv;
}

int
transfer_addressbook(char **orig_data, char *dest_dir)
{
    char *nickname, *filename, **p, *q;
    int  rv = 0, change = 0;
    TRANSFER_S transfer_this;

    dprint((7, "Transfer addressbook\n"));

    if(orig_data == NULL || *orig_data == NULL || **orig_data == '\0')
      return 0;

    for(p = orig_data; *p != NULL && **p != '\0'; p++){
	char *newfile = NULL;
	get_pair(*p, &nickname, &filename, 0, 0);
	if(*filename != '{' && !is_absolute_path(filename)){
	    transfer_this.tname         = filename;
	    transfer_this.is_exact_name = 1;
	    transfer_this.prepend       = "";
	    transfer_this.subdir        = ABOOK_SUBDIR;
	    if(transfer_config_file(transfer_this, dest_dir, &change) < 0)
	       rv += -1;
	    else
	       newfile = target_transfer_filename(filename);
	}
	else
	   newfile = cpystr(filename);
	if(newfile){
	   fs_resize((void **) &*p, 
		strlen(nickname ? nickname : "") + strlen(nickname ? " " : "") + strlen(newfile) + 1);
           sprintf(*p, "%s%s%s", nickname ? nickname : "", nickname ? " " : "", newfile);
	   fs_give((void **) &newfile);
	}
	if(filename) fs_give((void **) &filename);
	if(nickname) fs_give((void **) &nickname);
    }

    if(change){
       set_variable_list(V_ADDRESSBOOK, orig_data, TRUE, Main);
       if(ps_global->prc)
         ps_global->prc->outstanding_pinerc_changes = 1;
    }

    return 0;
}

int
transfer_signature(char *glo_signature, char **role_signature, char *dest_dir)
{
    char *newfile, **p, *q, *s;
    int  rv = 0, change = 0;
    TRANSFER_S transfer_this;

    dprint((7, "Transfer signature\n"));

    if(glo_signature){
       transfer_this.tname         = glo_signature;
       transfer_this.is_exact_name = 1;
       transfer_this.prepend       = "";
       transfer_this.subdir        = SGNTURE_SUBDIR;
       if(transfer_config_file(transfer_this, dest_dir, &change) < 0)
	  rv += -1;
       else{
	  newfile = target_transfer_filename(glo_signature);
	  if(change){
	    set_variable(V_SIGNATURE_FILE, newfile, 1, 0, Main);
	    if(ps_global->prc)
	       ps_global->prc->outstanding_pinerc_changes = 1;
	  }
	  fs_give((void **) &newfile);
       }
    }

    change = 0;
    for(p = role_signature; *p != NULL && **p != '\0'; p++){
	PAT_S *pattern = parse_pat(*p);
	if(pattern){
	   if(pattern->action && pattern->action->sig){
	     transfer_this.tname 	       = pattern->action->sig;
	     transfer_this.is_exact_name = 1;
	     transfer_this.prepend       = "";
	     transfer_this.subdir        = SGNTURE_SUBDIR;
	     if(transfer_config_file(transfer_this, dest_dir, &change) < 0)
	        rv += -1;
	     else{
	        newfile = target_transfer_filename(pattern->action->sig);
	        fs_give((void **) &pattern->action->sig);
	        pattern->action->sig = cpystr(newfile);
	        fs_give((void **) &newfile);
	        s = data_for_patline(pattern);
	        fs_resize((void **)&*p, strlen(s) + 4 + 1);
	        sprintf(*p, "LIT:%s", s);
	        fs_give((void **)&s);
	     }
	   }
	   free_pat(&pattern);
	}
    }

    if(change){
      set_variable_list(V_PAT_ROLES, role_signature, TRUE, Main);
      if(ps_global->prc)
	 ps_global->prc->outstanding_pinerc_changes = 1;
    }

    return 0;
}



/*----------------------------------------------------------------------
    Make sure the alpine configuration directory exists and initialize
    it in case it does not.

   Args: ps -- alpine structure to get mail directory and contexts from

  Result: returns 0 if it exists or it is created and all is well
                  1 if it is missing and can't be created.
  ----*/
int
init_config_dir(struct pine *ps)
{

    switch(is_writable_dir(ps->config_dir)){
      case 0:
        /* --- all is well --- */
	return(0);

      case 1:
	snprintf(tmp_20k_buf, SIZEOF_20KBUF, init_config_exists, ps->config_dir);
	display_init_err(tmp_20k_buf, 1);
	return(-1);

      case 2:
	snprintf(tmp_20k_buf, SIZEOF_20KBUF, init_config_file, ps->config_dir);
	display_init_err(tmp_20k_buf, 1);
	return(-1);

      case 3:
	snprintf(tmp_20k_buf, SIZEOF_20KBUF, init_config_create, ps->config_dir);
	display_init_err(tmp_20k_buf, 0);
#ifndef	_WINDOWS
    	sleep(4);
#endif
        if(create_mail_dir(ps->config_dir) < 0){
            snprintf(tmp_20k_buf, SIZEOF_20KBUF, "Error creating subdirectory \"%s\" : %s",
		    ps->config_dir, error_description(errno));
	    display_init_err(tmp_20k_buf, 1);
            return(-1);
        }
	else if(transfer_to_config_dir(ps->config_dir) < 0){
            snprintf(tmp_20k_buf, SIZEOF_20KBUF, "Error transfering configuration to subdirectory \"%s\" : %s",
		    ps->config_dir, error_description(errno));
	    display_init_err(tmp_20k_buf, 1);
            return(-1);
	}
    }

    return(0);
}
#endif /* ALPINE_USE_CONFIG_DIR */

/*----------------------------------------------------------------------
        Fetch the hostname of the current system and put it in pine struct

   Args: ps -- The pine structure to put the hostname, etc in

  Result: hostname, localdomain, userdomain and maildomain are set


** Pine uses the following set of names:
  hostname -    The fully-qualified hostname.  Obtained with
		gethostbyname() which reads /etc/hosts or does a DNS
		lookup.  This may be blank.
  localdomain - The domain name without the host.  Obtained from the
		above hostname if it has a "." in it.  Removes first
		segment.  If hostname has no "." in it then the hostname
		is used.  This may be blank.
  userdomain -  Explicitly configured domainname.  This is read out of the
		global pine.conf or user's .pinerc.  The user's entry in the
		.pinerc overrides.

** Pine has the following uses for such names:

  1. On outgoing messages in the From: line
	Uses userdomain if there is one.  If not uses, uses
	hostname unless Pine has been configured to use localdomain.

  2. When expanding/fully-qualifying unqualified addresses during
     composition
	(same as 1)

  3. When expanding/fully-qualifying unqualified addresses during
     composition when a local entry in the password file exists for
     name.
        If no userdomain is given, then this lookup is always done
	and the hostname is used unless Pine's been configured to 
	use the localdomain.  If userdomain is defined, it is used,
	but no local lookup is done.  We can't assume users on the
	local host are valid in the given domain (and, for simplicity,
	have chosen to ignore the cases userdomain matches localdomain
	or localhost).  Setting user-lookup-even-if-domain-mismatch
	feature will tell pine to override this behavior and perform
	the local lookup anyway.  The problem of a global "even-if"
	set and a .pinerc-defined user-domain of something odd causing
	the local lookup, but this will only effect the personal name, 
	and is not judged to be a significant problem.

  4. In determining if an address is that of the current pine user for
     formatting index and filtering addresses when replying
	If a userdomain is specified the address must match the
	userdomain exactly.  If a userdomain is not specified or the
	userdomain is the same as the hostname or domainname, then
	an address will be considered the users if it matches either
	the domainname or the hostname.  Of course, the userid must
	match too. 

  5. In Message ID's
	The fully-qualified hostname is always users here.


** Setting the domain names
  To set the domain name for all Pine users on the system to be
different from what Pine figures out from DNS, set the domain name in
the "user-domain" variable in pine.conf.  To set the domain name for an
individual user, set the "user-domain" variable in his .pinerc.
The .pinerc setting overrides any other setting.
 ----*/
int
init_hostname(struct pine *ps)
{
    char hostname[MAX_ADDRESS+1], domainname[MAX_ADDRESS+1];

    getdomainnames(hostname, sizeof(hostname)-1,
		   domainname, sizeof(domainname)-1);

    if(ps->hostname)
      fs_give((void **)&ps->hostname);

    ps->hostname = cpystr(hostname);

    if(ps->localdomain)
      fs_give((void **)&ps->localdomain);

    ps->localdomain = cpystr(domainname);
    ps->userdomain  = NULL;

    if(ps->VAR_USER_DOMAIN && ps->VAR_USER_DOMAIN[0]){
        ps->maildomain = ps->userdomain = ps->VAR_USER_DOMAIN;
    }else{
#if defined(DOS) || defined(OS2)
	if(ps->VAR_USER_DOMAIN)
	  ps->blank_user_domain = 1;	/* user domain set to null string! */

        ps->maildomain = ps->localdomain[0] ? ps->localdomain : ps->hostname;
#else
        ps->maildomain = strucmp(ps->VAR_USE_ONLY_DOMAIN_NAME, "yes")
			  ? ps->hostname : ps->localdomain;
#endif
    }

    /*
     * Tell c-client what domain to use when completing unqualified
     * addresses it finds in local mailboxes.  Remember, it won't 
     * affect what's to the right of '@' for unqualified addresses in
     * remote folders...
     */
    mail_parameters(NULL, SET_LOCALHOST, (void *) ps->maildomain);
    if(F_OFF(F_QUELL_MAILDOMAIN_WARNING, ps) && !strchr(ps->maildomain, '.')){
	snprintf(tmp_20k_buf, SIZEOF_20KBUF, _("Incomplete maildomain \"%s\"."),
		ps->maildomain);
	init_error(ps, SM_ORDER | SM_DING, 3, 5, tmp_20k_buf);
	strncpy(tmp_20k_buf,
	       _("Return address in mail you send may be incorrect."), SIZEOF_20KBUF);
	tmp_20k_buf[SIZEOF_20KBUF-1] = '\0';
	init_error(ps, SM_ORDER | SM_DING, 3, 5, tmp_20k_buf);
    }

    dprint((1,"User domain name being used \"%s\"\n",
               ps->userdomain == NULL ? "" : ps->userdomain));
    dprint((1,"Local Domain name being used \"%s\"\n",
               ps->localdomain ? ps->localdomain : "?"));
    dprint((1,"Host name being used \"%s\"\n",
               ps->hostname ? ps->hostname : "?"));
    dprint((1,
	       "Mail Domain name being used (by c-client too) \"%s\"\n",
               ps->maildomain ? ps->maildomain : "?"));

    if(!ps->maildomain || !ps->maildomain[0]){
#if defined(DOS) || defined(OS2)
	if(ps->blank_user_domain)
	  return(0);		/* prompt for this in send.c:dos_valid_from */
#endif
        fprintf(stderr, _("No host name or domain name set\n"));
        return(-1);
    }
    else
      return(0);
}


/*----------------------------------------------------------------------
  Make sure the default save folders exist in the default
  save context.
  ----*/
void
init_save_defaults(void)
{
    CONTEXT_S  *save_cntxt;

    if(!ps_global->VAR_DEFAULT_FCC ||
       !*ps_global->VAR_DEFAULT_FCC ||
       !ps_global->VAR_DEFAULT_SAVE_FOLDER ||
       !*ps_global->VAR_DEFAULT_SAVE_FOLDER)
      return;

    if(!(save_cntxt = default_save_context(ps_global->context_list)))
      save_cntxt = ps_global->context_list;

    if(!(folder_exists(save_cntxt, ps_global->VAR_DEFAULT_FCC) & FEX_ISFILE))
      context_create(save_cntxt, NULL, ps_global->VAR_DEFAULT_FCC);

    if(!(folder_exists(save_cntxt, ps_global->VAR_DEFAULT_SAVE_FOLDER) &
								 FEX_ISFILE))
      context_create(save_cntxt, NULL, ps_global->VAR_DEFAULT_SAVE_FOLDER);

    free_folder_list(save_cntxt);
}


/*----------------------------------------------------------------------
      Put sent-mail files in date order 

   Args: a, b  -- The names of two files.  Expects names to be sent-mail-mmm-yy
                  Other names will sort in order and come before those
                  in above format.
 ----*/
int   
compare_sm_files(const qsort_t *aa, const qsort_t *bb)
{
    struct sm_folder *a = (struct sm_folder *)aa,
                     *b = (struct sm_folder *)bb;

    if(a->month_num == -1 && b->month_num == -1 && a->name && b->name)
      return(strucmp(a->name, b->name));
    if(a->month_num == -1)      return(-1);
    if(b->month_num == -1)      return(1);

    return(a->month_num - b->month_num);
}



/*----------------------------------------------------------------------
      Create an ordered list of sent-mail folders and their month numbers

   Args: dir -- The directory to find the list of files in

 Result: Pointer to list of files is returned. 

This list includes all files that start with "sent-mail", but not "sent-mail" 
itself.
  ----*/
struct sm_folder *
get_mail_list(CONTEXT_S *list_cntxt, char *folder_base)
{
    register struct sm_folder *sm  = NULL;
    struct sm_folder          *sml = NULL;
    char                      *filename;
    int                        i, folder_base_len;
    int                        max_files;
    char		       searchname[MAXPATH+1];

    if((folder_base_len = strlen(folder_base)) == 0 || !list_cntxt){
	sml = (struct sm_folder *) fs_get(sizeof(struct sm_folder));
	memset((void *)sml, 0, sizeof(struct sm_folder));
        return(sml);
    }

#ifdef	DOS
    if(*list_cntxt->context != '{'){	/* NOT an IMAP collection! */
	snprintf(searchname, sizeof(searchname), "%4.4s*", folder_base);
	folder_base_len = strlen(searchname) - 1;
    }
    else
#endif					/* MAXPATH + 1 = sizeof(searchmane) */
    snprintf(searchname, sizeof(searchname), "%.*s*", MAXPATH+1-2, folder_base);

    build_folder_list(NULL, list_cntxt, searchname, NULL, BFL_FLDRONLY);

    max_files = MIN(MAX(0, folder_total(FOLDERS(list_cntxt))), 5000);
    sml = sm = (struct sm_folder *) fs_get(sizeof(struct sm_folder)*(max_files+1));
    memset((void *)sml, 0, sizeof(struct sm_folder) * (max_files+1));

    for(i = 0; i < folder_total(FOLDERS(list_cntxt)); i++){
	filename = folder_entry(i, FOLDERS(list_cntxt))->name;
#ifdef	DOS
        if(struncmp(filename, folder_base, folder_base_len) == 0
           && strucmp(filename, folder_base)){

	if(*list_cntxt->context != '{'){
	    int j;
	    for(j = 0; j < 4; j++)
	      if(!isdigit((unsigned char)filename[folder_base_len + j]))
		break;

	   if(j < 4)		/* not proper date format! */
	     continue;		/* keep trying */
	}
#else
#ifdef OS2
        if(strnicmp(filename, folder_base, folder_base_len) == 0
           && stricmp(filename, folder_base)){
#else
        if(strncmp(filename, folder_base, folder_base_len) == 0
           && strcmp(filename, folder_base)){
#endif
#endif
	    sm->name = cpystr(filename);
#ifdef	DOS
	    if(*list_cntxt->context != '{'){ /* NOT an IMAP collection! */
		sm->month_num  = (sm->name[folder_base_len] - '0') * 10;
		sm->month_num += sm->name[folder_base_len + 1] - '0';
	    }
	    else
#endif
            sm->month_num = month_num(sm->name + (size_t)folder_base_len + 1);
            sm++;
            if(sm >= &sml[max_files])
               break; /* Too many files, ignore the rest ; shouldn't occur */
        }
    }

    /* anything to sort?? */
    if(sml->name && *(sml->name) && (sml+1)->name && *((sml+1)->name)){
	qsort(sml,
	      sm - sml,
	      sizeof(struct sm_folder),
	      compare_sm_files);
    }

    return(sml);
}



int
check_prune_time(time_t *now, struct tm **tm_now)
{
    char tmp[50];

    *now = time((time_t *) 0);
    *tm_now = localtime(now);

    /*
     * If the last time we did this is blank (as if pine's run for
     * first time), don't go thru list asking, but just note it for 
     * the next time...
     */
    if(ps_global->VAR_LAST_TIME_PRUNE_QUESTION == NULL){
	ps_global->last_expire_year = (*tm_now)->tm_year;
	ps_global->last_expire_month = (*tm_now)->tm_mon;
	snprintf(tmp, sizeof(tmp), "%d.%d", ps_global->last_expire_year,
		ps_global->last_expire_month + 1);
	set_variable(V_LAST_TIME_PRUNE_QUESTION, tmp, 1, 1, Main);
	return(0);
    }

    if(ps_global->last_expire_year != -1 &&
      ((*tm_now)->tm_year <  ps_global->last_expire_year ||
       ((*tm_now)->tm_year == ps_global->last_expire_year &&
        (*tm_now)->tm_mon <= ps_global->last_expire_month)))
      return(0); 
    
    return(1);
}


int
first_run_of_month(void)
{
    time_t     now;
    struct tm *tm_now;

    now = time((time_t *) 0);
    tm_now = localtime(&now);

    if(ps_global->last_expire_year == -1 ||
      (tm_now->tm_year <  ps_global->last_expire_year ||
       (tm_now->tm_year == ps_global->last_expire_year &&
        tm_now->tm_mon <= ps_global->last_expire_month)))
      return(0); 

    return(1);
}


int
first_run_of_year(void)
{
    time_t     now;
    struct tm *tm_now;

    now = time((time_t *) 0);
    tm_now = localtime(&now);

    if(ps_global->last_expire_year == -1 ||
      (tm_now->tm_year <=  ps_global->last_expire_year))
      return(0); 

    return(1);
}


/*
 * prune_move_folder - rename folder in context and delete old copy
 * Returns -1 if unsuccessful.
 */
int
prune_move_folder(char *oldpath, char *newpath, CONTEXT_S *prune_cntxt)
{
    char spath[MAXPATH+1];

    strncpy(spath, oldpath, sizeof(spath)-1);
    spath[sizeof(spath)-1] = '\0';

    /*--- User says OK to rename ---*/
    dprint((5, "rename \"%s\" to \"%s\"\n",
	   spath ? spath : "?", newpath ? newpath : "?"));
    q_status_message1(SM_ORDER, 1, 3,
		      /* TRANSLATORS: arg is a filename */
		      _("Renaming \"%s\" at start of month"),
		      pretty_fn(spath ? spath : "?"));

    if(!context_rename(prune_cntxt, NULL, spath, newpath)){
        q_status_message2(SM_ORDER | SM_DING, 3, 4,
			  /* TRANSLATORS: 1st arg is filename, 2nd is error message */
			  _("Error renaming \"%s\": %s"),
                          pretty_fn(spath ? spath : "?"),
			  error_description(errno));
        dprint((1, "Error renaming %s to %s: %s\n",
                   spath ? spath : "?", newpath ? newpath : "?",
		   error_description(errno)));
        display_message('x');
        return -1;
    }

    context_create(prune_cntxt, NULL, spath);

    return 0;
}
