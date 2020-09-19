#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: smime.c 1176 2008-09-29 21:16:42Z hubert@u.washington.edu $";
#endif

/*
 * ========================================================================
 * Copyright 2013-2020 Eduardo Chappa
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

/*
 *  This is based on a contribution from Jonathan Paisley
 *
 *  File:   	    smime.c
 *  Author: 	    paisleyj@dcs.gla.ac.uk
 *  Date:   	    01/2001
 */


#include "../pith/headers.h"

#ifdef SMIME

#include "../pith/osdep/canaccess.h"
#include "../pith/helptext.h"
#include "../pith/store.h"
#include "../pith/status.h"
#include "../pith/detach.h"
#include "../pith/conf.h"
#include "../pith/smkeys.h"
#include "../pith/smime.h"
#include "../pith/mailpart.h"
#include "../pith/reply.h"
#include "../pith/tempfile.h"
#include "../pith/readfile.h"
#include "../pith/remote.h"
#include "../pith/body.h"
#ifdef PASSFILE
#include "../pith/imap.h"
#endif /* PASSFILE */

#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

/* internal prototypes */
static void            forget_private_keys(void);
static int             app_RAND_load_file(const char *file);
static void            openssl_extra_randomness(void);
static int             app_RAND_write_file(const char *file);
static const char     *openssl_error_string(void);
static int             load_private_key(PERSONAL_CERT *pcert);
static void            create_local_cache(char *h, char *base, BODY *b, int type);
static long            rfc822_output_func(void *b, char *string);
static void            setup_pkcs7_body_for_signature(BODY *b, char *description,
						      char *type, char *filename, char *smime_type);
static BIO            *body_to_bio(BODY *body);
static BIO            *bio_from_store(STORE_S *store);
static STORE_S        *get_part_contents(long msgno, const char *section);
static PKCS7         *get_pkcs7_from_part(long msgno, const char *section);
static int            do_signature_verify(PKCS7 *p7, BIO *in, BIO *out, int silent);
static int            do_detached_signature_verify(BODY *b, long msgno, char *section);
static PERSONAL_CERT *find_certificate_matching_pkcs7(PKCS7 *p7);
static int            do_decoding(BODY *b, long msgno, const char *section);
static void           free_smime_struct(SMIME_STUFF_S **smime);
static void           setup_storage_locations(void);
static int            copy_container_to_dir(WhichCerts which);
static int	      do_fiddle_smime_message(BODY *b, long msgno, char *section);
void		      setup_privatekey_storage(void);
int		      smime_extract_and_save_cert(PKCS7 *p7);
int		      same_cert(X509 *, X509 *);
#ifdef PASSFILE
int		      load_key_and_cert(char *pathkeydir, char *pathcertdir, char **keyfile, char **certfile, EVP_PKEY **pkey, X509 **pcert);
#endif /* PASSFILE */
EVP_PKEY 	     *load_pkey_with_prompt(char *fpath, char *text, char *prompt, int *);
void		      smime_remove_trailing_crlf(char **mimetext, unsigned long *mimelen, char **bodytext, unsigned long *bodylen);
void		      smime_remove_folding_space(char **mimetext, unsigned long *mimelen, char **bodytext, unsigned long *bodylen);
int		      smime_validate_extra_test(char *mimetext, unsigned long mimelen, char *bodytext, unsigned long bodylen, PKCS7 *p7, int nflag);

int  (*pith_opt_smime_get_passphrase)(void);
int  (*pith_smime_import_certificate)(char *, char *, char *, size_t);
int  (*pith_smime_enter_password)(char *, char *, size_t);
int  (*pith_smime_confirm_save)(char *);

static X509_STORE   *s_cert_store;

/* State management for randomness functions below */
static int seeded = 0;

#ifdef PASSFILE
/* 
 * This code does not work in Windows, because of the PASSFILE thing, so
 * I did not try to fix it. If you think it does need to be applied to
 * the Windows version of alpine, there are more changes that are needed
 * than fixing this function in this module. E. Chappa 09/28/17.
 *
 * load key from pathkeydir and cert from pathcertdir. It chooses the first 
 * key/certificate pair that matches. Delete pairs that you do not want used, 
 * if you do not want them selected. All parameters must be non-null. 
 * Memory freed by caller.
 * Return values:
 * -1 : user cancelled load
 *  0 : load was successful
 *  1 : there was an error in the loading.
 */
int
load_key_and_cert(char *pathkeydir, char *pathcertdir, char **keyfile, 
		char **certfile, EVP_PKEY **pkey, X509 **pcert)
{
   char buf[MAXPATH+1], pathkey[MAXPATH+1], prompt[MAILTMPLEN];
   DIR *dirp;
   struct dirent *d;
   int b = 0, ret = 1; /* assume error */

   if(pathkeydir == NULL || pathcertdir == NULL || keyfile == NULL 
	|| pkey == NULL	|| certfile == NULL || pcert == NULL)
     return 1;

   *keyfile = NULL;
   *certfile = NULL;
   *pkey = NULL;
   *pcert = NULL;

   if((dirp = opendir(pathkeydir)) != NULL){
      while(b == 0 && (d=readdir(dirp)) != NULL){
	size_t ll;

        if((ll=strlen(d->d_name)) && ll > 4){
	   if(!strcmp(d->d_name+ll-4, ".key")){
              strncpy(buf, d->d_name, sizeof(buf));
              buf[sizeof(buf)-1] = '\0';
	      build_path(pathkey, pathkeydir, buf, sizeof(pathkey));
 	      buf[strlen(buf)-4] = '\0';
	      snprintf(prompt, sizeof(prompt),
		_("Enter password of key <%s> to unlock password file: "), buf);
	      if((*pkey = load_pkey_with_prompt(pathkey, NULL, prompt, &ret)) != NULL){
		if(load_cert_for_key(pathcertdir, *pkey, certfile, pcert)){
		  b = 1;	/* break */
		  *keyfile = cpystr(buf);
		} else {
		  EVP_PKEY_free(*pkey);
		  *pkey = NULL;
		  q_status_message1(SM_ORDER, 0, 2,
		     _("Cannot find certificate that matches key <%s>. Continuing..."), buf);
		}
	      }
	   }
	}
      }
      closedir(dirp);
   }
   return ret;
}


/* setup a key and certificate to encrypt and decrypt a password file. 
 * These files will be saved in the .alpine-smime/.pwd directory, but its
 * location can be setup in the command line with the -pwdcertdir option.
 * Here are the rules:
 *
 *  Check if the .alpine-smime/.pwd (or -pwdcertdir directory) exists, 
 *  if not create it. If we are successful, move to the next step
 *
 *  - If the user has a key/cert pair, in the .alpine-smime/.pwd dir 
 *    setup is successful;
 *  - if the user does not have a key/cert pair, look to see if
 *    ps_global->smime->personal_certs is already setup, if so, use it.
 *  - if ps_global->smime->personal_certs is not set up, see if we can 
 *    find a certificate/cert pair in the default locations at compilation 
 *    time. (~/.alpine-smime/private and ~/.alpine-smime/public
 *  - if none of this is successful, create a key/certificate pair
 *    (TODO: implement this)
 *  - in any other case, setup is not successful.
 *
 *  If setup is successful, setup ps_global->pwdcert.
 *  If any of this fails, ps_global->pwdcert will be null.
 *  Ok, that should do it.
 *
 * return values: 0 - everything is normal
 *		  1 - User could not unlock key or no key in directory.
 *		  2 - User cancelled to create self signed certificate
 *		 -1 - we do not know which directory to use
 *		 -2 - "-pwdcertdir" was given by user, but directory does not exist
 *		 -3 - "DF_PASSWORD_DIR" exists but it is not a directory!!??
 * 		 -4 - we tried to create DF_PASSWORD_DIR but failed.
 *		 -5 - password directory exists, but it is empty
 *
 */
int
setup_pwdcert(void **pwdcert)
{
  int rv;
  int we_inited = 0;
  int setup_dir = 0;	/* make it non zero if we know which dir to use */
  struct stat sbuf;
  char pathdir[MAXPATH+1], pathkey[MAXPATH+1], fpath[MAXPATH+1], pathcert[MAXPATH+1];
  char fpath2[MAXPATH+1], prompt[MAILTMPLEN];
  char *keyfile, *certfile, *text;
  EVP_PKEY *pkey = NULL;
  X509 *pcert = NULL;
  PERSONAL_CERT *pc, *pc2 = NULL;
  static int was_here = 0;

  if(pwdcert == NULL || was_here == 1)
    return -1;

  was_here++;
  if(ps_global->pwdcertdir){
     if(our_stat(ps_global->pwdcertdir, &sbuf) == 0
	&& ((sbuf.st_mode & S_IFMT) == S_IFDIR)){
	setup_dir++;
	strncpy(pathdir, ps_global->pwdcertdir, sizeof(pathdir));
	pathdir[sizeof(pathdir)-1] = '\0';
     }
     else rv = -2;
  } else {
      smime_path(DF_PASSWORD_DIR, pathdir, sizeof(pathdir));
      if(our_stat(pathdir, &sbuf) == 0){
	if((sbuf.st_mode & S_IFMT) == S_IFDIR)
	  setup_dir++;
	else rv = -3;
      } else if(can_access(pathdir, ACCESS_EXISTS) != 0
	    && our_mkpath(pathdir, 0700) == 0)
	  setup_dir++;
	else rv = -4;
  }

  if(setup_dir == 0){
    was_here = 0;
    return rv;
  }

  if(load_key_and_cert(pathdir, pathdir, &keyfile, &certfile, &pkey, &pcert) < 0){
    was_here = 0;
    return 1;
  }

  if(ps_global->pwdcertdir == NULL){	/* save the result of pwdcertdir */
    ps_global->pwdcertdir = cpystr(pathdir);
    /* if the user gave a pwdcertdir and there is nothing there, do not
     * continue. Let the user initialize on their own this directory.
     */
    if(certfile == NULL || keyfile == NULL){
      was_here = 0;
      return -5;
    }
  }

  if(certfile && keyfile){
     pc = (PERSONAL_CERT *) fs_get(sizeof(PERSONAL_CERT));
     memset((void *)pc, 0, sizeof(PERSONAL_CERT));
     pc->name = keyfile;
     pc->key  = pkey;
     pc->cert = pcert;
     pc->cname = certfile;
     *pwdcert = (void *) pc;
     was_here = 0;
     return 0;
  }

  /* look to see if there are any certificates lying around, first
   * we try to load ps_global->smime to see if that has information
   * we can use. If we are the process filling the smime structure
   * we deinit at the end, since this might not do a full init.
   */
  if(ps_global && ps_global->smime && !ps_global->smime->inited){
     we_inited++;
     smime_init();
  }

  /* at this point ps_global->smime->inited == 1 */
  if(ps_global->smime && ps_global->smime->personal_certs != NULL){
    pc = (PERSONAL_CERT *) ps_global->smime->personal_certs;
    if(ps_global->smime->privatetype == Directory){
	 build_path(pathkey, ps_global->smime->privatepath, pc->name, sizeof(pathkey));
	 strncat(pathkey, ".key", 5);
	 pathkey[sizeof(pathkey)-1] = '\0';
	 text = NULL;
    } else if (ps_global->smime->privatetype == Container){ 
	 if(pc->keytext == NULL){	/* we should *never* be here, but just in case */
	   if(ps_global->smime->privatecontent != NULL){
	     char tmp[MAILTMPLEN], *s, *t, c;
	     snprintf(tmp, sizeof(tmp), "%s%s", EMAILADDRLEADER, pc->name);
	     tmp[sizeof(tmp)-1] = '\0';
	     if((s = strstr(ps_global->smime->privatecontent, tmp)) != NULL){
		if((t = strstr(s+strlen(tmp), EMAILADDRLEADER)) != NULL){
		   c = *t;
		   *t = '\0';
		   pc->keytext = cpystr(s + strlen(tmp) + strlen(NEWLINE));
		   *t = c;
	        }
		else
		   pc->keytext = cpystr(s + strlen(tmp) + strlen(NEWLINE));
	     }
	   }
	 }
	 if(pc->keytext != NULL)	/* we should go straight here */
	   text = pc->keytext;
    } else if (ps_global->smime->privatetype == Keychain){
	   pathkey[0] = '\0';	/* no apple key chain support yet */
	   text = NULL;
    }
    if((pathkey && *pathkey) || text){
      snprintf(prompt, sizeof(prompt),
	_("Enter password of key <%s> to unlock password file: "), pc->name);

      if((pkey = load_pkey_with_prompt(pathkey, text, prompt, NULL)) != NULL){
	 pc2 = (PERSONAL_CERT *) fs_get(sizeof(PERSONAL_CERT));
	 memset((void *)pc2, 0, sizeof(PERSONAL_CERT));
	 pc2->name = cpystr(pc->name);
	 pc2->key  = pkey;
	 pc2->cert = X509_dup(pc->cert);

	 /* now copy the keys and certs, starting by the key...  */
	 build_path(fpath, pathdir, pc->name, sizeof(fpath));
	 strncat(fpath, ".key", 5);
	 fpath[sizeof(fpath)-1] = '\0';
	 if(our_stat(fpath, &sbuf) == 0){	/* if fpath exists */
	     if((sbuf.st_mode & S_IFMT) == S_IFREG) /* and is a regular file */
	       setup_dir++;			/* we are done */
	 } else if(ps_global->smime->privatetype == Directory){
		   if(our_copy(fpath, pathkey) == 0)
		     setup_dir++;
	 } else if(ps_global->smime->privatetype == Container){
		     BIO *out;
		     if((out = BIO_new_file(fpath, "w")) != NULL){
			if(BIO_puts(out, pc->keytext) > 0)
			   setup_dir++;
		        BIO_free(out);
		     }
	 } else if(ps_global->smime->privatetype == Keychain){
			/* add support for Apple Mac OS X */
	 }
      }

	/* successful copy of key, now continue with certificate */
      if(setup_dir){
	setup_dir = 0;

	build_path(pathkey, ps_global->smime->publicpath, pc->name, sizeof(pathkey));
	strncat(pathkey, ".crt", 5);
	pathkey[sizeof(pathkey)-1] = '\0';

	build_path(fpath, pathdir, pc->name, sizeof(fpath));
	strncat(fpath, ".crt", 5);
	fpath[sizeof(fpath)-1] = '\0';

	if(our_stat(fpath, &sbuf) == 0){
	   if((sbuf.st_mode & S_IFMT) == S_IFREG)
	      setup_dir++;
	}
	else if(ps_global->smime->privatetype == Directory){
		if(our_copy(fpath, pathkey) == 0)
		   setup_dir++;
	} else if(ps_global->smime->privatetype == Container) {
		  BIO *out;
		  if((out = BIO_new_file(fpath, "w")) != NULL){
		     if(PEM_write_bio_X509(out, pc->cert))
			setup_dir++;
			   BIO_free(out);
		  }
	} else if (ps_global->smime->privatetype == Keychain) {
			/* add support for Mac OS X */
	}
      }		

      if(setup_dir){
	*pwdcert = (void *) pc2;
	was_here = 0;
	return 0;
      }
      else if(pc2 != NULL)
	free_personal_certs(&pc2);
    }		/* if (pathkey...) */
  }		/* if(ps_global->smime->personal_certs) */


  if(setup_dir == 0){
     /* PATHCERTDIR(Private) must be null, so create a path */
     set_current_val(&ps_global->vars[V_PRIVATEKEY_DIR], TRUE, TRUE);
     smime_path(ps_global->VAR_PRIVATEKEY_DIR, pathkey, sizeof(pathkey));

     /* PATHCERTDIR(Public) must be null, so create a path */
     set_current_val(&ps_global->vars[V_PUBLICCERT_DIR], TRUE, TRUE);
     smime_path(ps_global->VAR_PUBLICCERT_DIR, pathcert, sizeof(pathcert));

     /* BUG: this does not support local containers */
     load_key_and_cert(pathkey, pathcert, &keyfile, &certfile, &pkey, &pcert);

     if(certfile && keyfile){
	build_path(fpath, pathdir, keyfile, sizeof(fpath));
	strncat(fpath, ".key", 5);
	fpath[sizeof(fpath)-1] = '\0';

	build_path(fpath2, pathkey, keyfile, sizeof(fpath));
	strncat(fpath2, ".key", 5);
	fpath2[sizeof(fpath2)-1] = '\0';

	if(our_copy(fpath, fpath2) == 0)
	   setup_dir++;

	if(setup_dir){
	  setup_dir = 0;

	  build_path(fpath, pathdir, certfile, sizeof(fpath));
	  build_path(fpath2, pathcert, certfile, sizeof(fpath2));

	  if(our_copy(fpath, fpath2) == 0)
	     setup_dir++;
	}
     }
  }

  if(keyfile && certfile){
     pc = (PERSONAL_CERT *) fs_get(sizeof(PERSONAL_CERT));
     memset((void *)pc, 0, sizeof(PERSONAL_CERT));
     pc->name = keyfile;
     pc->key  = pkey;
     pc->cert = pcert;
     *pwdcert = (void *) pc;
     fs_give((void **)&certfile);
     was_here = 0;
     return 0;
  }

  was_here = 0;
  if(we_inited)
    smime_deinit();
  return 0;
}
#endif /* PASSFILE */

/* smime_expunge_cert.
 * Return values: < 0 there was an error.
 *                >=0 the number of messages expunged
 */
int
smime_expunge_cert(WhichCerts ctype)
{
  int count, removed; 
  CertList *cl, *dummy, *data;
  char *path, buf[MAXPATH+1];
  char *contents;

  if(DATACERT(ctype)== NULL)
    return -1;

  /* data cert is the way we unify certificate management across 
   * functions, but it is not where we really save the information in the 
   * case ctype is equal to Private. What we will do is to update the
   * datacert, and in the case of ctype equal to Private use the updated
   * certdata to update the personal_certs data. 
   */

  path = PATHCERTDIR(ctype);

  if(path){
    /* add a fake certificate at the beginning of the list */
    dummy = fs_get(sizeof(CertList));
    memset((void *)dummy, 0, sizeof(CertList));
    dummy->next = DATACERT(ctype);

    for(cl = dummy, count = 0; cl && cl->next;){
	if(cl->next->data.deleted == 0){
	   cl = cl->next;
	   continue;
	}

	removed = 1;		/* assume success */
	if(SMHOLDERTYPE(ctype) == Directory){
	  build_path(buf, path, cl->next->name, sizeof(buf));
	  if(ctype == Private && strlen(buf) + strlen(EXTCERT(Private)) < sizeof(buf)){
	    strncat(buf, EXTCERT(Private), 5);
	    buf[sizeof(buf)-1] = '\0';
	  }

	  if(our_unlink(buf) < 0){
	     q_status_message1(SM_ORDER, 3, 3, _("Error removing certificate %s"), cl->next->name);
	     cl = cl->next;
	     removed = 0;
	  }
	}
	else if(SMHOLDERTYPE(ctype) == Container){
	  char *prefix= ctype == CACert ? CACERTSTORELEADER : EMAILADDRLEADER;
	  char tmp[MAILTMPLEN], *s, *t;

	  contents = CONTENTCERTLIST(ctype);
	  snprintf(tmp, sizeof(tmp), "%s%s", prefix, cl->next->name);
	  tmp[sizeof(tmp) - 1] = '\0';
	  if((s = strstr(contents, tmp)) != NULL){
	     if((t = strstr(s+strlen(tmp), prefix)) == NULL)
		*s = '\0';
	     else
		memmove(s, t, strlen(t)+1);
	     fs_resize((void **)&contents, strlen(contents)+1);
	     switch(ctype){
		case Private: ps_global->smime->privatecontent = contents; break;
		case Public : ps_global->smime->publiccontent = contents; break;
		case CACert : ps_global->smime->cacontent = contents; break;
		default  : break;
	     }
	  }
	  else
	     removed = 0;
	} else { /* unhandled case */
	}

 	if(removed > 0){
	   count++;	/* count it! */
	   data = cl->next;
	   cl->next = data->next;
	   if(data->name) fs_give((void **)&data->name);
	   fs_give((void **)&data);
	}
    }
  } else
	q_status_message(SM_ORDER, 3, 3, _("Error expunging certificate"));

  switch(ctype){
     case Private: ps_global->smime->privatecertlist = dummy->next; break;
     case Public : ps_global->smime->publiccertlist = dummy->next; break;
     case CACert : ps_global->smime->cacertlist = dummy->next; break;
	default  : break;
  }
  fs_give((void **)&dummy);
  if(SMHOLDERTYPE(ctype) == Container){
    if(copy_dir_to_container(ctype, contents) < 0) 
      count = 0;
  }
  if(count > 0){
    q_status_message2(SM_ORDER, 3, 3, _("Removed %s certificate%s"), comatose(count), plural(count));
  }
  else
    q_status_message(SM_ORDER, 3, 3, _("Error: No certificates were removed"));
  return count;
}

void
mark_cert_deleted(WhichCerts ctype, int num, unsigned state)
{
  CertList *cl;
  int i;

  for(cl = DATACERT(ctype), i = 0; cl != NULL && i < num; cl = cl->next, i++);
  cl->data.deleted = state;
}

unsigned
get_cert_deleted(WhichCerts ctype, int num)
{
  CertList *cl;
  int i;

  for(cl = DATACERT(ctype), i = 0; cl != NULL && i < num; cl = cl->next, i++);
  return (cl && cl->data.deleted) ? 1 : 0;
}

EVP_PKEY *
load_pkey_with_prompt(char *fpath, char *text, char *prompt, int *ret)
{
  EVP_PKEY *pkey;
  int rc = 0;   /* rc == 1, cancel, rc == 0 success */
  char pass[MAILTMPLEN+1];
  BIO *in;

  /* attempt to load with empty password */
  in = text ? BIO_new_mem_buf(text, strlen(text)) : BIO_new_file(fpath, "r");
  if(in != NULL){
     pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, "");
     if(pkey != NULL) return pkey;
  } else return NULL;

  if(pith_smime_enter_password)
    while(pkey == NULL && rc != 1){
	do {
	   rc = (*pith_smime_enter_password)(prompt, (char *)pass, sizeof(pass));
	 } while (rc!=0 && rc!=1 && rc>0);

	 (void) BIO_reset(in);
	 pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, (char *)pass);
    }

  BIO_free(in);

  if(ret) *ret = rc == 1 ? -1 : pkey != NULL ? 0 : 1;
  return pkey;
}

/* This is a tool for conf_screen, The return value must be zero when
 * nothing changed, so if there is a failure in the import return 0
 * and return 1 when we succeeded.\
 * We call this function in two ways:
 * either fname is null or not. If they fname is null, so is p_cert.
 * if p_cert is not null, it is the PERSONAL_CERT structure of fname if this
 * is available, otherwise we will fill it up here.
 */
int
import_certificate(WhichCerts ctype, PERSONAL_CERT *p_cert, char *fname)
{
   int   r = 1, rc; 
   char  filename[MAXPATH+1], full_filename[MAXPATH+1], buf[MAXPATH+1];
   char *what;

   if(pith_smime_import_certificate == NULL
	|| pith_smime_enter_password == NULL){
     q_status_message(SM_ORDER, 0, 2,
                      _("import of certificates not implemented yet!"));
     return 0;
  }

   if(fname == NULL){
      what = ctype == Public || ctype == CACert ? "certificate" : "key";
      r = (*pith_smime_import_certificate)(filename, full_filename, what, sizeof(filename) - 20);

     if(r < 0)
       return 0;
   } else {
     char *s;
     strncpy(full_filename, fname, sizeof(full_filename));
     if((s = strrchr(full_filename, '/')) != NULL)
       strncpy(filename, s+1, sizeof(filename));
   }

   /* we are trying to import a new key for the password file. First we ask for the
    * private key. Once this is loaded, we make a reasonable attempt to find the
    * public key in the same directory as the key was loaded from. We do this by
    * looking for a file with the correct public certificate name, then we look
    * in the same private key, and if not, we ask the user for its location. If all
    * of this works, we import the key and public to the password directory.
    */
#ifdef PASSFILE
   if(ctype == Password){
     char PrivateKeyPath[MAXPATH+1], PublicCertPath[MAXPATH+1], s[MAXPATH+1];
     char full_name_key[MAXPATH+1], full_name_cert[MAXPATH+1];
     char *use_this_file;
     char prompt[500];
     EVP_PKEY *key = p_cert ? p_cert->key : NULL;

     rc = 1;	/* assume success :) */
     if(strlen(filename) > 4){
	strncpy(s, filename, sizeof(s));
	s[sizeof(s)-1] = '\0';
	if(!strcmp(s + strlen(s) - strlen(EXTCERT(Private)), EXTCERT(Private)))
	  s[strlen(s) - strlen(EXTCERT(Private))] = '\0';
	else
	  rc = 0;
     } else rc = 0;

     if(rc == 0){
	q_status_message(SM_ORDER, 1, 3, _("Error in key name. Check file extension"));
	return 0;
     }

     snprintf(prompt, sizeof(prompt), _("Enter passphrase to unlock new key <%s>: "), filename);
     prompt[sizeof(prompt)-1] = '\0';
     if(key != NULL 
	|| (key = load_pkey_with_prompt(full_filename, NULL, prompt, NULL)) != NULL){
	BIO *ins = NULL;
	X509 *cert = p_cert ? p_cert->cert : NULL, *cert2;

	strncpy(full_name_key, full_filename, sizeof(full_filename));
        full_name_key[sizeof(full_name_key)-1] = '\0';

	build_path(buf, PATHCERTDIR(ctype), s, sizeof(buf));

	strncpy(PrivateKeyPath, buf, sizeof(PrivateKeyPath));
	PrivateKeyPath[sizeof(PrivateKeyPath)-1] = '\0';
	if(strlen(PrivateKeyPath) + 4 < sizeof(PrivateKeyPath)){
	   strncat(PrivateKeyPath, EXTCERT(Private), 5);
	   PrivateKeyPath[sizeof(PrivateKeyPath)-1] = '\0';
	}

	/* remove .key extension and replace it with .crt extension */
	strncpy(full_name_cert, full_name_key, sizeof(full_name_key));
	full_name_cert[sizeof(full_name_cert)-1] = '\0';
	full_name_cert[strlen(full_name_cert) - strlen(EXTCERT(Private))] = '\0';
	strncat(full_name_cert, EXTCERT(Public), 5);
	full_name_cert[sizeof(full_name_cert)-1] = '\0';


	/* set up path to location where we will save public cert */
	strncpy(PublicCertPath, buf, sizeof(PublicCertPath));
	PublicCertPath[sizeof(PublicCertPath)-1] = '\0';
	if(strlen(PublicCertPath) + 4 < sizeof(PublicCertPath)){
	  strncat(PublicCertPath, EXTCERT(Public), 5);
	  PublicCertPath[sizeof(PublicCertPath)-1] = '\0';
	}
	/* attempt #1, use provided certificate, 
	 * assumption is that full_name_cert is the file that this
	 * certificate derives from (which is obtained by substitution
	 * of .key extension in key by .crt extension)
	 */
	if(cert != NULL)  /* attempt #1 */
	    use_this_file = &full_name_cert[0];
	else if((ins = BIO_new_file(full_name_cert, "r")) != NULL){
	/* attempt #2 to guess public cert name, use .crt extension */
	    if((cert = PEM_read_bio_X509(ins, NULL, NULL, NULL)) != NULL){
	    use_this_file = &full_name_cert[0];
	    }
	}
	else{ /* attempt #3 to guess public cert name: use the original key */
	  if((ins = BIO_new_file(full_name_key, "r")) != NULL){
	    if((cert = PEM_read_bio_X509(ins, NULL, NULL, NULL)) != NULL){
	       use_this_file = &full_name_key[0];
	    }
	  }
	  else {
	   int done = 0;
	    /* attempt #4, ask the user */
	   do {
	      r = (*pith_smime_import_certificate)(filename, use_this_file, "certificate", sizeof(filename) - 20);
	      if(r < 0){
		 if(ins != NULL) BIO_free(ins);
		 if(cert != NULL) X509_free(cert);
		 return 0;
	      }
	      if((ins = BIO_new_file(use_this_file, "r")) != NULL){
		if((cert = PEM_read_bio_X509(ins, NULL, NULL, NULL)) != NULL)
		  done++;
		else
		  q_status_message(SM_ORDER, 1, 3, _("Error parsing certificate"));
	      }
	      else 
		  q_status_message(SM_ORDER, 1, 3, _("Error reading certificate"));
	   } while (done == 0);
	  }
	}
	if(ins != NULL){
	   if(cert != NULL){	/* check that certificate matches key */
	      if(!X509_check_private_key(cert, key)){
		rc = 0;
		q_status_message(SM_ORDER, 1, 3, _("Certificate does not match key"));
	      }
	      else
		 rc = 1;	/* Success! */
	   }
	   else
	     q_status_message(SM_ORDER, 1, 3, _("Error in certificate file (not a certificate?)"));
	}
	if(rc == 1){	/* if everything has been successful, 
			 * copy the files to their final destination */
	   if(our_copy(PrivateKeyPath, full_filename) == 0){	/* <-- save the private key */
	      q_status_message(SM_ORDER, 1, 3, _("Private key saved"));
	      if(our_copy(PublicCertPath, use_this_file) == 0){
		char  tmp[MAILTMPLEN];
	        FILE *fp;

		if(!passfile_name(ps_global->pinerc, tmp, sizeof(tmp)) 
			|| !(fp = our_fopen(tmp, "rb"))){
		   q_status_message(SM_ORDER, 1, 3, _("Error reading password file!"));
		   rc = 0;
	        }
		else {
		   char tmp2[MAILTMPLEN];
		   int encrypted = 0;
		   char *text;
		   PERSONAL_CERT *pwdcert, *pc = p_cert;

		   pwdcert = (PERSONAL_CERT *) ps_global->pwdcert;
		   if(pwdcert == NULL)
		      setup_pwdcert((void **)&pwdcert);

		   tmp2[0] = '\0';
		   fgets(tmp2, sizeof(tmp2), fp);
		   fclose(fp);
		   if(strcmp(tmp2, "-----BEGIN PKCS7-----\n")){
	              if(encrypt_file((char *)tmp, NULL, pwdcert))
	                 encrypted++;
		   }
		   else
		     encrypted++;

		   if(encrypted){
		     text = decrypt_file((char *)tmp, NULL, pwdcert);
		     if(text != NULL){
			if(pc == NULL){
			   pc = fs_get(sizeof(PERSONAL_CERT));
			   memset((void *)pc, 0, sizeof(PERSONAL_CERT));
			   filename[strlen(filename)-strlen(EXTCERT(Private))] = '\0';
			   pc->name = cpystr(filename);
			   snprintf(buf, sizeof(buf), "%s%s", filename, EXTCERT(Public));
			   buf[sizeof(buf)-1] = '\0';
			   pc->cname = cpystr(buf);
			   pc->key  = key; 
			   pc->cert = cert;
			}
			
			if(encrypt_file((char *)tmp, text, pc)){ /* we did it! */
			   build_path(buf, PATHCERTDIR(ctype), pwdcert->name, sizeof(buf));
			   strncat(buf, EXTCERT(Private), 5);
			   buf[sizeof(buf)-1] = '\0';
			   if(strcmp(PrivateKeyPath, buf)){
			      if (unlink(buf) < 0)
				q_status_message(SM_ORDER, 1, 3, _("Failed to remove old key"));
			   }
			   build_path(buf, PATHCERTDIR(ctype), pwdcert->cname, sizeof(buf));
			   if(strcmp(PublicCertPath, buf)){
			      if(unlink(buf) < 0)
				q_status_message(SM_ORDER, 1, 3, _("Failed to remove old certificate"));
			   }
			   free_personal_certs((PERSONAL_CERT **)&ps_global->pwdcert);
			   ps_global->pwdcert = pc;
			   rc = 1;
			   q_status_message(SM_ORDER, 1, 3, _("Password file reencrypted"));
			} else {
			   q_status_message(SM_ORDER, 1, 3, _("Failed to reencrypt password file"));
			   rc = 0;
			}
		     } else {
		        q_status_message(SM_ORDER, 1, 3, _("Error decrypting Password file"));
		     }
		   } else {
		     q_status_message(SM_ORDER, 1, 3, _("Password file not encrypted and could not encrypt"));
		     rc = 0;
		   }
		}
	      }
	      else{
	        q_status_message(SM_ORDER, 1, 3, _("Error saving public certificate"));
		if(our_unlink(PrivateKeyPath) < 0)
		   q_status_message(SM_ORDER, 1, 3, _("Error while cleaning private key"));
	        rc = 0;
	      }
	   }
	   else{
	      rc = 0;
	      q_status_message(SM_ORDER, 1, 3, _("Error saving private key"));
	   }
	   if(ins != NULL) BIO_free(ins);
	   if(rc == 0 && cert != NULL) X509_free(cert);
	}
     } else {
	rc = 0;
	q_status_message(SM_ORDER, 1, 3, _("Error unlocking private key"));
     }

     return rc;
   }
#endif /* PASSFILE */

   smime_init();
   ps_global->mangled_screen = 1;

   if (ctype == Private){
	char prompt[500], *s, *t;
	EVP_PKEY *key = NULL;

	if(!ps_global->smime->privatecertlist){
	  ps_global->smime->privatecertlist = fs_get(sizeof(CertList));
	  memset((void *)DATACERT(ctype), 0, sizeof(CertList));
	}

	for(s = t = filename; (t = strstr(s, ".key")) != NULL; s = t + 1);
	if(s) *(s-1) = 0;

	snprintf(prompt, sizeof(prompt), _("Enter passphrase for <%s>: "), filename);
	prompt[sizeof(prompt)-1] = '\0';
        if((key = load_pkey_with_prompt(full_filename, NULL, prompt, NULL)) != NULL){
	  if(SMHOLDERTYPE(ctype) == Directory){
	    build_path(buf, PATHCERTDIR(ctype), filename, sizeof(buf));
	    if(strcmp(buf + strlen(buf) - 4, EXTCERT(ctype)) != 0 && strlen(buf) + 4 < sizeof(buf)){
	       strncat(buf, EXTCERT(ctype), 5);
	       buf[sizeof(buf)-1] = '\0';
	    }
	    rc = our_copy(buf, full_filename);
	  }
	  else /* if(SMHOLDERTYPE(ctype) == Container){ */
	     rc = add_file_to_container(ctype, full_filename, NULL);
	  if(rc == 0)
	     q_status_message(SM_ORDER, 1, 3, _("Private key saved"));
	  else
	     q_status_message(SM_ORDER, 1, 3, _("Error saving private key"));
	  if(ps_global->smime->publiccertlist)
	     ps_global->smime->publiccertlist->data.renew = 1;
	}
	else
	  q_status_message(SM_ORDER, 1, 3, _("Problem unlocking key (not a certificate or wrong password)"));
   } else  if (ctype == CACert){
      BIO *ins;
      X509 *cert;

      if((ins = BIO_new_file(full_filename, "r")) != NULL){
	if((cert = PEM_read_bio_X509(ins, NULL, NULL, NULL)) != NULL){
	  if(SMHOLDERTYPE(ctype) == Directory){
	    build_path(buf, PATHCERTDIR(ctype), filename, sizeof(buf));
	    if(strcmp(buf + strlen(buf) - 4, ".crt") != 0 && strlen(buf) + 4 < sizeof(buf)){
	       strncat(buf, EXTCERT(ctype), 5);
	       buf[sizeof(buf)-1] = '\0';
	    }

	    rc = our_copy(buf, full_filename);
	  }
	  else /* if(SMHOLDERTYPE(ctype) == Container){ */
	     rc = add_file_to_container(ctype, full_filename, NULL);
	  if(rc == 0)
	      q_status_message(SM_ORDER, 1, 3, _("Certificate saved"));
	  else
	      q_status_message(SM_ORDER, 1, 3, _("Error saving certificate"));
	  X509_free(cert);	/* not needed anymore */
	}
	else
	  q_status_message(SM_ORDER, 1, 3, _("Error in certificate file (not a certificate?)"));
	BIO_free(ins);
      }
      renew_store();
   } else { /* ctype == Public. save certificate, but first validate that it is one */
      BIO *ins;
      X509 *cert;

      if((ins = BIO_new_file(full_filename, "r")) != NULL){
	if((cert = PEM_read_bio_X509(ins, NULL, NULL, NULL)) != NULL){
	  if(SMHOLDERTYPE(ctype) == Directory){
	    char **email;

	    if((email = get_x509_subject_email(cert)) != NULL){
	       int i;
	       for(i = 0; email[i] != NULL; i++){
		  save_cert_for(email[i], cert, Public);
		  fs_give((void **)&email[i]);
	       }
	       fs_give((void **)email);
	    }
	    if(strcmp(filename + strlen(filename) - 4, ".crt") == 0)
	       filename[strlen(filename) - 4] = '\0';
	    save_cert_for(filename, cert, Public);
	  }
	  else  /* if(SMHOLDERTYPE(ctype) == Container){ */
	     add_file_to_container(ctype, full_filename, NULL);
	  X509_free(cert);
	  if(ps_global->smime->publiccertlist)
	     ps_global->smime->publiccertlist->data.renew = 1;
	}
	else
	  q_status_message(SM_ORDER, 1, 3, _("Error in certificate file (not a certificate?)"));
	BIO_free(ins);
      }
   }
   if(DATACERT(ctype)) RENEWCERT(DATACERT(ctype)) = 1;
   return 1;
}

/* itype: information type to add: 0 - public, 1 - private.
 * Memory freed by caller
 */
BIO *
print_private_key_information(char *email, int itype)
{
  BIO *out;
  PERSONAL_CERT *pc;

  if(ps_global->smime == NULL 
	|| ps_global->smime->personal_certs == NULL 
	|| (itype != 0 && itype != 1))
    return NULL;

  for(pc = ps_global->smime->personal_certs;
        pc != NULL && strcmp(pc->name, email) != 0; pc = pc->next);
  if(pc->key == NULL
	&& !load_private_key(pc)
	&& ps_global->smime
	&& ps_global->smime->need_passphrase){
	if (pith_opt_smime_get_passphrase)
	   (*pith_opt_smime_get_passphrase)();
	load_private_key(pc);
  }

  if(pc->key == NULL)
     return NULL;

  out = BIO_new(BIO_s_mem());
  if(itype == 0)		/* 0 means public */
    EVP_PKEY_print_public(out, pc->key, 0, NULL);
  else if (itype == 1)		/* 1 means private */
    EVP_PKEY_print_private(out, pc->key, 0, NULL);

  if(F_OFF(F_REMEMBER_SMIME_PASSPHRASE,ps_global))
    forget_private_keys();

  return out;
}

/*
 * Forget any cached private keys
 */
static void
forget_private_keys(void)
{
    PERSONAL_CERT *pcert;
    size_t len;
    volatile char *p;
    
    dprint((9, "forget_private_keys()"));
    if(ps_global->smime){
	ps_global->smime->already_auto_asked = 0;
	for(pcert=(PERSONAL_CERT *) ps_global->smime->personal_certs;
	    pcert;
	    pcert=pcert->next){

	    if(pcert->key){
		EVP_PKEY_free(pcert->key);
		pcert->key = NULL;
	    }
	}

	ps_global->smime->entered_passphrase = 0;
	len = sizeof(ps_global->smime->passphrase);
	p = ps_global->smime->passphrase;

	while(len-- > 0)
	  *p++ = '\0';
    }
}

/* modelled after signature_path in reply.c, but uses home dir instead of the
 * directory where the .pinerc is located, since according to documentation,
 * the .alpine-smime directories are subdirectories of the home directory
 */
int
smime_path(char *rpath, char *fpath, size_t len)
{
    *fpath = '\0';
    if(rpath && *rpath){
        size_t spl = strlen(rpath);

        if(IS_REMOTE(rpath)){
            if(spl < len - 1)
              strncpy(fpath, rpath, len-1);
            fpath[len-1] = '\0';
        }
        else if(is_absolute_path(rpath)){
            strncpy(fpath, rpath, len-1);
            fpath[len-1] = '\0';
            fnexpand(fpath, len);
        }
        else if(ps_global->VAR_OPER_DIR){
            if(strlen(ps_global->VAR_OPER_DIR) + spl < len - 1)
              build_path(fpath, ps_global->VAR_OPER_DIR, rpath, len);
        }
	else if(ps_global->home_dir){
            if(strlen(ps_global->home_dir) + spl < len - 1)
              build_path(fpath, ps_global->home_dir, rpath, len);
	}
    }
    return fpath && *fpath ? 1 : 0;
}



/*
 * taken from openssl/apps/app_rand.c
 */
static int
app_RAND_load_file(const char *file)
{
#define RANDBUFLEN 200
    char buffer[RANDBUFLEN];

    if(file == NULL)
      file = RAND_file_name(buffer, RANDBUFLEN);

    if(file == NULL || !RAND_load_file(file, -1)){
	if(RAND_status() == 0){
	    dprint((1, "unable to load 'random state'\n"));
	    dprint((1, "This means that the random number generator has not been seeded\n"));
	    dprint((1, "with much random data.\n"));
	}

	return 0;
    }

    seeded = 1;
    return 1;
}


/*
 * copied and fiddled from imap/src/osdep/unix/auth_ssl.c
 */
static void
openssl_extra_randomness(void)
{
#if !defined(WIN32)
    int fd;
    unsigned long i;
    char *tf = NULL;
    char tmp[MAXPATH];
    struct stat sbuf;
				/* if system doesn't have /dev/urandom */
    if(stat ("/dev/urandom", &sbuf)){
      tmp[0] = '0';
      tf = temp_nam(NULL, NULL);
      if(tf){
	strncpy(tmp, tf, sizeof(tmp));
	tmp[sizeof(tmp)-1] = '\0';
	fs_give((void **) &tf);
      }     

      if((fd = open(tmp, O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0)
	i = (unsigned long) tmp;
      else{
	unlink(tmp);		/* don't need the file */
	fstat(fd, &sbuf);	/* get information about the file */
	i = sbuf.st_ino;	/* remember its inode */
	close(fd);		/* or its descriptor */
      }
				/* not great but it'll have to do */
      snprintf(tmp+strlen(tmp), sizeof(tmp)-strlen(tmp), "%.80s%lx%lx%lx",
	       tcp_serverhost (),i,
	       (unsigned long) (time (0) ^ gethostid ()),
	       (unsigned long) getpid ());
      RAND_seed(tmp, strlen(tmp));
    }
#endif
}


/* taken from openssl/apps/app_rand.c */
static int
app_RAND_write_file(const char *file)
{
    char buffer[200];

    if(!seeded)
	/*
	 * If we did not manage to read the seed file,
	 * we should not write a low-entropy seed file back --
	 * it would suppress a crucial warning the next time
	 * we want to use it.
	 */
	return 0;

    if(file == NULL)
      file = RAND_file_name(buffer, sizeof buffer);

    if(file == NULL || !RAND_write_file(file)){
	dprint((1, "unable to write 'random state'\n"));
	return 0;
    }

    return 1;
}

CertList *
certlist_from_personal_certs(PERSONAL_CERT *pc)
{
   CertList *cl;
   X509 *x;

   if(pc == NULL)
     return NULL;
   
   if((x = get_cert_for(pc->name, Public, 1)) != NULL)
     cl = smime_X509_to_cert_info(x, pc->name);
   cl->next = certlist_from_personal_certs(pc->next);

   return cl;
}

void
renew_cert_data(CertList **data, WhichCerts ctype)
{
  smime_init();
  if(ctype == Private){
     if(data){
	PERSONAL_CERT *pc = (PERSONAL_CERT *)ps_global->smime->personal_certs;
	if(*data)
	  free_certlist(data);
	free_personal_certs(&pc);
	setup_privatekey_storage();
        *data = certlist_from_personal_certs((PERSONAL_CERT *)ps_global->smime->personal_certs);
	if(data && *data){
	    resort_certificates(data, ctype);
	    RENEWCERT(*data) = 0;
	}
        ps_global->smime->privatecertlist = *data;
     }
     if(ps_global->smime->privatecertlist)
       RENEWCERT(ps_global->smime->privatecertlist) = 0;
  } else {
    X509_LOOKUP    *lookup = NULL;
    X509_STORE     *store = NULL;

    if((store = X509_STORE_new()) != NULL){
       if((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) != NULL){
 	  free_certlist(data);
	  if(SMHOLDERTYPE(ctype) == Directory)
	    add_certs_in_dir(lookup, PATHCERTDIR(ctype), EXTCERT(ctype), data);
	  else /* if(SMHOLDERTYPE(ctype) == Container) */
	    *data = mem_to_certlist(CONTENTCERTLIST(ctype), ctype);
	  if(data && *data){
	    resort_certificates(data, ctype);
	    RENEWCERT(*data) = 0;
	  }
	  if(ctype == Public)
	    ps_global->smime->publiccertlist = *data;
	  else
	    ps_global->smime->cacertlist = *data;
       }
       free_x509_store(&store);
    }
  }
  setup_certs_backup_by_type(ctype);
}

void
smime_reinit(void)
{
   smime_deinit();
   smime_init();
}

/* Installed as an atexit() handler to save the random data */
void
smime_deinit(void)
{
    dprint((9, "smime_deinit()"));
    app_RAND_write_file(NULL);
    if (s_cert_store != NULL) free_x509_store(&s_cert_store);
#ifdef ERR_free_strings
    ERR_free_strings();
#endif /* ERR_free_strings */
#ifdef EVP_cleanup
    EVP_cleanup();
#endif /* EVP_cleanup */
    free_smime_struct(&ps_global->smime);
}

/* we renew the store when it has changed */
void
renew_store(void)
{
    if(ps_global->smime->inited){
       if(s_cert_store != NULL)
	 free_x509_store(&s_cert_store);
	s_cert_store = get_ca_store();
    }
}

/* Initialise openssl stuff if needed */
void
smime_init(void)
{
    if(F_OFF(F_DONT_DO_SMIME, ps_global) && !(ps_global->smime && ps_global->smime->inited)){

	dprint((9, "smime_init()"));
	if(!ps_global->smime)
	  ps_global->smime = new_smime_struct();

	setup_storage_locations();

	s_cert_store = get_ca_store();
	setup_certs_backup_by_type(CACert);

#ifdef OPENSSL_1_1_0
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS|OPENSSL_INIT_ADD_ALL_DIGESTS|OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#else
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
#endif /* OPENSSL_1_1_0 */

	app_RAND_load_file(NULL);
    	openssl_extra_randomness();
	ps_global->smime->inited = 1;
    }
    
    ERR_clear_error();
}


/* validate a certificate. Return value : 0 for no error, -1 for error.
 * In the latter case, set the openssl smime error in *error.
 */
int
smime_validate_cert(X509 *cert, long *error)
{
   X509_STORE_CTX *csc;

   ERR_clear_error();
   *error = 0;
   if((s_cert_store != NULL) && (csc = X509_STORE_CTX_new()) != NULL){
     X509_STORE_set_flags(s_cert_store, 0);
     if(X509_STORE_CTX_init(csc,s_cert_store,cert,NULL)
	&& X509_verify_cert(csc) <= 0)
	*error   = X509_STORE_CTX_get_error(csc);
     X509_STORE_CTX_free(csc);
   }
   return *error ? -1 : 0;
}

PERSONAL_CERT *
get_personal_certs(char *path)
{
    PERSONAL_CERT *result = NULL;
    char buf2[MAXPATH], *fname;
    X509 *cert;
    size_t ll;
#ifndef _WINDOWS
    struct dirent *d;
    DIR *dirp;
#else /* _WINDOWS */
    struct _finddata_t dbuf;
    char buf[_MAX_PATH + 4];
    long findrv;
#endif /* _WINDOWS */

    ps_global->smime->privatepath = cpystr(path);

#ifndef _WINDOWS
    dirp = opendir(path);
    if(dirp){
	while((d=readdir(dirp)) != NULL){
	   fname = d->d_name;
#else /* _WINDOWS */
    snprintf(buf, sizeof(buf), "%s%s*.*", path, (path[strlen(path)-1] == '\\') ? "" : "\\");
    buf[sizeof(buf)-1] = '\0';
    if((findrv = _findfirst(buf, &dbuf)) < 0)
        return(NULL);
            
    do {
            fname = fname_to_utf8(dbuf.name);
#endif
	    if((ll=strlen(fname)) && ll > 4 && !strcmp(fname+ll-4, ".key")){

		/* copy file name to temp buffer */
		strncpy(buf2, fname, sizeof(buf2)-1);
		buf2[sizeof(buf2)-1] = '\0';
		/* chop off ".key" trailier */
		buf2[strlen(buf2)-4] = '\0';
		/* Look for certificate */
		cert = get_cert_for(buf2, Public, 1);

		if(cert){
		    PERSONAL_CERT *pc;

		    /* create a new PERSONAL_CERT, fill it in */

		    pc = (PERSONAL_CERT *) fs_get(sizeof(*pc));
		    pc->cert = cert;
		    pc->name = cpystr(buf2);
		    strncat(buf2, EXTCERT(Public), 5);
		    pc->cname = cpystr(buf2);

		    /* Try to load the key with an empty password */
		    pc->key = load_key(pc, "", SM_NORMALCERT);

		    pc->next = result;
		    result = pc;
		}
	    }
#ifndef _WINDOWS
	}
	closedir(dirp);
    }
#else /* _WINDOWS */
    } while(_findnext(findrv, &dbuf) == 0);
    _findclose(findrv);
#endif /* !_WINDOWS */
    return result;
}


void
setup_privatekey_storage(void)
{
    char path[MAXPATH+1], *contents;
    int privatekeycontainer = 0;

    /* private keys in a container */
    if(ps_global->VAR_PRIVATEKEY_CONTAINER && ps_global->VAR_PRIVATEKEY_CONTAINER[0]){

	privatekeycontainer = 1;
	contents = NULL;
	path[0] = '\0';
	if(!smime_path(ps_global->VAR_PRIVATEKEY_CONTAINER, path, MAXPATH))
	  privatekeycontainer = 0;

	if(privatekeycontainer && !IS_REMOTE(path)
	   && ps_global->VAR_OPER_DIR
           && !in_dir(ps_global->VAR_OPER_DIR, path)){
	    q_status_message2(SM_ORDER | SM_DING, 3, 4,
			  /* TRANSLATORS: First arg is the directory name, second is
			     the file user wants to read but can't. */
			  _("Can't read file outside %s: %s"),
			  ps_global->VAR_OPER_DIR, path);
	    privatekeycontainer = 0;
	}

	if(privatekeycontainer
	   && (IS_REMOTE(path) || can_access(path, ACCESS_EXISTS) == 0)){
	    if(!(IS_REMOTE(path) && (contents = simple_read_remote_file(path, REMOTE_SMIME_SUBTYPE)))
	       &&
	       !(contents = read_file(path, READ_FROM_LOCALE)))
	      privatekeycontainer = 0;
	}

	if(privatekeycontainer && path[0]){
	    ps_global->smime->privatetype = Container;
	    ps_global->smime->privatepath = cpystr(path);

	    if(contents){
		ps_global->smime->privatecontent = contents;
		ps_global->smime->personal_certs = mem_to_personal_certs(contents);
	    }
	}
    }

    /* private keys in a directory of files */
    if(!privatekeycontainer){
	ps_global->smime->privatetype = Directory;

	path[0] = '\0';
	if(!(smime_path(ps_global->VAR_PRIVATEKEY_DIR, path, MAXPATH)
	     && !IS_REMOTE(path)))
	  ps_global->smime->privatetype = Nada;
	else if(can_access(path, ACCESS_EXISTS)){
	    if(our_mkpath(path, 0700)){
		q_status_message1(SM_ORDER, 3, 3, _("Can't create directory %s"), path);
		ps_global->smime->privatetype = Nada;
	    }
	}

	if(ps_global->smime->privatetype == Directory)
	   ps_global->smime->personal_certs = get_personal_certs(path);
    }
    setup_certs_backup_by_type(Private);
}

static void
setup_storage_locations(void)
{
    int publiccertcontainer = 0, cacertcontainer = 0;
    char path[MAXPATH+1], *contents;

    if(!ps_global->smime)
      return;

#ifdef APPLEKEYCHAIN
    if(F_ON(F_PUBLICCERTS_IN_KEYCHAIN, ps_global)){
	ps_global->smime->publictype = Keychain;
    }
    else{
#endif /* APPLEKEYCHAIN */
    /* Public certificates in a container */
    if(ps_global->VAR_PUBLICCERT_CONTAINER && ps_global->VAR_PUBLICCERT_CONTAINER[0]){

	publiccertcontainer = 1;
	contents = NULL;
	path[0] = '\0';
	if(!smime_path(ps_global->VAR_PUBLICCERT_CONTAINER, path, MAXPATH))
	  publiccertcontainer = 0;

	if(publiccertcontainer && !IS_REMOTE(path)
	   && ps_global->VAR_OPER_DIR
           && !in_dir(ps_global->VAR_OPER_DIR, path)){
	    q_status_message2(SM_ORDER | SM_DING, 3, 4,
			  /* TRANSLATORS: First arg is the directory name, second is
			     the file user wants to read but can't. */
			  _("Can't read file outside %s: %s"),
			  ps_global->VAR_OPER_DIR, path);
	    publiccertcontainer = 0;
	}

	if(publiccertcontainer
	   && (IS_REMOTE(path) || can_access(path, ACCESS_EXISTS) == 0)){
	    if(!(IS_REMOTE(path) && (contents = simple_read_remote_file(path, REMOTE_SMIME_SUBTYPE)))
	       &&
	       !(contents = read_file(path, READ_FROM_LOCALE)))
	      publiccertcontainer = 0;
	}

	if(publiccertcontainer && path[0]){
	    ps_global->smime->publictype = Container;
	    ps_global->smime->publicpath = cpystr(path);

	    if(contents){
		ps_global->smime->publiccontent = contents;
		ps_global->smime->publiccertlist = mem_to_certlist(contents, Public);
	    }
	}
    }

    /* Public certificates in a directory of files */
    if(!publiccertcontainer){
	ps_global->smime->publictype = Directory;

	path[0] = '\0';
	if(!(smime_path(ps_global->VAR_PUBLICCERT_DIR, path, MAXPATH)
	     && !IS_REMOTE(path)))
	  ps_global->smime->publictype = Nada;
	else if(can_access(path, ACCESS_EXISTS)){
	    if(our_mkpath(path, 0700)){
		q_status_message1(SM_ORDER, 3, 3, _("Can't create directory %s"), path);
		ps_global->smime->publictype = Nada;
	    }
	}

	if(ps_global->smime->publictype == Directory)
	  ps_global->smime->publicpath = cpystr(path);
    }

#ifdef APPLEKEYCHAIN
    }
#endif /* APPLEKEYCHAIN */

    setup_privatekey_storage();

    /* extra cacerts in a container */
    if(ps_global->VAR_CACERT_CONTAINER && ps_global->VAR_CACERT_CONTAINER[0]){

	cacertcontainer = 1;
	contents = NULL;
	path[0] = '\0';
	if(!smime_path(ps_global->VAR_CACERT_CONTAINER, path, MAXPATH))
	  cacertcontainer = 0;

	if(cacertcontainer && !IS_REMOTE(path)
	   && ps_global->VAR_OPER_DIR
           && !in_dir(ps_global->VAR_OPER_DIR, path)){
	    q_status_message2(SM_ORDER | SM_DING, 3, 4,
			  /* TRANSLATORS: First arg is the directory name, second is
			     the file user wants to read but can't. */
			  _("Can't read file outside %s: %s"),
			  ps_global->VAR_OPER_DIR, path);
	    cacertcontainer = 0;
	}

	if(cacertcontainer
	   && (IS_REMOTE(path) || can_access(path, ACCESS_EXISTS) == 0)){
	    if(!(IS_REMOTE(path) && (contents = simple_read_remote_file(path, REMOTE_SMIME_SUBTYPE)))
	       &&
	       !(contents = read_file(path, READ_FROM_LOCALE)))
	      cacertcontainer = 0;
	}

	if(cacertcontainer && path[0]){
	    ps_global->smime->catype = Container;
	    ps_global->smime->capath = cpystr(path);
	    ps_global->smime->cacontent = contents;
	    if(contents)
	      ps_global->smime->cacertlist = mem_to_certlist(contents, CACert);
	}
    }

    if(!cacertcontainer){
	ps_global->smime->catype = Directory;

	path[0] = '\0';
	if(!(smime_path(ps_global->VAR_CACERT_DIR, path, MAXPATH)
	     && !IS_REMOTE(path)))
	  ps_global->smime->catype = Nada;
	else if(can_access(path, ACCESS_EXISTS)){
	    if(our_mkpath(path, 0700)){
		q_status_message1(SM_ORDER, 3, 3, _("Can't create directory %s"), path);
		ps_global->smime->catype = Nada;
	    }
	}

	if(ps_global->smime->catype == Directory)
	  ps_global->smime->capath = cpystr(path);
    }
}


int
copy_publiccert_dir_to_container(void)
{
    return(copy_dir_to_container(Public, NULL));
}


int
copy_publiccert_container_to_dir(void)
{
    return(copy_container_to_dir(Public));
}


int
copy_privatecert_dir_to_container(void)
{
    return(copy_dir_to_container(Private, NULL));
}


int
copy_privatecert_container_to_dir(void)
{
    return(copy_container_to_dir(Private));
}


int
copy_cacert_dir_to_container(void)
{
    return(copy_dir_to_container(CACert, NULL));
}


int
copy_cacert_container_to_dir(void)
{
    return(copy_container_to_dir(CACert));
}

/* Add the contents of a file to a container. Do not check the content
 * of the file, just add it using the format for that container. The
 * caller must check the format, so that there is no data corruption
 * in the future.
 * return value: 0 - success,
 *               != 0 - failure.
 */
int
add_file_to_container(WhichCerts ctype, char *fpath, char *altname)
{
    char *sep = (ctype == Public || ctype == Private)
                ? EMAILADDRLEADER : CACERTSTORELEADER;
    char *content = ctype == Public ? ps_global->smime->publiccontent
		    : (ctype == Private ? ps_global->smime->privatecontent
		    : ps_global->smime->cacontent);
    char *name;
    char *s;
    unsigned char c;
    struct stat sbuf;
    STORE_S *in = NULL;
    int rv = -1; 	/* assume error */
    size_t clen;	/* content buffer size */

    if(our_stat(fpath, &sbuf) < 0 
	|| (in = so_get(FileStar, fpath, READ_ACCESS | READ_FROM_LOCALE)) == NULL)
      goto endadd;

    if(altname != NULL)
      name = altname;
    else if((name = strrchr(fpath, '/')) != NULL){
      size_t ll;
      if((ll = strlen(++name)) > 4 && strucmp(name + ll - 4, EXTCERT(ctype)) == 0)
        name[ll-strlen(EXTCERT(ctype))] = '\0';
    }
    else 
      goto endadd;

    if(content){
      clen = strlen(content) + strlen(sep) + strlen(name) + sbuf.st_size + 2*strlen(NEWLINE) + 1;
      fs_resize((void **)&content, clen);
      s = content;
      content += strlen(content);
    }
    else{
      clen = strlen(sep) + strlen(name) + sbuf.st_size + strlen(NEWLINE) + 1;
      s = content = fs_get(clen);
      *content = '\0';
    }
    strncat(content, sep, clen - strlen(content));
    strncat(content, name, clen - strlen(content));
    content += strlen(content);
#ifdef _WINDOWS
    *content++ = '\r';
#endif /* _WINDOWS */
    *content++ = '\n';

    while(so_readc(&c, in))
       *content++ = (char) c;
    *content = '\0';

    switch(ctype){
      case Private:   ps_global->smime->privatecontent = s; break;
      case Public :   ps_global->smime->publiccontent = s; break;
      case CACert :   ps_global->smime->cacontent = s; break;
      default : break;
    }

    rv = copy_dir_to_container(ctype, s);

endadd: 
    if(in) so_give(&in);

    return rv;
}


/*
 * returns 0 on success, -1 on failure
 * contents is an argument which tells this function to write the value
 * of this variable instead of reading the contents of the directory.
 * If the var contents is not null use its value as the value of the 
 * container.
 */
int
copy_dir_to_container(WhichCerts which, char *contents)
{
    int ret = 0, container = 0;
    BIO *bio_out = NULL, *bio_in = NULL;
    char srcpath[MAXPATH+1], dstpath[MAXPATH+1], emailaddr[MAXPATH], file[MAXPATH], line[4096];
    char *tempfile = NULL, fpath[MAXPATH+1], *fname;
    size_t ll;
#ifndef _WINDOWS
    DIR *dirp;
    struct dirent *d;
#else /* _WINDOWS */
    struct _finddata_t dbuf;
    char buf[_MAX_PATH + 4];
    long findrv;
#endif /* _WINDOWS */
    REMDATA_S *rd = NULL;
    char *configdir = NULL;
    char *configpath = NULL;
    char *configcontainer = NULL;
    char *filesuffix = NULL;
    char *ret_dir = NULL;

    dprint((9, "copy_dir_to_container(%s)", which==Public ? "Public" : which==Private ? "Private" : which==CACert ? "CACert" : "?"));
    smime_init();

    srcpath[0] = '\0';
    dstpath[0] = '\0';
    file[0] = '\0';
    emailaddr[0] = '\0';

    if(which == Public){
	configdir  = ps_global->VAR_PUBLICCERT_DIR;
	configpath = ps_global->smime->publicpath;
	configcontainer = cpystr(DF_PUBLIC_CONTAINER);
	filesuffix = ".crt";
    }
    else if(which == Private){
	configdir = ps_global->VAR_PRIVATEKEY_DIR;
	configpath = ps_global->smime->privatepath;
	configcontainer = cpystr(DF_PRIVATE_CONTAINER);
	filesuffix = ".key";
    }
    else if(which == CACert){
	configdir = ps_global->VAR_CACERT_DIR;
	configpath = ps_global->smime->capath;
	configcontainer = cpystr(DF_CA_CONTAINER);
	filesuffix = ".crt";
    }
    container = SMHOLDERTYPE(which) == Container;

    if(!(configdir && configdir[0])){
	q_status_message(SM_ORDER, 3, 3, _("Directory not defined"));
	return -1;
    }

    if(!(configpath && configpath[0])){
#ifdef APPLEKEYCHAIN
	if(which == Public && F_ON(F_PUBLICCERTS_IN_KEYCHAIN, ps_global)){
	    q_status_message(SM_ORDER, 3, 3, _("Turn off the Keychain feature above first"));
	    return -1;
	}
#endif /* APPLEKEYCHAIN */
	q_status_message(SM_ORDER, 3, 3, _("Container path is not defined"));
	return -1;
    }

    if(!(filesuffix && strlen(filesuffix) == 4)){
	return -1;
    }


    /*
     * If there is a legit directory to read from set up the
     * container file to write to.
     */
    if(smime_path(configdir, srcpath, MAXPATH) && !IS_REMOTE(srcpath)){

	if(IS_REMOTE(configpath)){
	    rd = rd_create_remote(RemImap, configpath, REMOTE_SMIME_SUBTYPE,
				  NULL, "Error: ",
				  _("Can't access remote smime configuration."));
	    if(!rd)
	      return -1;
	    
	    (void) rd_read_metadata(rd);

	    if(rd->access == MaybeRorW){
		if(rd->read_status == 'R')
		  rd->access = ReadOnly;
		else
		  rd->access = ReadWrite;
	    }

	    if(rd->access != NoExists){

		rd_check_remvalid(rd, 1L);

		/*
		 * If the cached info says it is readonly but
		 * it looks like it's been fixed now, change it to readwrite.
		 */
		if(rd->read_status == 'R'){
		    rd_check_readonly_access(rd);
		    if(rd->read_status == 'W'){
			rd->access = ReadWrite;
			rd->flags |= REM_OUTOFDATE;
		    }
		    else
		      rd->access = ReadOnly;
		}
	    }

	    if(rd->flags & REM_OUTOFDATE){
		if(rd_update_local(rd) != 0){

		    dprint((1, "copy_dir_to_container: rd_update_local failed\n"));
		    rd_close_remdata(&rd);
		    return -1;
		}
	    }
	    else
	      rd_open_remote(rd);

	    if(rd->access != ReadWrite || rd_remote_is_readonly(rd)){
		rd_close_remdata(&rd);
		return -1;
	    }

	    rd->flags |= DO_REMTRIM;

	    strncpy(dstpath, rd->lf, sizeof(dstpath)-1);
	    dstpath[sizeof(dstpath)-1] = '\0';
	}
	else{
	    strncpy(dstpath, configpath, sizeof(dstpath)-1);
	    dstpath[sizeof(dstpath)-1] = '\0';
	}

	/*
	 * dstpath is either the local Container file or the local cache file
	 * for the remote Container file.
	 */
	tempfile = tempfile_in_same_dir(dstpath, "az", &ret_dir);
    }

    /*
     * If there is a legit directory to read from and a tempfile
     * to write to we continue.
     */
    if(tempfile && (bio_out=BIO_new_file(tempfile, "w")) != NULL){

	if(contents != NULL){
	   if(BIO_puts(bio_out, contents) < 0)
	     ret = -1;
	}
	else {
#ifndef _WINDOWS
	  if((dirp = opendir(srcpath)) != NULL){

	    while((d=readdir(dirp)) && !ret){
		fname = d->d_name;
#else /* _WINDOWS */
    	  snprintf(buf, sizeof(buf), "%s%s*.*", srcpath, (srcpath[strlen(srcpath)-1] == '\\') ? "" : "\\");
	  buf[sizeof(buf)-1] = '\0';
	  if((findrv = _findfirst(buf, &dbuf)) < 0)
	        return -1;
            
	  do{
                fname = fname_to_utf8(dbuf.name);
#endif /* ! _WINDOWS */
		if((ll=strlen(fname)) && ll > 4 && !strcmp(fname+ll-4, filesuffix)){

		    /* copy file name to temp buffer */
		    strncpy(emailaddr, fname, sizeof(emailaddr)-1);
		    emailaddr[sizeof(emailaddr)-1] = '\0';
		    /* chop off suffix trailier */
		    emailaddr[strlen(emailaddr)-4] = 0;

		    /*
		     * This is the separator between the contents of
		     * different files.
		     */
		    if(which == CACert){
			if(!((BIO_puts(bio_out, CACERTSTORELEADER) > 0)
			     && (BIO_puts(bio_out, emailaddr) > 0)
			     && (BIO_puts(bio_out, NEWLINE) > 0)))
			  ret = -1;
		    }
		    else{
			if(!((BIO_puts(bio_out, EMAILADDRLEADER) > 0)
			     && (BIO_puts(bio_out, emailaddr) > 0)
			     && (BIO_puts(bio_out, NEWLINE) > 0)))
			  ret = -1;
		    }

		    /* read then write contents of file */
		    build_path(file, srcpath, fname, sizeof(file));
		    if(!(bio_in = BIO_new_file(file, "r")))
		      ret = -1;

		    if(!ret){
			int good_stuff = 0;

			while(BIO_gets(bio_in, line, sizeof(line)) > 0){
			    if(strncmp("-----BEGIN", line, strlen("-----BEGIN")) == 0)
			      good_stuff = 1;

			    if(good_stuff)
			      BIO_puts(bio_out, line);

			    if(strncmp("-----END", line, strlen("-----END")) == 0)
			      good_stuff = 0;
			}
		    }

		    BIO_free(bio_in);
		}
#ifndef _WINDOWS
	    }
	    closedir(dirp);
	  }
#else /* _WINDOWS */
	    } while (_findnext(findrv, &dbuf) == 0);
		_findclose(findrv);
#endif /* ! _WINDOWS */
	}

	BIO_free(bio_out);

	if(!ret){
	    if(container && configpath && *configpath){
	      strncpy(fpath, configpath, sizeof(fpath));
	      fpath[sizeof(fpath) - 1] = '\0';
	    }
	    else if(ret_dir){  
                if(strlen(dstpath) + strlen(configcontainer) - strlen(ret_dir) + 1 < sizeof(dstpath))
                   snprintf(fpath, sizeof(fpath), "%s%c%s",
                        dstpath, tempfile[strlen(ret_dir)], configcontainer);
                else
                   ret = -1;  
            }
            else ret = -1;

	    if(!ret){
	      if(!IS_REMOTE(configpath)){
		if(rename_file(tempfile, fpath) < 0){
		   q_status_message2(SM_ORDER, 3, 3,
		      _("Can't rename %s to %s"), tempfile, fpath);
		   ret = -1;
	        } else q_status_message1(SM_ORDER, 3, 3,
		      _("saved container to %s"), fpath);
	      }
	      else { /* if the container is remote, copy it */
		int   e;
		char datebuf[200];

		if(rd != NULL && rename_file(tempfile, rd->lf) < 0){
		   q_status_message2(SM_ORDER, 3, 3,
		      _("Can't rename %s to %s"), tempfile, rd->lf);
		   ret = -1;
		}
		
		datebuf[0] = '\0';

		if((e = rd_update_remote(rd, datebuf)) != 0){
		    if(e == -1){
			q_status_message2(SM_ORDER | SM_DING, 3, 5,
			  _("Error opening temporary smime file %s: %s"),
			    rd->lf, error_description(errno));
			dprint((1,
			   "write_remote_smime: error opening temp file %s\n",
			   rd->lf ? rd->lf : "?"));
		    }
		    else{
			q_status_message2(SM_ORDER | SM_DING, 3, 5,
					_("Error copying to %s: %s"),
					rd->rn, error_description(errno));
			dprint((1,
			  "write_remote_smime: error copying from %s to %s\n",
			  rd->lf ? rd->lf : "?", rd->rn ? rd->rn : "?"));
		    }
		    
		    q_status_message(SM_ORDER | SM_DING, 5, 5,
       _("Copy of smime key to remote folder failed, NOT saved remotely"));
		}
		else{
		    rd_update_metadata(rd, datebuf);
		    rd->read_status = 'W';
		}

		rd_close_remdata(&rd);
	      }
	    }
	}
    }

    if(tempfile)
      fs_give((void **) &tempfile);

    if(ret_dir) 
      fs_give((void **) &ret_dir);

    if(configcontainer)
      fs_give((void **) &configcontainer);

    return ret;
}


/*
 * returns 0 on success, -1 on failure
 */
int
copy_container_to_dir(WhichCerts which)
{
    char  path[MAXPATH+1], file[MAXPATH+1], buf[MAXPATH+1];
    char  iobuf[4096];
    char *contents = NULL;
    char *leader = NULL;
    char *filesuffix = NULL;
    char *configdir = NULL;
    char *configpath = NULL;
    char *tempfile = NULL;
    char *p, *q, *line, *name, *certtext, *save_p;
    int  len;
    BIO *in, *out;

    dprint((9, "copy_container_to_dir(%s)", which==Public ? "Public" : which==Private ? "Private" : which==CACert ? "CACert" : "?"));
    smime_init();

    path[0] = '\0';

    if(which == Public){
	leader = EMAILADDRLEADER;
	contents  = ps_global->smime->publiccontent;
	configdir  = ps_global->VAR_PUBLICCERT_DIR;
	configpath = ps_global->smime->publicpath;
	filesuffix = ".crt";
	if(!(configpath && configpath[0])){
#ifdef APPLEKEYCHAIN
	    if(which == Public && F_ON(F_PUBLICCERTS_IN_KEYCHAIN, ps_global)){
		q_status_message(SM_ORDER, 3, 3, _("Turn off the Keychain feature above first"));
		return -1;
	    }
#endif /* APPLEKEYCHAIN */
	    q_status_message(SM_ORDER, 3, 3, _("Container path is not defined"));
	    return -1;
	}

	fs_give((void **) &ps_global->smime->publicpath);

	path[0] = '\0';
	if(!(smime_path(ps_global->VAR_PUBLICCERT_DIR, path, MAXPATH)
	     && !IS_REMOTE(path))){
	    q_status_message(SM_ORDER, 3, 3, _("Directory is not defined"));
	    return -1;
	}

	if(can_access(path, ACCESS_EXISTS)){
	    if(our_mkpath(path, 0700)){
		q_status_message1(SM_ORDER, 3, 3, _("Can't create directory %s"), path);
		return -1;
	    }
	}

	ps_global->smime->publicpath = cpystr(path);
	configpath = ps_global->smime->publicpath;
    }
    else if(which == Private){
	leader = EMAILADDRLEADER;
	contents  = ps_global->smime->privatecontent;
	configdir = ps_global->VAR_PRIVATEKEY_DIR;
	configpath = ps_global->smime->privatepath;
	filesuffix = ".key";
	if(!(configpath && configpath[0])){
	    q_status_message(SM_ORDER, 3, 3, _("Container path is not defined"));
	    return -1;
	}

	fs_give((void **) &ps_global->smime->privatepath);

	path[0] = '\0';
	if(!(smime_path(ps_global->VAR_PRIVATEKEY_DIR, path, MAXPATH)
	     && !IS_REMOTE(path))){
	    q_status_message(SM_ORDER, 3, 3, _("Directory is not defined"));
	    return -1;
	}

	if(can_access(path, ACCESS_EXISTS)){
	    if(our_mkpath(path, 0700)){
		q_status_message1(SM_ORDER, 3, 3, _("Can't create directory %s"), path);
		return -1;
	    }
	}

	ps_global->smime->privatepath = cpystr(path);
	configpath = ps_global->smime->privatepath;
    }
    else if(which == CACert){
	leader = CACERTSTORELEADER;
	contents  = ps_global->smime->cacontent;
	configdir = ps_global->VAR_CACERT_DIR;
	configpath = ps_global->smime->capath;
	filesuffix = ".crt";
	if(!(configpath && configpath[0])){
	    q_status_message(SM_ORDER, 3, 3, _("Container path is not defined"));
	    return -1;
	}

	fs_give((void **) &ps_global->smime->capath);

	path[0] = '\0';
	if(!(smime_path(ps_global->VAR_CACERT_DIR, path, MAXPATH)
	     && !IS_REMOTE(path))){
	    q_status_message(SM_ORDER, 3, 3, _("Directory is not defined"));
	    return -1;
	}

	if(can_access(path, ACCESS_EXISTS)){
	    if(our_mkpath(path, 0700)){
		q_status_message1(SM_ORDER, 3, 3, _("Can't create directory %s"), path);
		return -1;
	    }
	}

	ps_global->smime->capath = cpystr(path);
	configpath = ps_global->smime->capath;
    }

    if(!(configdir && configdir[0])){
	q_status_message(SM_ORDER, 3, 3, _("Directory not defined"));
	return -1;
    }

    if(!(configpath && configpath[0])){
	q_status_message(SM_ORDER, 3, 3, _("Container path is not defined"));
	return -1;
    }

    if(!(filesuffix && strlen(filesuffix) == 4)){
	return -1;
    }


    if(contents && *contents){
	for(p = contents; *p != '\0';){
	    line = p;

	    while(*p && *p != '\n')
	      p++;

	    save_p = NULL;
	    if(*p == '\n'){
		save_p = p;
		*p++ = '\0';
	    }

	    if(strncmp(leader, line, strlen(leader)) == 0){
		name = line + strlen(leader);
		certtext = p;
		if(strncmp("-----BEGIN", certtext, strlen("-----BEGIN")) == 0){
		    if((q = strstr(certtext, leader)) != NULL){
			p = q;
		    }
		    else{		/* end of file */
			q = certtext + strlen(certtext);
			p = q;
		    }

		    strncpy(buf, name, sizeof(buf)-5);
		    buf[sizeof(buf)-5] = '\0';
		    strncat(buf, filesuffix, 5);
		    build_path(file, configpath, buf, sizeof(file));

		    in = BIO_new_mem_buf(certtext, q-certtext);
		    if(in){
			tempfile = tempfile_in_same_dir(file, "az", NULL);
			out = NULL;
			if(tempfile)
			  out = BIO_new_file(tempfile, "w");

			if(out){
			    while((len = BIO_read(in, iobuf, sizeof(iobuf))) > 0)
			      BIO_write(out, iobuf, len);

			    BIO_free(out);

			    if(rename_file(tempfile, file) < 0){
				q_status_message2(SM_ORDER, 3, 3,
				                  _("Can't rename %s to %s"),
						  tempfile, file);
				return -1;
			    }

			    fs_give((void **) &tempfile);
			}
			  
			BIO_free(in);
		    }
		}
	    }

	    if(save_p)
	      *save_p = '\n';
	}
    }

    return 0;
}


#ifdef APPLEKEYCHAIN

int
copy_publiccert_container_to_keychain(void)
{
    /* NOT IMPLEMNTED */
    return -1;
}

int
copy_publiccert_keychain_to_container(void)
{
    /* NOT IMPLEMNTED */
    return -1;
}

#endif /* APPLEKEYCHAIN */


/*
 * Get a pointer to a string describing the most recent OpenSSL error.
 * It's statically allocated, so don't change or attempt to free it.
 */
static const char *
openssl_error_string(void)
{
    char	*errs;
    const char	*data = NULL;
    long errn;

    errn = ERR_peek_error_line_data(NULL, NULL, &data, NULL);
    errs = (char*) ERR_reason_error_string(errn);

    if(errs)
      return errs;
    else if(data)
      return data;

    return "unknown error";
}


/* Return true if the body looks like a PKCS7 object */
int
is_pkcs7_body(BODY *body)
{
    int result;

    result = body->type==TYPEAPPLICATION &&
             body->subtype &&
             (strucmp(body->subtype,"pkcs7-mime")==0 ||
              strucmp(body->subtype,"x-pkcs7-mime")==0 ||
	      strucmp(body->subtype,"pkcs7-signature")==0 ||
	      strucmp(body->subtype,"x-pkcs7-signature")==0);

    return result;
}


/*
 * Recursively stash a pointer to the decrypted data in our
 * manufactured body.
 * parameters: type: call of type 1, save the base and header for multipart messages
		     call of type 0, do not save the base and header for multipart messages
 */
static void
create_local_cache(char *h, char *base, BODY *b, int type)
{
    if(b->type==TYPEMULTIPART){
        PART *p;

        if(type == 1){
	  cpytxt(&b->mime.text, h+b->mime.offset, b->mime.text.size);
	  cpytxt(&b->contents.text, base + b->contents.offset, b->size.bytes);
	} else if(type == 0){
	/*
	 * We don't really want to copy the real body contents. It shouldn't be
	 * used, and in the case of a message with attachments, we'll be 
	 * duplicating the files multiple times.
	 */
	  cpytxt(&b->contents.text, "BODY UNAVAILABLE", 16);

          for(p=b->nested.part; p; p=p->next)
            create_local_cache(h, base, (BODY *) p, type);
	}
    }
    else{
	cpytxt(&b->mime.text, h+b->mime.offset, b->mime.text.size);
        cpytxt(&b->contents.text, base + b->contents.offset, b->size.bytes);
    }
}


static long
rfc822_output_func(void *b, char *string)
{
    BIO *bio = (BIO *) b;

    return(string ? *string ? (BIO_puts(bio, string) >  0 ? 1L : 0L) 
			    : (BIO_puts(bio, string) >= 0 ? 1L : 0L)  
		  : 0L);
}


/*
 * Attempt to load the private key for the given PERSONAL_CERT.
 * This sets the appropriate passphrase globals in order to
 * interact with the user correctly.
 */
static int
load_private_key(PERSONAL_CERT *pcert)
{
    if(!pcert->key){
    
    	/* Try empty password by default */
    	char	*password = "";
    
    	if(ps_global->smime
           && (ps_global->smime->need_passphrase
               || ps_global->smime->entered_passphrase)){
	    /* We've already been in here and discovered we need a different password */
	    
	    if(ps_global->smime->entered_passphrase)
    	      password = (char *) ps_global->smime->passphrase;	/* already entered */
	    else
	      return 0;
	}

        ERR_clear_error();

        if(!(pcert->key = load_key(pcert, password, SM_NORMALCERT))){
            long err = ERR_get_error();

    	    /* Couldn't load key... */

	    if(ps_global->smime && ps_global->smime->entered_passphrase){

    	    	/* The user got the password wrong maybe? */

        	if((ERR_GET_LIB(err)==ERR_LIB_EVP && ERR_GET_REASON(err)==EVP_R_BAD_DECRYPT) ||
                	(ERR_GET_LIB(err)==ERR_LIB_PEM && ERR_GET_REASON(err)==PEM_R_BAD_DECRYPT))
                  q_status_message(SM_ORDER | SM_DING, 4, 4, _("Incorrect passphrase"));
        	else
		  q_status_message1(SM_ORDER, 4, 4, _("Couldn't read key: %s"),(char*)openssl_error_string());
    	    	
		/* This passphrase is no good; forget it */
		ps_global->smime->entered_passphrase = 0;
	    }
	    
	    if(ps_global->smime){
	    /* Indicate to the UI that we need re-entry (see mailcmd.c:process_cmd())*/
		ps_global->smime->need_passphrase = 1;
		if(ps_global->smime->passphrase_emailaddr){
		  int i;
		  for(i = 0; ps_global->smime->passphrase_emailaddr[i] != NULL; i++)
		     fs_give((void **)&ps_global->smime->passphrase_emailaddr[i]);
		  fs_give((void **) ps_global->smime->passphrase_emailaddr);
		}

		ps_global->smime->passphrase_emailaddr = get_x509_subject_email(pcert->cert);
	    }

            return 0;
        }
	else{
	    /* This key will be cached, so we won't be called again */
	    if(ps_global->smime){
		ps_global->smime->entered_passphrase = 0;
		ps_global->smime->need_passphrase = 0;
	    }
	}
	
	return 1;
    }
    
    return 0;
}


static void
setup_pkcs7_body_for_signature(BODY *b, char *description, char *type, char *filename, char *smime_type)
{
    b->type = TYPEAPPLICATION;
    b->subtype = cpystr(type);
    b->encoding = ENCBINARY;
    b->description = cpystr(description);

    b->disposition.type = cpystr("attachment");
    set_parameter(&b->disposition.parameter, "filename", filename);

    set_parameter(&b->parameter, "name", filename);
    if(smime_type && *smime_type)
      set_parameter(&b->parameter, "smime-type", smime_type);
}


/*
 * Look for a personal certificate matching the 
 * given address
 */
PERSONAL_CERT *
match_personal_cert_to_email(ADDRESS *a)
{
    PERSONAL_CERT   *pcert = NULL;
    char	buf[MAXPATH];
    char    	**email;
    int i, done;

    if(!a || !a->mailbox || !a->host)
      return NULL;
    
    snprintf(buf, sizeof(buf), "%s@%s", a->mailbox, a->host);
    
    if(ps_global->smime){
	for(pcert=(PERSONAL_CERT *) ps_global->smime->personal_certs;
	    pcert;
	    pcert=pcert->next){
	
	    if(!pcert->cert)
	      continue;
	
	    email = get_x509_subject_email(pcert->cert);

	    done = 0;
	    if(email != NULL){
		for(i = 0; email[i] && strucmp(email[i], buf) != 0; i++);
		if(email[i] != NULL) done++;
		for(i = 0; email[i] != NULL; i++)
		   fs_give((void **)&email[i]);
		fs_give((void **)email);
	    }

	    if(done > 0)
	      break;
	}
    }
    
    return pcert;
}


/*
 * Look for a personal certificate matching the from
 * (or reply_to? in the given envelope)
 */
PERSONAL_CERT *
match_personal_cert(ENVELOPE *env)
{
    PERSONAL_CERT   *pcert;
    
    pcert = match_personal_cert_to_email(env->reply_to);
    if(!pcert)
      pcert = match_personal_cert_to_email(env->from);
        
    return pcert;
}


/*
 * Flatten the given body into its MIME representation.
 * Return the result in a BIO.
 */
static BIO *
body_to_bio(BODY *body)
{
    BIO *bio = NULL;
    int  len;

    bio = BIO_new(BIO_s_mem());
    if(!bio)
      return NULL;
    
    pine_encode_body(body); /* this attaches random boundary strings to multiparts */
    pine_write_body_header(body, rfc822_output_func, bio);
    pine_rfc822_output_body(body, rfc822_output_func, bio);

    /*
     * Now need to truncate by two characters since the above
     * appends CRLF.
     */
    if((len=BIO_ctrl_pending(bio)) > 1){
	BUF_MEM *biobuf = NULL;

	/* this code used to truncate without closing the bio, and 
	   then resetting the memory, causing non validation in
	   signatures. Fix contributed by Bernd Edlinger.
	 */
	BIO_get_mem_ptr(bio, &biobuf);
	BIO_set_close(bio, BIO_NOCLOSE);
	BUF_MEM_grow(biobuf, len-2);	/* remove CRLF */
	BIO_set_mem_buf(bio, biobuf, BIO_CLOSE);
    }

    return bio;
} 


static BIO *
bio_from_store(STORE_S *store)
{
    BIO *ret = NULL;

    if(store && store->src == BioType && store->txt){
	ret = (BIO *) store->txt;
    }

    return(ret);
}

/* 
 * Encrypt file; given a path (char *) fp, replace the file
 * by an encrypted version of it. If (char *) text is not null, then
 * replace the text of (char *) fp by the encrypted version of (char *) text.
 * certpath is the FULL path to the file containing the certificate used for 
 * encryption.
 * return value: 0 - failed to encrypt; 1 - success! 
 */
int
encrypt_file(char *fp, char *text, PERSONAL_CERT *pc)
{
  const EVP_CIPHER *cipher = NULL;
  STACK_OF(X509) *encerts = NULL;
  BIO *out = NULL;
  PKCS7 *p7 = NULL;
  int rv = 0;

  if(pc == NULL)
    return 0;

  cipher = EVP_aes_256_cbc();
  encerts = sk_X509_new_null();

  sk_X509_push(encerts, X509_dup(pc->cert));

  if(text){
    if((out = BIO_new(BIO_s_mem())) != NULL){
      (void) BIO_reset(out);
      BIO_puts(out, text);
    }
  }
  else if((out = BIO_new_file(fp, "rb")) != NULL)
    BIO_read_filename(out, fp);

  if((p7 = PKCS7_encrypt(encerts, out, cipher, 0)) != NULL){
	BIO_set_close(out, BIO_CLOSE);
	BIO_free(out);
	if((out = BIO_new_file(fp, "w")) != NULL){
	  BIO_reset(out);
	  rv = PEM_write_bio_PKCS7(out, p7);
	  BIO_flush(out);
        }
  }

  if(out != NULL)
    BIO_free(out);
  PKCS7_free(p7);
  sk_X509_pop_free(encerts, X509_free);

  return rv;
}

/*
 * Encrypt a message on the way out. Called from call_mailer in send.c
 * The body may be reallocated. 
 */
int
encrypt_outgoing_message(METAENV *header, BODY **bodyP)
{
    PKCS7 *p7 = NULL;
    BIO	*in = NULL;
    BIO *out = NULL;
    const EVP_CIPHER *cipher = NULL;
    STACK_OF(X509) *encerts = NULL;
    STORE_S *outs = NULL;
    PINEFIELD	*pf;
    ADDRESS	*a;
    BODY	*body = *bodyP;
    BODY	*newBody = NULL;
    int		 result = 0;
    X509	*cert;
    char	buf[MAXPATH];

    dprint((9, "encrypt_outgoing_message()"));
    smime_init();

    cipher = EVP_aes_256_cbc();

    encerts = sk_X509_new_null();

    /* Look for a certificate for each of the recipients */
    for(pf = header->local; pf && pf->name; pf = pf->next)
        if(pf->type == Address && pf->rcptto && pf->addr && *pf->addr){
            for(a=*pf->addr; a; a=a->next){
                snprintf(buf, sizeof(buf), "%s@%s", a->mailbox, a->host);

                if((cert = get_cert_for(buf, Public, 1)) != NULL){
                  sk_X509_push(encerts,cert);
                }else{
                    q_status_message2(SM_ORDER, 1, 1,
                                      _("Unable to find certificate for <%s@%s>"),
				      a->mailbox, a->host);
                    goto end;
                }
            }
        }

    /* add the sender's certificate so that they can decrypt the message too */
    for(a=header->env->from; a ; a = a->next){
       snprintf(buf, sizeof(buf), "%s@%s", a->mailbox, a->host);

       if((cert = get_cert_for(buf, Public, 1)) != NULL
	  && sk_X509_find(encerts, cert) == -1)
         sk_X509_push(encerts,cert);
    }

    in = body_to_bio(body);

    p7 = PKCS7_encrypt(encerts, in, cipher, 0);

    outs = so_get(BioType, NULL, EDIT_ACCESS);
    out = bio_from_store(outs);

    i2d_PKCS7_bio(out, p7);
    (void) BIO_flush(out);

    so_seek(outs, 0, SEEK_SET);

    newBody = mail_newbody();

    newBody->type = TYPEAPPLICATION;
    newBody->subtype = cpystr("pkcs7-mime");
    newBody->encoding = ENCBINARY;

    newBody->disposition.type = cpystr("attachment");
    set_parameter(&newBody->disposition.parameter, "filename", "smime.p7m");

    newBody->description = cpystr("S/MIME Encrypted Message");
    set_parameter(&newBody->parameter, "smime-type", "enveloped-data");
    set_parameter(&newBody->parameter, "name", "smime.p7m");

    newBody->contents.text.data = (unsigned char *) outs;

    *bodyP = newBody;

    result = 1;

end:

    BIO_free(in);
    PKCS7_free(p7);
    sk_X509_pop_free(encerts, X509_free);

    dprint((9, "encrypt_outgoing_message returns %d", result));
    return result;
}


/*
    Get (and decode) the body of the given section of msg
 */
static STORE_S*
get_part_contents(long msgno, const char *section)
{
    long len;
    gf_io_t     pc;
    STORE_S *store = NULL;
    char	*err;

    store = so_get(CharStar, NULL, EDIT_ACCESS);
    if(store){
        gf_set_so_writec(&pc,store);

        err = detach(ps_global->mail_stream, msgno, (char*) section, 0L, &len, pc, NULL, 0L);

        gf_clear_so_writec(store);

        so_seek(store, 0, SEEK_SET);

        if(err)
          so_give(&store);
    }

    return store;
}


static PKCS7 *
get_pkcs7_from_part(long msgno,const char *section)
{
    STORE_S *store = NULL;
    PKCS7   *p7 = NULL;
    BIO	   *in = NULL;

    store = get_part_contents(msgno, section);

    if(store){
	if(store->src == CharStar){
	    int len;

	    /*
	     * We're reaching inside the STORE_S structure. We should
	     * probably have a way to get the length, instead.
	     */
	    len = (int) (store->eod - store->dp);
	    in = BIO_new_mem_buf(store->txt, len);
	}
	else{				/* just copy it */
	    unsigned char c;

	    in = BIO_new(BIO_s_mem());
	    (void) BIO_reset(in);

	    so_seek(store, 0L, 0);
	    while(so_readc(&c, store)){
		BIO_write(in, &c, 1);
	    }
	}

        if(in){
/* dump_bio_to_file(in, "/tmp/decoded-signature"); */
            if((p7=d2i_PKCS7_bio(in,NULL)) == NULL){
		/* error */
	    }

	    BIO_free(in);
        }

	so_give(&store);
    }

    return p7;
}

int
same_cert(X509 *x, X509 *cert)
{
   char    bufcert[256],  bufx[256];
   int rv = 0;

   get_fingerprint(cert, EVP_md5(), bufcert, sizeof(bufcert), ":");
   get_fingerprint(x, EVP_md5(), bufx, sizeof(bufx), ":");
   if(strcmp(bufx, bufcert) == 0)
     rv = 1;

   return rv;
}


/* extract and save certificates from a PKCS7 package.
 * Return value:
 *	0 - no errors. Either the certificate was in public/
 *	    or we could save it there.
 *    < 0 - the certificate was not in public/ and the user
 *	    did not save it there.
 */

int
smime_extract_and_save_cert(PKCS7 *p7)
{
    STACK_OF(X509) *signers;
    X509 *x, *cert;
    char **email;
    int i, j, rv, already_saved;
    long error;

    /* any signers for this message? */
    if((signers = PKCS7_get0_signers(p7, NULL, 0)) == NULL)
      return -1;

    rv = 0;
    for(i = 0; i < sk_X509_num(signers); i++){
	if((x = sk_X509_value(signers,i)) == NULL)
	    continue;

	if((email = get_x509_subject_email(x)) != NULL){
	  for(j = 0; email[j] != NULL; j++){
	     already_saved = 0;
			/* check if we have the certificate for this address */
	     cert = get_cert_for(email[j], Public, 1);
			/* if we have one, check if it is the one packaged */
	     if(cert != NULL){
		already_saved = same_cert(x, cert);
		X509_free(cert);
	     }

			/* if not saved, try to save it */
	     if(already_saved == 0
		  && (*pith_smime_confirm_save)(email[j]) == 1){
		save_cert_for(email[j], x, Public);
		if(ps_global->smime->publiccertlist)	/* renew store */
		  free_certlist(&ps_global->smime->publiccertlist);
	     }

			/* check if it got saved */
	     cert = get_cert_for(email[j], Public, 1);
			/* if saved, all is good */
	     if(cert != NULL)
		X509_free(cert);
	     else	/* else, we do not have this certificate saved */
		rv += -1;

	     fs_give((void **) &email[j]);
	  }
	  fs_give((void **) email);
	}
    }
    sk_X509_free(signers);

    return rv;
}

/*
 * Try to verify a signature.
 * 
 * p7  - the pkcs7 object to verify
 * in  - the plain data to verify (NULL if not detached)
 * out - BIO to which to write the opaque data
 * silent - if non zero, do not print errors, only print success.
 */
static int
do_signature_verify(PKCS7 *p7, BIO *in, BIO *out, int silent)
{
    STACK_OF(X509) *otherCerts = NULL;
    CertList *cl;
    int result, flags;
    const char *data;
    long err;

    if(!s_cert_store){
	if(!silent) q_status_message(SM_ORDER | SM_DING, 2, 2,
		_("Couldn't verify S/MIME signature: No CA Certs were loaded"));

    	return -1;
    }

    flags = F_ON(F_USE_CERT_STORE_ONLY, ps_global) ? PKCS7_NOINTERN : 0;

    if(ps_global->smime->publiccertlist == NULL){
       renew_cert_data(&ps_global->smime->publiccertlist, Public);
       for(cl = ps_global->smime->publiccertlist; cl ; cl = cl->next){
	  if(cl->x509_cert == NULL){
	    char *s = strrchr(cl->name, '.');
	    *s = '\0';
	    cl->x509_cert = get_cert_for(cl->name, Public, 1);
	    *s = '.';
	  }
       }
    }

    if(ps_global->smime->publiccertlist){
       otherCerts = sk_X509_new_null();
       for(cl = ps_global->smime->publiccertlist; cl ; cl = cl->next)
	   if(cl->x509_cert != NULL)
	      sk_X509_push(otherCerts, X509_dup(cl->x509_cert));
    }

    result = PKCS7_verify(p7, otherCerts, s_cert_store, in, out, flags);

    if(result){
	q_status_message(SM_ORDER, 1, 1, _("S/MIME signature verified ok"));
    }
    else{
	err = ERR_peek_error_line_data(NULL, NULL, &data, NULL);

	if(out && err==ERR_PACK(ERR_LIB_PKCS7,PKCS7_F_PKCS7_VERIFY,PKCS7_R_CERTIFICATE_VERIFY_ERROR)){

	    /* 
	     * verification failed due to an error in verifying a certificate.
	     * Just write the "out" BIO, and leave. Of course let the user
	     * know about this. Make two more attempts to get the data out. The
	     * last one should succeed. In any case, let the user know why it
	     * failed.
	     */
	    if(PKCS7_verify(p7, otherCerts, s_cert_store, in, out, PKCS7_NOVERIFY) == 0)
		PKCS7_verify(p7, otherCerts, s_cert_store, in, out, PKCS7_NOVERIFY|PKCS7_NOSIGS);
	}
	if (!silent) q_status_message1(SM_ORDER | SM_DING, 3, 3,
		_("Couldn't verify S/MIME signature: %s"), (char *) openssl_error_string());
    }

    sk_X509_pop_free(otherCerts, X509_free);

    return result;
}

/* Big comment, explaining the mess that exists out there, and how we deal
   with it, and also how we solve the problems that are created this way.

  When Alpine sends a message, it constructs that message, computes the 
  signature, but then it forgets the message it signed and reconstructs it 
  again. Since it signs a message containing a notice about "mime aware 
  tools", but it does not send that we do not include that in the part 
  that is signed, and that takes care of much of the problems.
 
  Another problem is what is received from the servers. All servers tested 
  seem to transmit the message that was signed intact and Alpine can check 
  the signature correctly. That is not a problem. The problem arises when 
  the message includes attachments. In this case different servers send 
  different things, so it will be up to us to figure out what is the text 
  that was actually signed. Confused? here is the story:
 
  When a message containing and attachment is sent by Alpine, UW-IMAP, 
  Panda-IMAP, Gmail, and local reading of folders send exactly the message 
  that was sent by Alpine, but GMX.com, Exchange, and probably other 
  servers add a trailing \r\n in the message, so when validating the 
  signature, these messages will not validate. There are several things 
  that can be done.
 
  1. Add a trailing \r\n to any message that contains attachments, sign that 
     and send that. In this way, all messages will validate with all 
     servers.
  
  2. Compatibility mode: If a message has an attachment, contains a trailing 
     \r\n and does not validate (sent by an earlier version of Alpine), 
     remove the trailing \r\n and try to revalidate again.

  3. We do not add \r\n to validate a message that we sent, because that 
     would only work in Alpine, and not in any other client. That would 
     not be a good thing to do.

  PART II

  Now we have to deal with encrypted and signed messages. The problem is 
  that c-client makes all its pointers point to "on disk" content, but 
  since we decrypted the data earlier, we have to make sure of two things. 
  One is that we saved that data (so we do not have to decrypt it again) 
  and second that we can use it.

  In order to save the data we use create_local_cache, so that we do not
  have to redecrypt the message. Once this is saved, c-client functions will
  find it and send it to us in mail_fetch_mime and mail_fetch_body.

  PART III

  When we are trying to verify messages with detached signatures, some 
  imap servers send incorrect information in the mail_fetch_mime call. By 
  incorrect I mean that this is not fetched directly from the message, but 
  it is read from the message, processed, and then the processed part is 
  sent to us, so this text might not agree with what is in the message, 
  and so the validation of the signature might fail. However, the good 
  news is that the message validates if saved to a local folder. This 
  means that if normal validation does not work we can make it work by 
  saving the message locally and validating that. This is implemented 
  below, and causes delay in the display of the message. I am considering 
  at this time not to do this automatically, but wait for the user to tell 
  us to do it for them by means of a command available in the 
  mail_view_screen. This might help in other situations, where a message 
  is supposed to have an attachment, but it can not be seen in the 
  processed text. Nevertheless, at this time, this is automatic, and is 
  causing a delay in the processing of the message, but it is validating
  correctly all messages.

  PART IV

  When the user sends a message as encrypted and signed, this code used to 
  encrypt first, and then sign the pkcs7 body, but it turns out that some 
  other clients can not handle these messages. While we could argue that the 
  other clients need to improve, we will support reading messages in both 
  ways, and will send messages using this technique; that is, signed first,
  encrypted second. It seems that all tested clients support this way, so it
  should be safe to do so.
 */

typedef struct smime_filter_s {
  void (*filter)();
} SMIME_FILTER_S;

SMIME_FILTER_S sig_filter[] = {
   {smime_remove_trailing_crlf},
   {smime_remove_folding_space}
};

#define TOTAL_FILTERS  (sizeof(sig_filter)/sizeof(sig_filter[0]))
#define TOTAL_SIGFLTR  (1 << TOTAL_FILTERS)  /* not good, keep filters to a low number */

void
smime_remove_trailing_crlf(char **mimetext, unsigned long *mimelen, 
			char **bodytext, unsigned long *bodylen)
{
  if(*bodylen > 2 && !strncmp(*bodytext+*bodylen-2, "\r\n", 2))
    *bodylen -= 2;
}

void
smime_remove_folding_space(char **mimetext, unsigned long *mimelen, 
			char **bodytext, unsigned long *bodylen)
{
   char *s = NULL, *t;
   unsigned long mlen = *mimelen;

   if(*mimetext){
      for (s = t = *mimetext; t - *mimetext < *mimelen; ){
	 if(*t == '\r' && *(t+1) == '\n' && (*(t+2) == '\t' || *(t+2) == ' ')){
	    *s++ = ' ';
	    t += 3;
	    mlen -= 2;
	 }
	 else
	    *s++ = *t++;
      }
      *mimelen = mlen;
   }
}

int
smime_validate_extra_test(char *mimetext, unsigned long mimelen, char *bodytext, unsigned long bodylen, PKCS7 *p7, int nflag)
{
  int result, i, j, flag;
  char *mtext, *btext;
  unsigned long mlen, blen;
  BIO *in;

  mtext = mimelen ? fs_get(mimelen+1) : NULL;
  btext = fs_get(bodylen+1);
  result = 0;

  flag = 1;	/* silence all failures */
  for(i = 1; result == 0 && i < TOTAL_SIGFLTR; i++){
     if((in = BIO_new(BIO_s_mem())) == NULL)
       return -1;

     (void) BIO_reset(in);

     if(i+1 == TOTAL_SIGFLTR)
	flag = nflag;

     if(mimelen)
	strncpy(mtext, mimetext, mlen = mimelen);
     strncpy(btext, bodytext, blen = bodylen);
     for(j = 0; j < TOTAL_FILTERS; j++)
	if((i >> j) & 1)
	  (sig_filter[j].filter)(&mtext, &mlen, &btext, &blen);
     if(mtext != NULL) 
	BIO_write(in, mtext, mlen);
     BIO_write(in, btext, blen);
     result = do_signature_verify(p7, in, NULL, flag);
     BIO_free(in);
  }
  if(mtext) fs_give((void **)&mtext);
  if(btext) fs_give((void **)&btext);
  return result;
}

/*
 * Given a multipart body of type multipart/signed, attempt to verify it.
 * Returns non-zero if the body was changed.
 */
static int
do_detached_signature_verify(BODY *b, long msgno, char *section)
{
    PKCS7   *p7 = NULL;
    BIO	    *in = NULL;
    PART    *p;
    int	     result, modified_the_body = 0;
    int      flag;	/* 1 silent, 0 not silent */
    unsigned long mimelen, bodylen;
    char     newSec[100], *mimetext, *bodytext;
    char    *what_we_did;
    SIZEDTEXT *st;

    dprint((9, "do_detached_signature_verify(msgno=%ld type=%d subtype=%s section=%s)", msgno, b->type, b->subtype ? b->subtype : "NULL", (section && *section) ? section : (section != NULL) ? "Top" : "NULL"));

    smime_init();

    /* if it was signed and then encrypted, use the decrypted text
     * to check the validity of the signature
     */
    if(b->sparep){
	if(get_body_sparep_type(b->sparep) == SizedText){
	   /* bodytext includes mimetext */
	   st = (SIZEDTEXT *) get_body_sparep_data(b->sparep);
	   bodytext = (char *) st->data;
	   bodylen  = st->size;
	   mimetext = NULL;
	   mimelen  = 0L;
	}
    }
    else{
      snprintf(newSec, sizeof(newSec), "%s%s1", section ? section : "", (section && *section) ? "." : "");
      mimetext = mail_fetch_mime(ps_global->mail_stream, msgno, (char*) newSec, &mimelen, 0);
      if(mimetext)
        bodytext = mail_fetch_body (ps_global->mail_stream, msgno, (char*) newSec, &bodylen, 0);

      if(mimetext == NULL || bodytext ==  NULL)
         return modified_the_body;
    }

    snprintf(newSec, sizeof(newSec), "%s%s2", section ? section : "", (section && *section) ? "." : "");

    if((p7 = get_pkcs7_from_part(msgno, newSec)) == NULL
       || (in = BIO_new(BIO_s_mem())) == NULL)
	return modified_the_body;

    (void) BIO_reset(in);
    if(mimetext != NULL) 
      BIO_write(in, mimetext, mimelen);
    BIO_write(in, bodytext, bodylen);

    smime_extract_and_save_cert(p7);

    if((result = do_signature_verify(p7, in, NULL, 1)) == 0){
      flag = (mimelen == 0 || !IS_REMOTE(ps_global->mail_stream->mailbox))
		? 0 : 1;
      result = smime_validate_extra_test(mimetext, mimelen, bodytext, bodylen, p7, flag);
      if(result < 0)
         return modified_the_body;
      if(result == 0
	   && mimelen > 0	/* do not do this for encrypted messages */
	   && IS_REMOTE(ps_global->mail_stream->mailbox)){
	   char *fetch;
	   unsigned long hlen, tlen;
	   STORE_S *msg_so;

	   BIO_free(in); 
	   if((in = BIO_new(BIO_s_mem())) != NULL
	      && (fetch = mail_fetch_header(ps_global->mail_stream, msgno, NULL, 
				NULL, &hlen, FT_PEEK)) != NULL
	      && (msg_so = so_get(CharStar, NULL, WRITE_ACCESS)) != NULL
	      && so_nputs(msg_so, fetch, (long) hlen)
	      && (fetch = pine_mail_fetch_text(ps_global->mail_stream, msgno, NULL, 
				&tlen, FT_PEEK)) != NULL
	      && so_nputs(msg_so, fetch, tlen)){
		STRING bs;
		char *h = (char *) so_text(msg_so);
		char *bstart = strstr(h, "\r\n\r\n");
		ENVELOPE *env;
		BODY *body, *tmpB;

		bstart += 4;
		INIT(&bs, mail_string, bstart, tlen);
		rfc822_parse_msg_full(&env, &body, h, bstart-h-4, &bs, BADHOST, 0, 0);
		mail_free_envelope(&env);

		mail_free_body_part(&b->nested.part);
		tmpB = mail_body_section(body, (unsigned char *) section);
		if(MIME_MSG(tmpB->type, tmpB->subtype))
		   b->nested.part = tmpB->nested.msg->body->nested.part;
		else
		   b->nested.part = tmpB->nested.part;
		create_local_cache(bstart, bstart, &b->nested.part->body, 1);
		modified_the_body = 1;

		snprintf(newSec, sizeof(newSec), "%s%s1", section ? section : "", (section && *section) ? "." : "");

		mimetext = mail_fetch_mime(ps_global->mail_stream, msgno, (char*) newSec, &mimelen, 0);

		if(mimetext)
		   bodytext = mail_fetch_body (ps_global->mail_stream, msgno, (char*) newSec, &bodylen, 0);

		if (mimetext == NULL || bodytext ==  NULL)
		   return modified_the_body;

		snprintf(newSec, sizeof(newSec), "%s%s2", section ? section : "", (section && *section) ? "." : "");

		if((p7 = get_pkcs7_from_part(msgno, newSec)) == NULL)
		  return modified_the_body;

		(void) BIO_reset(in);
		BIO_write(in, mimetext, mimelen);
		BIO_write(in, bodytext, bodylen);
		so_give(&msg_so);

		if((result = do_signature_verify(p7, in, NULL, 1)) == 0){
		  result = smime_validate_extra_test(mimetext, mimelen, bodytext, bodylen, p7, 0);
		  if(result < 0)
		    return modified_the_body;
		}
	   }
	}
    }

    BIO_free(in);
    if(b->subtype)
	fs_give((void**) &b->subtype);

    b->subtype = cpystr(OUR_PKCS7_ENCLOSURE_SUBTYPE);
    b->encoding = ENC8BIT;

    if(b->description)
	fs_give ((void**) &b->description);

    what_we_did = result ? _("This message was cryptographically signed.") :
			   _("This message was cryptographically signed but the signature could not be verified.");

    b->description = cpystr(what_we_did);

    b->sparep = create_body_sparep(P7Type, p7);

    p = b->nested.part;
	
    /* p is signed plaintext */
    if(p && p->next)
	mail_free_body_part(&p->next); /* hide the pkcs7 from the viewer */

    modified_the_body = 1;

    return modified_the_body;
}


PERSONAL_CERT *
find_certificate_matching_recip_info(PKCS7_RECIP_INFO *ri)
{
    PERSONAL_CERT *x = NULL;

    if(ps_global->smime){
	for(x = (PERSONAL_CERT *) ps_global->smime->personal_certs; x; x=x->next){
	    X509 *mine;

	    mine = x->cert;

	    if(!X509_NAME_cmp(ri->issuer_and_serial->issuer,X509_get_issuer_name(mine)) &&
		    !ASN1_INTEGER_cmp(ri->issuer_and_serial->serial,X509_get_serialNumber(mine))){
		break;
	    }
	}
    }
    
    return x;
}


static PERSONAL_CERT *
find_certificate_matching_pkcs7(PKCS7 *p7)
{
    int i;
    STACK_OF(PKCS7_RECIP_INFO) *recips;
    PERSONAL_CERT *x = NULL;

    recips = p7->d.enveloped->recipientinfo;

    for(i=0; i<sk_PKCS7_RECIP_INFO_num(recips); i++){
        PKCS7_RECIP_INFO	*ri;

        ri = sk_PKCS7_RECIP_INFO_value(recips, i);

        if((x=find_certificate_matching_recip_info(ri))!=0){
            break;
        }
    }
    
    return x;
}

/* decrypt an encrypted file.
   Args: fp - the path to the encrypted file.
	 rv - a code that tells the caller what happened inside the function 
	 pcert - a personal certificate that was used to encrypt this file
   Returns the decoded text allocated in a char *, whose memory must be
   freed by caller 
 */

char *
decrypt_file(char *fp, int *rv, PERSONAL_CERT *pc)
{
  PKCS7 *p7 = NULL;
  char *text, *tmp;
  BIO *in = NULL, *out = NULL;
  int i, j;
  long unsigned int len;
  void *ret;

  if(pc == NULL || (text = read_file(fp, 0)) == NULL || *text == '\0')
    return NULL;

  tmp = strchr(text + strlen("-----BEGIN PKCS7-----") + strlen(NEWLINE), '-');
  if(tmp != NULL) *tmp = '\0';
  tmp = text + strlen("-----BEGIN PKCS7-----") + strlen(NEWLINE);

  ret = rfc822_base64((unsigned char *)tmp, strlen(tmp), &len);

  if((in = BIO_new_mem_buf((char *)ret, len)) != NULL){
     p7 = d2i_PKCS7_bio(in, NULL);
     BIO_free(in);
  }

  if (text) fs_give((void **)&text);
  if (ret)  fs_give((void **)&ret);

  if (rv) *rv = pc->key == NULL ? -1 : 1;

  out = BIO_new(BIO_s_mem());
  (void) BIO_reset(out);

  if(PKCS7_decrypt(p7, pc->key, pc->cert, out, 0) != 0){
    len = BIO_get_mem_data(out, &tmp);
    text = fs_get((len+1)*sizeof(char));
    strncpy(text, tmp, len);
    text[len] = '\0';
    BIO_free(out);
  } else
    q_status_message1(SM_ORDER, 1, 1, _("Error decrypting: %s"),
                              (char *) openssl_error_string());
  PKCS7_free(p7);

  return text;
}

/*
 * Try to decode (decrypt or verify a signature) a PKCS7 body
 * Returns non-zero if something was changed.
 */
static int
do_decoding(BODY *b, long msgno, const char *section)
{
    int modified_the_body = 0;
    BIO *out = NULL;
    PKCS7 *p7 = NULL;
    X509 *recip = NULL;
    EVP_PKEY *key = NULL;
    PERSONAL_CERT 	*pcert = NULL;
    char    *what_we_did = "";
    char     null[1];

    dprint((9, "do_decoding(msgno=%ld type=%d subtype=%s section=%s)", msgno, b->type, b->subtype ? b->subtype : "NULL", (section && *section) ? section : (section != NULL) ? "Top" : "NULL"));
    null[0] = '\0';
    smime_init();

    /*
     *	Extract binary data from part to an in-memory store
     */

    if(b->sparep){
        if(get_body_sparep_type(b->sparep) == P7Type)
	  p7 = (PKCS7*) get_body_sparep_data(b->sparep);
    }
    else{
	p7 = get_pkcs7_from_part(msgno, section && *section ? section : "1");
	if(!p7){
            q_status_message1(SM_ORDER, 2, 2, "Couldn't load PKCS7 object: %s",
			     (char*) openssl_error_string());
            goto end;
	}

    	/*
    	 * Save the PKCS7 object for later dealings by the user interface.
	 * It will be cleaned up when the body is garbage collected.
	 */
	b->sparep = create_body_sparep(P7Type, p7);
    }

    dprint((1, "type_is_signed = %d, type_is_enveloped = %d", PKCS7_type_is_signed(p7), PKCS7_type_is_enveloped(p7)));

    if(PKCS7_type_is_signed(p7)){
    	int 	sigok;
	
	out = BIO_new(BIO_s_mem());
	(void) BIO_reset(out);
	BIO_puts(out, "MIME-Version: 1.0\r\n"); /* needed so rfc822_parse_msg_full believes it's MIME */

    	sigok = do_signature_verify(p7, NULL, out, 0);

	what_we_did = sigok ? _("This message was cryptographically signed.") :
			      _("This message was cryptographically signed but the signature could not be verified.");

	/* make sure it's null terminated */
	BIO_write(out, null, 1);
    }
    else if(!PKCS7_type_is_enveloped(p7)){
        q_status_message(SM_ORDER, 1, 1, "PKCS7 object not recognised.");
        goto end;
    }
    else{ /* It *is* enveloped */
	int decrypt_result;

	what_we_did = _("This message was encrypted.");

	/* now need to find a cert that can decrypt this */
	pcert = find_certificate_matching_pkcs7(p7);

	if(!pcert){
            q_status_message(SM_ORDER, 3, 3, _("Couldn't find the certificate needed to decrypt."));
            goto end;
	}

	recip = pcert->cert;

	if(!load_private_key(pcert)
	   && ps_global->smime
	   && ps_global->smime->need_passphrase
	   && !ps_global->smime->already_auto_asked){
	    /* Couldn't load key with blank password, ask user */
	    ps_global->smime->already_auto_asked = 1;
	    if(pith_opt_smime_get_passphrase){
	      (*pith_opt_smime_get_passphrase)();
	      load_private_key(pcert);
	    }
	}

	key = pcert->key;
	if(!key)	
    	  goto end;

	out = BIO_new(BIO_s_mem());
	(void) BIO_reset(out);
	BIO_puts(out, "MIME-Version: 1.0\r\n");

	decrypt_result = PKCS7_decrypt(p7, key, recip, out, 0);

	if(F_OFF(F_REMEMBER_SMIME_PASSPHRASE,ps_global))
	  forget_private_keys();

	if(!decrypt_result){
            q_status_message1(SM_ORDER, 1, 1, _("Error decrypting: %s"),
			      (char*) openssl_error_string());
            goto end;	}

	BIO_write(out, null, 1);
    }

    /*
     * We've now produced a flattened MIME object in BIO out.
     * It needs to be turned back into a BODY.
     */

    if(out){
        BODY	 *body;
        ENVELOPE *env;
        char	 *h = NULL;
        char	 *bstart;
        STRING	  s;
	BUF_MEM  *bptr = NULL;
	int we_free = 0;

	BIO_get_mem_ptr(out, &bptr);
	if(bptr)
	   h = bptr->data;

        /* look for start of body */
        bstart = strstr(h, "\r\n\r\n");

	if(!bstart){
	   /* 
	    * Some clients do not canonicalize before encrypting, so 
	    * look for "\n\n" instead.
	    */
	   bstart = strstr(h, "\n\n");
	   if(bstart){
	      int lines;
	      char *s, *t;
	      for(lines = 0, bstart = h; (bstart = strchr(bstart, '\n')) != NULL; 
					bstart++, lines++);
	      h = t = fs_get(strlen(bptr->data) + lines + 1);
	      we_free++;
	      for(s = bptr->data; *s != '\0'; s++)
		if(*s == '\n' && *(s-1) != '\r'){
		  *t++ = '\r';
		  *t++ = '\n';
		}
		else
		  *t++ = *s;
	      *t = '\0';
	      bstart = strstr(h, "\r\n\r\n");
	   }
	}

        if(!bstart){
            q_status_message(SM_ORDER, 3, 3, _("Encrypted data couldn't be parsed."));
     	}
	else{
	    SIZEDTEXT *st;
            bstart += 4; /* skip over CRLF*2 */

            INIT(&s, mail_string, bstart, strlen(bstart));
            rfc822_parse_msg_full(&env, &body, h, bstart-h-2, &s, BADHOST, 0, 0);
            mail_free_envelope(&env); /* Don't care about this */

	    if(body->type == TYPEMULTIPART
		&& !strucmp(body->subtype, "SIGNED")){
	      char *cookie = NULL;
	      PARAMETER *param;
	      for (param = body->parameter; param && !cookie; param = param->next)
		if (!strucmp (param->attribute,"BOUNDARY")) cookie = param->value;
	      if(cookie != NULL){
	        st = fs_get(sizeof(SIZEDTEXT));
	        st->data = (void *) cpystr(bstart + strlen(cookie)+4); /* 4 = strlen("--\r\n") */
	        st->size = body->nested.part->next->body.mime.offset - 2*(strlen(cookie) + 4);
	        body->sparep = create_body_sparep(SizedText, (void *)st);
	      }
	      else
		q_status_message(SM_ORDER, 3, 3, _("Couldn't find cookie in attachment list."));
	    }
	    body->mime.offset    = 0;
	    body->mime.text.size = 0;

	    /*
	     * Now convert original body (application/pkcs7-mime)
	     * to a multipart body with one sub-part (the decrypted body).
	     * Note that the sub-part may also be multipart!
	     */

	    b->type = TYPEMULTIPART;
	    if(b->subtype)
	      fs_give((void **) &b->subtype);

	    /*
	     * This subtype is used in mailview.c to annotate the display of
	     * encrypted or signed messages. We know for sure then that it's a PKCS7
	     * part because the sparep field is set to the PKCS7 object (see above).
	     */
	    b->subtype = cpystr(OUR_PKCS7_ENCLOSURE_SUBTYPE);
	    b->encoding = ENC8BIT;

	    if(b->description)
	      fs_give((void **) &b->description);

	    b->description = cpystr(what_we_did);

	    if(b->disposition.type)
	      fs_give((void **) &b->disposition.type);

	    if(b->contents.text.data)
	      fs_give((void **) &b->contents.text.data);

	    if(b->parameter)
	      mail_free_body_parameter(&b->parameter);

	    /* Allocate mem for the sub-part, and copy over the contents of our parsed body */
	    b->nested.part = fs_get(sizeof(PART));
	    b->nested.part->body = *body;
	    b->nested.part->next = NULL;

	    fs_give((void**) &body);

            /*
             * IMPORTANT BIT: set the body->contents.text.data elements to contain 
             * the decrypted data. Otherwise, it'll try to load it from the original 
             * data. Eek. 
	     */
            create_local_cache(bstart-b->nested.part->body.mime.offset, bstart, &b->nested.part->body, 0);

            modified_the_body = 1;
        }
	if(we_free)
	   fs_give((void **) &h);
    }

end:
    if(out)
      BIO_free(out);

    return modified_the_body;
}


/*
 * Recursively handle PKCS7 bodies in our message.
 *
 * Returns non-zero if some fiddling was done.
 */
static int
do_fiddle_smime_message(BODY *b, long msgno, char *section)
{
    int modified_the_body = 0;

    if(!b)
      return 0;

    dprint((9, "do_fiddle_smime_message(msgno=%ld type=%d subtype=%s section=%s)", msgno, b->type, b->subtype ? b->subtype : "NULL", (section && *section) ? section : (section != NULL) ? "Top" : "NULL"));

    if(is_pkcs7_body(b)){
    
        if(do_decoding(b, msgno, section)){
            /*
             *	b should now be a multipart message:
	     *   fiddle it too in case it's been multiply-encrypted!
             */

            /* fallthru */
            modified_the_body = 1;
        }
    }

    if(b->type==TYPEMULTIPART || MIME_MSG(b->type, b->subtype)){

        PART	*p;
        int		partNum;
        char	newSec[100];

	if(MIME_MULT_SIGNED(b->type, b->subtype)){


            /*
             * Ahah. We have a multipart signed entity.
	     *
	     * Multipart/signed
             *   part 1 (signed thing)
             *   part 2 (the pkcs7 signature)
	     *
	     * We're going to convert that to
	     *
	     * Multipart/OUR_PKCS7_ENCLOSURE_SUBTYPE
             *   part 1 (signed thing)
	     *   part 2 has been freed
	     *
	     * We also extract the signature from part 2 and save it
	     * in the multipart body->sparep, and we add a description
	     * in the multipart body->description.
	     *
	     *
	     * The results of a decrypted message will be similar. It
	     * will be
	     *
	     * Multipart/OUR_PKCS7_ENCLOSURE_SUBTYPE
             *   part 1 (decrypted thing)
             */

            modified_the_body += do_detached_signature_verify(b, msgno, section);
        }
	else if(MIME_MSG(b->type, b->subtype)){
	    modified_the_body += do_fiddle_smime_message(b->nested.msg->body, msgno, section);
	}
	else{

            for(p=b->nested.part,partNum=1; p; p=p->next,partNum++){
                /* Append part number to the section string */

                snprintf(newSec, sizeof(newSec), "%s%s%d", section, *section ? "." : "", partNum);

                modified_the_body += do_fiddle_smime_message(&p->body, msgno, newSec);
            }
        }
    }

    return modified_the_body;
}


/*
 * Fiddle a message in-place by decrypting/verifying S/MIME entities.
 * Returns non-zero if something was changed.
 */
int
fiddle_smime_message(BODY *b, long msgno)
{
    return do_fiddle_smime_message(b, msgno, "");
}


/********************************************************************************/


/*
 *  Output a string in a distinctive style
 */
void
gf_puts_uline(char *txt, gf_io_t pc)
{
    pc(TAG_EMBED); pc(TAG_BOLDON);
    gf_puts(txt, pc);
    pc(TAG_EMBED); pc(TAG_BOLDOFF);
}

/* get_chain_for_cert: error and level are mandatory arguments */
STACK_OF(X509) *
get_chain_for_cert(X509 *cert, int *error, int *level)
{
  STACK_OF(X509) *chain = NULL;
  X509_STORE_CTX *ctx;   
  X509 *x, *xtmp;
  int rc;       /* return code */

  *level = -1;
  *error = 0;
  ERR_clear_error();
  if((s_cert_store != NULL) && (ctx = X509_STORE_CTX_new()) != NULL){
      X509_STORE_set_flags(s_cert_store, 0);
      if(!X509_STORE_CTX_init(ctx, s_cert_store, cert, NULL))
	*error   = X509_STORE_CTX_get_error(ctx);
      else if((chain = sk_X509_new_null()) != NULL){
	for(x = cert; ; x = xtmp){
	    if(++*level > 0)
	      sk_X509_push(chain, X509_dup(x));
	    rc = X509_STORE_CTX_get1_issuer(&xtmp, ctx, x);
	    if(rc < 0)
	      *error = 1;
	    if(rc <= 0)
	      break;
	    if(!X509_check_issued(xtmp, xtmp))
	       break;
	}
      }
      X509_STORE_CTX_free(ctx);
  }
  return chain;
}


/*
 * Sign a message. Called from call_mailer in send.c.
 *
 * This takes the header for the outgoing message as well as a pointer
 * to the current body (which may be reallocated).
 * The last argument (BODY **bp) is an argument that tells Alpine
 * if the body has 8 bit. if *bp is not null we compute two signatures
 * one for the quoted-printable encoded message, and another for the
 * 8bit encoded message. We return the signature for the 8bit encoded
 * part in p2->body.mime.text.data.
 * The reason why we compute two signatures is so that we can decide
 * which one to use later, and we only do it in the case that *bp is
 * not null. If we did not do this, then we might not be able to sign
 * a message until we log in to the smtp server, so instead of doing
 * that, we get ready for any possible situation we might find.
 */
int
sign_outgoing_message(METAENV *header, BODY **bodyP, int dont_detach, BODY **bp)
{
    STORE_S *outs = NULL;
    STORE_S *outs_2 = NULL;
    BODY    *body = *bodyP;
    BODY    *newBody = NULL;
    PART    *p1 = NULL;
    PART    *p2 = NULL;
    PERSONAL_CERT   *pcert;
    BIO *in = NULL;
    BIO *in_2 = NULL;
    BIO *out = NULL;
    BIO *out_2 = NULL;
    PKCS7   *p7 = NULL;
    PKCS7   *p7_2 = NULL;
    STACK_OF(X509) *chain;
    const EVP_MD *md = EVP_sha256();	/* use this digest instead of sha1 */
    int result = 0, error;
    int flags = dont_detach ? 0 : PKCS7_DETACHED;
    int level;

    dprint((9, "sign_outgoing_message()"));

    smime_init();

    /* Look for a private key matching the sender address... */
    
    pcert = match_personal_cert(header->env);
    
    if(!pcert){
        q_status_message(SM_ORDER, 3, 3, _("Couldn't find the certificate needed to sign."));
	goto end;
    }
    
    if(!load_private_key(pcert) && ps_global->smime && ps_global->smime->need_passphrase){
    	/* Couldn't load key with blank password, try again */
	if(pith_opt_smime_get_passphrase){
	  (*pith_opt_smime_get_passphrase)();
	  load_private_key(pcert);
	}
    }
    
    if(!pcert->key)
      goto end;

    if(((chain = get_chain_for_cert(pcert->cert, &error, &level)) != NULL && error)
	|| level == 0){
	sk_X509_pop_free(chain, X509_free);
	chain = NULL;
    }

    if(error)
      q_status_message(SM_ORDER, 1, 1, 
	_("Not all certificates needed to verify signature included in signed message"));
   
    in = body_to_bio(body);

    flags |= PKCS7_PARTIAL;
    if((p7 = PKCS7_sign(NULL, NULL, chain, in, flags)) != NULL
	&& PKCS7_sign_add_signer(p7, pcert->cert, pcert->key, md, flags))
	   PKCS7_final(p7, in, flags);

    if(bp && *bp){
      int i, save_encoding;
         
      for(i = 0; (i <= ENCMAX) && body_encodings[i]; i++);

      if(i > ENCMAX){             /* no empty encoding slots! */
         *bp = NULL;
      }
      else {
	save_encoding = (*bp)->encoding;
	body_encodings[(*bp)->encoding = i] = body_encodings[ENC8BIT];

	in_2 = body_to_bio(body);

	body_encodings[i] = NULL;
	(*bp)->encoding = save_encoding;
      }
    }

    if(bp && *bp){
       if((p7_2 = PKCS7_sign(NULL, NULL, chain, in_2, flags)) != NULL
	&& PKCS7_sign_add_signer(p7_2, pcert->cert, pcert->key, md, flags))
	   PKCS7_final(p7_2, in_2, flags);
    }

    if(F_OFF(F_REMEMBER_SMIME_PASSPHRASE,ps_global))
      forget_private_keys();

    if(chain)
      sk_X509_pop_free(chain, X509_free);

    if(!p7){
        q_status_message(SM_ORDER, 1, 1, _("Error creating signed object."));
	goto end;
    }

    outs = so_get(BioType, NULL, EDIT_ACCESS);
    out = bio_from_store(outs);

    i2d_PKCS7_bio(out, p7);
    (void) BIO_flush(out);

    so_seek(outs, 0, SEEK_SET);

    if(bp && *bp && p7_2){
      outs_2 = so_get(BioType, NULL, EDIT_ACCESS);
      out_2 = bio_from_store(outs_2);

      i2d_PKCS7_bio(out_2, p7_2);
      (void) BIO_flush(out_2);

      so_seek(outs_2, 0, SEEK_SET);
    }
    
    if((flags&PKCS7_DETACHED)==0){
   
    	/* the simple case: the signed data is in the pkcs7 object */
    
	newBody = mail_newbody();
    	
	setup_pkcs7_body_for_signature(newBody, "S/MIME Cryptographically Signed Message", "pkcs7-mime", "smime.p7m", "signed-data");

    	newBody->contents.text.data = (unsigned char *) outs;
	*bodyP = newBody;

	result = 1;
    }
    else{
    
	/*
	 * OK.
    	 * We have to create a new body as follows:
	 *
	 * multipart/signed; blah blah blah
	 *      reference to existing body
	 *
	 *	pkcs7 object
	 */

	newBody = mail_newbody();

	newBody->type = TYPEMULTIPART;
	newBody->subtype = cpystr("signed");
	newBody->encoding = ENC7BIT;

	set_parameter(&newBody->parameter, "protocol", "application/pkcs7-signature");
	set_parameter(&newBody->parameter, "micalg", "sha-256");

	p1 = mail_newbody_part();
	p2 = mail_newbody_part();

    	/*
    	 * This is nasty. We're just copying the body in here,
	 * but since our newBody is freed at the end of call_mailer,
	 * we mustn't let this body (the original one) be freed twice.
	 */
	p1->body = *body; /* ARRGH. This is special cased at the end of call_mailer */

	p1->next = p2;

	setup_pkcs7_body_for_signature(&p2->body, "S/MIME Cryptographic Signature", "pkcs7-signature", "smime.p7s", NULL);
    	p2->body.mime.text.data = (unsigned char *) outs_2;
    	p2->body.contents.text.data = (unsigned char *) outs;

    	newBody->nested.part = p1;

	*bodyP = newBody;
	
	result = 1;
    }

end:

    PKCS7_free(p7);
    BIO_free(in);

    if(bp && *bp){
      if(p7_2) PKCS7_free(p7_2);
      BIO_free(in_2);
    }

    dprint((9, "sign_outgoing_message returns %d", result));
    return result;
}


SMIME_STUFF_S *
new_smime_struct(void)
{
    SMIME_STUFF_S *ret = NULL;

    ret = (SMIME_STUFF_S *) fs_get(sizeof(*ret));
    memset((void *) ret, 0, sizeof(*ret));
    ret->publictype = Nada;

    return ret;
}


static void
free_smime_struct(SMIME_STUFF_S **smime)
{
    if(smime && *smime){
	if((*smime)->passphrase_emailaddr){
	  int i;
	  for(i = 0; (*smime)->passphrase_emailaddr[i] != NULL; i++)
	     fs_give((void **) &(*smime)->passphrase_emailaddr[i]);
	  fs_give((void **) (*smime)->passphrase_emailaddr);
	}

	if((*smime)->publicpath)
	  fs_give((void **) &(*smime)->publicpath);

	if((*smime)->publiccertlist)
	  free_certlist(&(*smime)->publiccertlist);

	if((*smime)->backuppubliccertlist)
	  free_certlist(&(*smime)->backuppubliccertlist);

	if((*smime)->cacertlist)
	  free_certlist(&(*smime)->cacertlist);

	if((*smime)->backupcacertlist)
	  free_certlist(&(*smime)->backupcacertlist);

	if((*smime)->privatecertlist)
	  free_certlist(&(*smime)->privatecertlist);

	if((*smime)->backupprivatecertlist)
	  free_certlist(&(*smime)->backupprivatecertlist);

	if((*smime)->publiccontent)
	  fs_give((void **) &(*smime)->publiccontent);

	if((*smime)->privatepath)
	  fs_give((void **) &(*smime)->privatepath);

	if((*smime)->personal_certs){
	    PERSONAL_CERT *pc;

	    pc = (PERSONAL_CERT *) (*smime)->personal_certs;
	    free_personal_certs(&pc);
	    (*smime)->personal_certs = NULL;
	}

	if((*smime)->privatecontent)
	  fs_give((void **) &(*smime)->privatecontent);

	if((*smime)->capath)
	  fs_give((void **) &(*smime)->capath);

	if((*smime)->cacontent)
	  fs_give((void **) &(*smime)->cacontent);

	fs_give((void **) smime);
    }
}

#endif /* SMIME */
