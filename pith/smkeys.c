#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: smkeys.c 1266 2009-07-14 18:39:12Z hubert@u.washington.edu $";
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
 *  This is based on a contribution from Jonathan Paisley, see smime.c
 */


#include "../pith/headers.h"

#ifdef SMIME

#include "../pith/status.h"
#include "../pith/conf.h"
#include "../pith/remote.h"
#include "../pith/tempfile.h"
#include "../pith/busy.h"
#include "../pith/osdep/lstcmpnt.h"
#include "../pith/util.h"
#include "../pith/mailindx.h"
#include "../pith/readfile.h"
#include "../pith/options.h"
#include "smkeys.h"

#ifdef APPLEKEYCHAIN
#include <Security/SecKeychain.h>
#include <Security/SecKeychainItem.h>
#include <Security/SecKeychainSearch.h>
#include <Security/SecCertificate.h>
#endif /* APPLEKEYCHAIN */


/* internal prototypes */
static char     *emailstrclean(char *string);
static int       mem_add_extra_cacerts(char *contents, X509_LOOKUP *lookup);
int		 compare_certs_by_name(const void *data1, const void *data2);
int		 password_policy_check(char *);

/* test if password passes a predetermined policy.
 * return value: 0 - does not pass; 1 - it passes 
 */
int
password_policy_check(char *password)
{
  int rv = 1;
  char *error;
  char tmp[1024];

  if(password == NULL || password[0] == '\0'){
    error = _("Password cannot be blank");
    rv = 0;     
  } else if(strlen(password) < 8){
    error = _("Password is too short");
    rv = 0;
  }
  if(rv == 0){
    snprintf(tmp, sizeof(tmp), "%s%s", error, _(". Enter password again"));
    tmp[sizeof(tmp) - 1] = '\0';
    q_status_message(SM_ORDER, 3, 3, tmp);
  }
  return rv;
}


int
create_master_password(char *pass, size_t passlen, int first_time)
{
#define MAXTRIAL 3
  int rv, trial;
  char prompt[MAILTMPLEN];
  char passbackup[MAILTMPLEN];

  if(first_time)
     q_status_message(SM_ORDER, 3, 3, 
		_(" Creating a Master Password for your Password file "));
  else
     q_status_message(SM_ORDER, 3, 3, 
		_(" Retrying to create a Master Password for your Password file "));

  for(trial = 0; trial < MAXTRIAL; trial++){
    snprintf(prompt, sizeof(prompt), 
		_("Create master password (attempt %d of %d): "), trial+1, MAXTRIAL);
    prompt[sizeof(prompt)- 1] = '\0';
    pass[0] = '\0';
    do {
      /* rv == 1 means cancel */
      rv = (pith_smime_enter_password)(prompt, pass, passlen);
      if(rv == 1 || password_policy_check(pass) == 0)
	 pass[0] = '\0';
      if(rv == 1) return 0;
    } while ((rv != 0  && rv != 1) || (rv == 0 && pass[0] == '\0'));

    snprintf(prompt, sizeof(prompt), 
		_("Confirm master password (attempt %d of %d): "), trial+1, MAXTRIAL);
    prompt[sizeof(prompt)- 1] = '\0';
    passbackup[0] = '\0';
    do { 
      rv = (pith_smime_enter_password)(prompt, passbackup, sizeof(passbackup));
    } while ((rv !=0 && rv !=1 && rv > 0) || passbackup[0] == '\0');
    if(!strcmp(pass, passbackup))
       break;
    if(trial + 1 < MAXTRIAL)
      q_status_message(SM_ORDER, 2, 2, _("Passwords do not match, try again."));
    else{
      q_status_message(SM_ORDER, 2, 2, _("Passwords do not match, too many failures."));
      pass[0] = '\0';
    }
  }
  return (trial < MAXTRIAL) ? 1 : 0;
}

/* 
 * Create a self signed certificate with root name _fname_, in directory
 * _pathdir_. If _version_ is 3, we use the _template_ file as configuration
 * file for openssl. At this moment, we only call this function with template = NULL
 * and version = 0, but a sensible call is 
 * ALPINE_self_signed_certificate("/etc/ssl/openssl.cnf", 2, pathdir, fname, first_time);
 * or so.
 * _pathdir_ is the directory to save the file,
 * _fname_ is the root of the name to use. Append ".key" and ".crt" to this name
 * _first_time_ is an indicator to tell us if this is the first time we call this function
 */
PERSONAL_CERT *
ALPINE_self_signed_certificate(char *template, int version, char *pathdir, char *fname)
{
    BIGNUM *b = NULL;
    X509_NAME *name = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY_CTX *pkctx;
    BIO *out = NULL;
    char tmp[MAXPATH+1], password[1024];
    char *keyfile = NULL, *certfile = NULL;
    char *extensions = NULL;
    FILE *fp;
    long errline = -1L;
    PERSONAL_CERT *pc = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *pcert = NULL;
    CONF *req_conf = NULL;
    static int first_time = 1;

    if(pathdir == NULL)
      return NULL;

    if(template){
       if((out = BIO_new_file(template, "r")) == NULL){
	 q_status_message(SM_ORDER, 2, 2, _("Problem reading configuration file"));
	 return pc;
       }

       if((req_conf = NCONF_new(NULL)) != NULL
	&& NCONF_load_bio(req_conf, out, &errline) > 0){
	  if((extensions = NCONF_get_string(req_conf, "req", "x509_extensions")) != NULL){
	   X509V3_CTX ctx;
	   X509V3_set_ctx_test(&ctx);
	   X509V3_set_nconf(&ctx, req_conf);
	     if (!X509V3_EXT_add_nconf(req_conf, &ctx, extensions, NULL)) {
		q_status_message(SM_ORDER, 2, 2, _("Problem loading openssl configuration"));
		NCONF_free(req_conf);
		return pc;
	     }
          }
       }
       BIO_free(out);
       out = NULL;
    }

    if(create_master_password(password, sizeof(password), first_time)
	&& (pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) != NULL
	&& EVP_PKEY_keygen_init(pkctx) > 0
	&& EVP_PKEY_CTX_set_rsa_keygen_bits(pkctx, 2048) > 0	/* RSA:2048 */
	&& EVP_PKEY_keygen(pkctx, &pkey) > 0){
	snprintf(tmp, sizeof(tmp), "%s.key", fname);
	tmp[sizeof(tmp)-1] = '\0';
	keyfile = cpystr(tmp);		
	build_path(tmp, pathdir, keyfile, sizeof(tmp));
	keyfile[strlen(keyfile)-4] = '\0'; /* keyfile does not have .key extension */
	if((fp = fopen(tmp, "w")) != NULL
	    && (out = BIO_new_fp(fp, BIO_CLOSE | BIO_FP_TEXT)) != NULL
	    && PEM_write_bio_PrivateKey(out, pkey, EVP_des_ede3_cbc(),
                                      NULL, 0, NULL, password)){
	    BIO_free(out);
	    out = NULL;
	}
	memset((void *)password, 0, sizeof(password));
	if((req = X509_REQ_new()) != NULL
	    && X509_REQ_set_version(req, 0L)){
	    name = X509_REQ_get_subject_name(req);
	    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Password File Certificate and Key Pair", -1, -1, 0);
	    if(X509_REQ_set_pubkey(req, pkey)
		&& (pcert = X509_new()) != NULL){
		if(X509_set_version(pcert, version)
		   && (b = BN_new()) != NULL	
		   && BN_set_word(b, 65537)
		   && BN_pseudo_rand(b, 64, 0, 0)
		   && X509_get_serialNumber(pcert) 
		   && BN_to_ASN1_INTEGER(b, X509_get_serialNumber(pcert)) /* set serial */
		   && X509_set_issuer_name(pcert, X509_REQ_get_subject_name(req))
		   && X509_set_subject_name(pcert, X509_REQ_get_subject_name(req))){
		      X509V3_CTX ext_ctx;
		      EVP_PKEY *tmppkey;

		      X509_gmtime_adj(X509_getm_notBefore(pcert), 0);
		      X509_time_adj_ex(X509_getm_notAfter(pcert), 1095, 0, NULL);

		      if((tmppkey = X509_REQ_get0_pubkey(req)) != NULL
		         && X509_set_pubkey(pcert, tmppkey)){
			 if(extensions != NULL && version == 2){
			     X509V3_set_ctx(&ext_ctx, pcert, pcert, NULL, NULL, 0);
			     if(req_conf){	/* only if template is not null */
			       X509V3_set_nconf(&ext_ctx, req_conf);
			       X509V3_EXT_add_nconf(req_conf, &ext_ctx, extensions, pcert);
			     }
			 }
			 EVP_PKEY_free(tmppkey);
			 X509_sign(pcert, pkey, NULL);
		      }
		      BN_free(b);
		   }
		}
	    }

	    snprintf(tmp, sizeof(tmp), "%s.crt", fname);
	    tmp[sizeof(tmp)-1] = '\0';
	    certfile = cpystr(tmp);
	    build_path(tmp, pathdir, certfile, sizeof(tmp));
	    if((fp = fopen(tmp, "w")) != NULL
		&&(out = BIO_new_fp(fp, BIO_FP_TEXT)) != NULL){
	      EVP_PKEY *tpubkey = X509_REQ_get0_pubkey(req);
	      PEM_write_bio_X509(out, pcert);
	      BIO_flush(out);
	      BIO_free(out);
	      out = NULL;
	    }
	    if(req_conf)
	       NCONF_free(req_conf);
    }
    if(keyfile && certfile && pkey && pcert){
        pc = (PERSONAL_CERT *) fs_get(sizeof(PERSONAL_CERT));
        memset((void *)pc, 0, sizeof(PERSONAL_CERT));
        pc->name = keyfile;
        pc->key  = pkey;
        pc->cert = pcert;
        pc->cname = certfile;
    }
    first_time = 0;
    return pc;
}

CertList *
smime_X509_to_cert_info(X509 *x, char *name)
{
  CertList *cert;
  char buf[MAXPATH+1];

  if(x == NULL) return NULL;

  cert = fs_get(sizeof(CertList));
  memset((void *)cert, 0, sizeof(CertList));
  cert->x509_cert = x;
  cert->name = name ? cpystr(name) : NULL;
  cert->data.date_from = smime_get_date(X509_get0_notBefore(x));
  cert->data.date_to = smime_get_date(X509_get0_notAfter(x));
  cert->cn = smime_get_cn(x);
  get_fingerprint(x, EVP_md5(), buf, sizeof(buf), NULL);
  cert->data.md5 = cpystr(buf);

  return cert;
}

#define SMIME_BACKUP_DIR	".backup"
#define MAX_TRY_BACKUP		100

/* return value: 0 - success, -1 error 
 * Call this function after setting up paths in ps_global->smime
 * and reading certificates names in certlist.
 */
int
setup_certs_backup_by_type(WhichCerts ctype)
{
   int rv = 0; 	/* assume success */
   int len;
   int i, done;
   char *d, *fname;
   char p[MAXPATH+1];	/* path to where the backup is */
   char buf[MAXPATH+1], buf2[MAXPATH+1];
   struct stat sbuf;
   CertList *data, *cl;
#ifndef _WINDOWS
   DIR *dirp;   
   struct dirent *df;	/* file in the directory */
#else /* _WINDOWS */
    struct _finddata_t dbuf;
    char bufn[_MAX_PATH + 4];
    long findrv;
#endif /* !_WINDOWS */
   CertList *cert, *cl2;
   X509 *x;
   BIO *in;

   return rv;	/* remove when this function is complete */

   if(SMHOLDERTYPE(ctype) == Directory){
     d = PATHCERTDIR(ctype);
     if(d != NULL){
       len = strlen(d) + strlen(S_FILESEP) + strlen(SMIME_BACKUP_DIR) + 1;
       snprintf(p, MAXPATH, "%s%s%s", d, S_FILESEP, SMIME_BACKUP_DIR);
       p[MAXPATH] = '\0';
       if(our_stat(p, &sbuf) < 0){
	 if(our_mkpath(p, 0700) != 0)
	   return -1;
       } else if((sbuf.st_mode & S_IFMT) != S_IFDIR){
	 for(i = 0, done = 0; done == 0 && i < MAX_TRY_BACKUP; i++){
	    snprintf(buf2, len+2, "%s%d", p, i);
	    if(our_stat(buf2, &sbuf) < 0){
	       if(our_mkpath(buf2, 0700) == 0)
		 done++;
	    }
	    else if((sbuf.st_mode & S_IFMT) == S_IFDIR)
		done++;
	    if(done){
		strncpy(p, buf2, MAXPATH);
		p[MAXPATH] = '\0';
	    }
	 }
	 if(done == 0)
	   return -1;
       }
       /* if we are here, we have a backup directory where to
        * backup certificates/keys, so now we will go
        * through the list of certificates and back them up
        * if we need to.
        */
	data = BACKUPDATACERT(ctype);
	for(cl = DATACERT(ctype); cl; cl = cl->next){
	   char clname[MAXPATH+1];

	   snprintf(clname, MAXPATH, "%s%s", cl->name, ctype == Private ? ".key" : "");
	   clname[MAXPATH] = '\0';
	   len = strlen(d) + strlen(clname) + 2;
	   if(len < MAXPATH){
	     snprintf(buf, len, "%s%s%s", d, S_FILESEP, clname);
	     buf[sizeof(buf)-1] = '\0';
	     len = strlen(p) + strlen(clname) + strlen(cl->data.md5) + 3;
	     if(len < MAXPATH){
		snprintf(buf2, len, "%s%s%s.%s", p, S_FILESEP, clname, cl->data.md5);
		buf2[sizeof(buf2)-1] = '\0';
		done = 0;	/* recycle done: it means we have a file that may be a certificate*/
		if(stat(buf2, &sbuf) < 0){
		  if (our_copy(buf2, buf) == 0)
		     done++;
		} else if((sbuf.st_mode & S_IFMT) == S_IFREG)
		     done++;

		if(done){
		  switch(ctype){
			case Public:
			case CACert: 
				if((in = BIO_new_file(buf2, "r"))!=0){
				  cert = fs_get(sizeof(CertList));
				  memset((void *)cert, 0, sizeof(CertList));
				  cert->x509_cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
				  if(cl->data.date_from != NULL)
				   cert->data.date_from	= cpystr(cl->data.date_from);
				  if(cl->data.date_to != NULL)
				   cert->data.date_to	= cpystr(cl->data.date_to);
				  if(cl->data.md5 != NULL)
				   cert->data.md5	= cpystr(cl->data.md5);
				  if(cl->cn != NULL)
				   cert->cn  = cpystr(cl->cn);
				  snprintf(buf2, len, "%s.%s", cl->name, cl->data.md5);
				  buf2[sizeof(buf2)-1] = '\0';
				  cert->name = cpystr(buf2);
				  if(data == NULL)
				    data = cert;
				  else{
				    for (cl2 = data; cl2 && cl2->next; cl2 = cl2->next);
				    cl2->next = cert;
				  }
				  BIO_free(in);
				}
				break;

			case Private: break;
			default: alpine_panic("Bad ctype (0)");
		  }
		}
	     }
	   }
	}
	/* if we are here, it means we just loaded the backup variable with
	 * a copy of the data that comes from the certlist not coming from
	 * backup. Now we are going to load the contents of the .backup
	 * directory.
	 */

	/* Here is the plan: read the backup directory (in the variable "p")
	 * and attempt to add it. If already there, skip it; otherwise continue
	 */
#ifndef _WINDOWS
	if ((dirp = opendir(p)) != NULL) {
		while ((df = readdir(dirp)) != NULL) {
			fname = df->d_name;

			if (fname && *fname == '.')	/* no hidden files here */
				continue;
#else
	snprintf(bufn, sizeof(bufn), "%s%s*.*", p, (p[strlen(p) - 1] == '\\') ? "" : "\\");
	bufn[sizeof(bufn) - 1] = '\0';
	if ((findrv = _findfirst(bufn, &dbuf)) >= 0) {
		do {
			fname = fname_to_utf8(dbuf.name);
#endif /* ! _WINDOWS */
			/* make sure that we have a file */
			snprintf(buf2, sizeof(buf2), "%s%s%s", p, S_FILESEP, fname);
			buf2[sizeof(buf2) - 1] = '\0';
			if (our_stat(buf2, &sbuf) == 0
				&& (sbuf.st_mode & S_IFMT) != S_IFREG)
				continue;

			/* make sure it is not already in the list */
			for (cl = data; cl; cl = cl->next)
				if (strcmp(cl->name, fname) == 0)
					break;
			if (cl != NULL)
				continue;

			/* ok, if it is not in the list, and it is a certificate. Add it */
			switch (ctype) {
			case Public:
			case CACert:
				if ((in = BIO_new_file(buf2, "r")) != 0) {
					x = PEM_read_bio_X509(in, NULL, NULL, NULL);
					if (x) { /* for now copy this information */
						cert = smime_X509_to_cert_info(x, fname);
						/* we will use the cert->data.md5 variable to find a backup
						   certificate, not the name */
						cert->next = data;
						data = cert;
					}
					BIO_free(in);
				}
				break;

			case Private:
				/* here we must check it is a key of some cert....*/
				break;

			default: alpine_panic("Bad ctype (1)");
			} /* end switch */
#ifndef _WINDOWS
		}
		closedir(dirp);
#else /* _WINDOWS */
	} while (_findnext(findrv, &dbuf) == 0);
	_findclose(findrv);
#endif /* ! _WINDOWS */
		}
	/* Now that we are here, we have all the information in the backup
	 * directory
	 */

	switch (ctype) {
	case Public: ps_global->smime->backuppubliccertlist = data; break;
	case Private: ps_global->smime->backupprivatecertlist = data; break;
	case CACert: ps_global->smime->backupcacertlist = data; break;
	default: alpine_panic("Bad ctype (n)");
	}
	}
   } else if(SMHOLDERTYPE(ctype) == Container){
    
   } /* else APPLEKEYCHAIN */
   return rv;
}

char *
smime_get_cn(X509 *x)
{
   X509_NAME_ENTRY *e;
   X509_NAME *subject;
   char    buf[256];
   char *rv = NULL;

   subject = X509_get_subject_name(x);
   if((e = X509_NAME_get_entry(subject, X509_NAME_entry_count(subject)-1)) != NULL){
      X509_NAME_get_text_by_OBJ(subject, X509_NAME_ENTRY_get_object(e), buf, sizeof(buf));
      rv = cpystr(buf);
   }

   return rv;
}

int
compare_certs_by_name(const void *data1, const void *data2)
{
   int rv, i, j;
   char *s;

   CertList *cl1 = *(CertList **) data1;
   CertList *cl2 = *(CertList **) data2;

   i = j = -1;
   if((s = strchr(cl1->name, '@')) != NULL){
     i = s - cl1->name;
     *s = '\0';
   }

   if((s = strchr(cl2->name, '@')) != NULL){
     j = s - cl2->name;
     *s = '\0';
   }

   if((rv = strucmp(cl1->name, cl2->name)) == 0)
     rv = strucmp(cl1->name + i + 1, cl2->name + j + 1);
   if(i >= 0) cl1->name[i] = '@';
   if(j >= 0) cl2->name[j] = '@';
   return rv;
}

void
resort_certificates(CertList **data, WhichCerts ctype)
{
   int i, j;
   CertList *cl = *data;
   CertList **cll;
   char *s, *t;

   if(cl == NULL)
     return;

   for(i = 0; cl; cl = cl->next, i++)
      if(SMHOLDERTYPE(ctype) == Directory && ctype != Private){
           for(t = s = cl->name; (t = strstr(s, ".crt")) != NULL; s = t+1);
           if (s) *(s-1) = '\0';
      }
   j = i;
   cll = fs_get(i*sizeof(CertList *));
   for(cl = *data, i = 0; cl; cl = cl->next, i++)
        cll[i] = cl;
   qsort((void *)cll, j, sizeof(CertList *), compare_certs_by_name);
   for(i = 0; i < j - 1; i++){
     cll[i]->next = cll[i+1];
     if(SMHOLDERTYPE(ctype) == Directory && ctype != Private)
        cll[i]->name[strlen(cll[i]->name)]= '.';    /* restore ".crt" part */
   }
   if(SMHOLDERTYPE(ctype) == Directory && ctype != Private)
      cll[j-1]->name[strlen(cll[j-1]->name)]= '.';    /* restore ".crt" part */
   cll[j-1]->next = NULL;
   *data = cll[0];
}


void
get_fingerprint(X509 *cert, const EVP_MD *type, char *buf, size_t maxLen, char *s)
{
    unsigned char md[128];
    char    *b;
    unsigned int len, i;

    len = sizeof(md);

    X509_digest(cert, type, md, &len);

    b = buf;
    *b = 0;
    for(i=0; i<len; i++){
	if(b-buf+3>=maxLen)
	  break;

	if(i != 0 && s && *s)
	  *b++ = *s;

	snprintf(b, maxLen - (b-buf), "%02x", md[i]);
	b+=2;
    }
}


/*
 * Remove leading whitespace, trailing whitespace and convert 
 * to lowercase. Also remove slash characters
 *
 * Args: s, -- The string to clean
 *
 * Result: the cleaned string
 */
static char *
emailstrclean(char *string)
{
    char *s = string, *sc = NULL, *p = NULL;

    for(; *s; s++){				/* single pass */
	if(!isspace((unsigned char) (*s))){
	    p = NULL;				/* not start of blanks   */
	    if(!sc)				/* first non-blank? */
	      sc = string;			/* start copying */
	}
	else if(!p)				/* it's OK if sc == NULL */
	  p = sc;				/* start of blanks? */

	if(sc && *s!='/' && *s!='\\')		/* if copying, copy */
	  *sc++ = isupper((unsigned char) (*s))
			  ? (unsigned char) tolower((unsigned char) (*s))
			  : (unsigned char) (*s);
    }

    if(p)					/* if ending blanks  */
      *p = '\0';				/* tie off beginning */
    else if(!sc)				/* never saw a non-blank */
      *string = '\0';				/* so tie whole thing off */

    return(string);
}


char *
smime_get_date(const ASN1_TIME *tm)
{
   BIO *mb = BIO_new(BIO_s_mem());
   char iobuf[4096];
   char date[MAILTMPLEN];
   char buf[MAILTMPLEN];
   char *m, *d, *t, *y, *z;
   int len;
   struct date smd;
   struct tm smtm;

   (void) BIO_reset(mb);
   if(ASN1_TIME_print(mb, tm) == 0)
     return cpystr(_("Invalid"));

   (void) BIO_flush(mb);
   len = BIO_read(mb, iobuf, sizeof(iobuf));
   iobuf[len-1] = '\0';

  /* openssl returns the date in the format:
   *	"MONTH (as name) DAY (as number) TIME(hh:mm:ss) YEAR GMT"
   */
   m = iobuf;
   d = strchr(iobuf, ' ');
   *d++ = '\0';
   while(*d == ' ') d++;
   t = strchr(d+1, ' ');
   *t++ = '\0';
   while(*t == ' ') t++;
   y = strchr(t+1, ' ');
   *y++ = '\0';
   while(*y == ' ') y++;
   z = strchr(y+1, ' ');
   *z++ = '\0';
   while(*z == ' ') z++;

   snprintf(date, sizeof(date), "%s %s %s %s (%s)", d, m, y, t, z);
   date[sizeof(date)-1] = '\0';
   if(F_ON(F_DATES_TO_LOCAL,ps_global)){
      parse_date(convert_date_to_local(date), &smd);
      memset(&smtm, 0, sizeof(smtm));
      smtm.tm_year = smd.year - 1900;
      smtm.tm_mon  = MIN(MAX(smd.month-1, 0), 11);
      smtm.tm_mday = MIN(MAX(smd.day, 1), 31);
      our_strftime(buf, sizeof(buf), "%x", &smtm);
   }
   else
      snprintf(buf, sizeof(buf), "%s/%s/%s", m, d, y + strlen(y) - 2);
   buf[sizeof(buf)-1] = '\0';

   BIO_free(mb);
   return cpystr(buf);
}

/*
 * Add a lookup for each "*.crt*" file in the given directory.
 */
int
add_certs_in_dir(X509_LOOKUP *lookup, char *path, char *ext, CertList **cdata)
{
    char buf[MAXPATH], *fname;
#ifndef _WINDOWS
    struct direct *d;
    DIR       *dirp;  
#else /* _WINDOWS */
    struct _finddata_t dbuf;
    char bufn[_MAX_PATH + 4];
    long findrv;
#endif /* !_WINDOWS */
    CertList *cert, *cl;
    int  ret = 0, nfiles = 0, nerr = 0;

#ifndef _WINDOWS
    if((dirp = opendir(path)) != NULL){
      while(!ret && (d=readdir(dirp)) != NULL){
            fname = d->d_name;
#else /* _WINDOWS */
    snprintf(bufn, sizeof(bufn), "%s%s*.*", path, (path[strlen(path)-1] == '\\') ? "" : "\\");
    bufn[sizeof(bufn)-1] = '\0';
    if((findrv = _findfirst(bufn, &dbuf)) >= 0){
      do{
          fname = fname_to_utf8(dbuf.name);
#endif /* ! _WINDOWS */
            if(srchrstr(fname, ext)){
              nfiles++;
              build_path(buf, path, fname, sizeof(buf));

    	    	if(!X509_LOOKUP_load_file(lookup, buf, X509_FILETYPE_PEM)){
		    q_status_message1(SM_ORDER, 3, 3, _("Error loading file %s"), buf);
		    nerr++;
		} else {
		  if(cdata){
		     BIO *in;
		     X509 *x;

		     cert = fs_get(sizeof(CertList));
		     memset((void *)cert, 0, sizeof(CertList));
		     cert->name = cpystr(fname);
		     /* read buf into a bio and fill the CertData structure */
		     if((in = BIO_new_file(buf, "r"))!=0){
			if((x = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL){
			   cert->data.date_from	= smime_get_date(X509_get0_notBefore(x));
			   cert->data.date_to	= smime_get_date(X509_get0_notAfter(x));
			   get_fingerprint(x, EVP_md5(), buf, sizeof(buf), NULL);
			   cert->data.md5	= cpystr(buf);
			   cert->cn = smime_get_cn(x);
			   X509_free(x);
			}
			BIO_free(in);
		     }
		     if(*cdata == NULL)
			*cdata = cert;
		     else{
		        for (cl = *cdata; cl && cl->next; cl = cl->next);
		        cl->next = cert;
		     }
		  }

		}
            }

#ifndef _WINDOWS
      }
      closedir(dirp);
#else  /* _WINDOWS */
      } while(_findnext(findrv, &dbuf) == 0);
      _findclose(findrv);
#endif /* ! _WINDOWS */
    }

    /* if all certificates fail to load */
    if(nerr > 0 && nerr == nfiles) ret = -1;
    return ret;
}


/*
 * Get an X509_STORE. This consists of the system
 * certs directory and any certificates in the user's
 * ~/.alpine-smime/ca directory.
 */
X509_STORE *
get_ca_store(void)
{
    X509_LOOKUP	*lookup;
    X509_STORE *store = NULL;

    dprint((9, "get_ca_store()"));

    if(!(store=X509_STORE_new())){
	dprint((9, "X509_STORE_new() failed"));
	return store;
    }

    if(!(lookup=X509_STORE_add_lookup(store, X509_LOOKUP_file()))){
	dprint((9, "X509_STORE_add_lookup() failed"));
	free_x509_store(&store);
	return NULL;
    }
    
    if(ps_global->smime && ps_global->smime->catype == Container
       && ps_global->smime->cacontent){

	if(!mem_add_extra_cacerts(ps_global->smime->cacontent, lookup)){
	    free_x509_store(&store);
	    return NULL;
	}
    }
    else if(ps_global->smime && ps_global->smime->catype == Directory
	    && ps_global->smime->capath){
	if(add_certs_in_dir(lookup, ps_global->smime->capath, ".crt", &ps_global->smime->cacertlist) < 0){
	    free_x509_store(&store);
	    return NULL;
	}
	resort_certificates(&ps_global->smime->cacertlist, CACert);
    }

    if(!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir()))){
	free_x509_store(&store);
	return NULL;
    }

#ifdef SMIME_SSLCERTS
    dprint((9, "get_ca_store(): adding cacerts from %s", SMIME_SSLCERTS));
    X509_LOOKUP_add_dir(lookup, SMIME_SSLCERTS, X509_FILETYPE_PEM);
#endif

    return store;
}

void
free_x509_store(X509_STORE **xstore)
{
  if(xstore == NULL || *xstore == NULL)
     return;
  X509_STORE_free(*xstore);
  *xstore = NULL;
}

EVP_PKEY *
load_key(PERSONAL_CERT *pc, char *pass, int flag)
{
    BIO *in;
    EVP_PKEY *key = NULL;
    char buf[MAXPATH], file[MAXPATH];

    if(!(ps_global->smime && pc && pc->name))
      return key;

    if(ps_global->smime->privatetype == Container){
	char *q;
	
	if(pc->keytext && (q = strstr(pc->keytext, "-----END")) != NULL){
	    while(*q && *q != '\n')
	      q++;

	    if(*q == '\n')
	      q++;

	    if((in = BIO_new_mem_buf(pc->keytext, q-pc->keytext)) != NULL){
		key = PEM_read_bio_PrivateKey(in, NULL, NULL, pass);
		BIO_free(in);
	    }
	}
    }
    else if(ps_global->smime->privatetype == Directory){
	/* filename is path/name.key */
	strncpy(buf, pc->name, sizeof(buf)-5);
	buf[sizeof(buf)-5] = '\0';
	strncat(buf, ".key", 5);
	build_path(file, ps_global->smime->privatepath, buf, sizeof(file));

	if(!(in = BIO_new_file(file, "r")))
	  return NULL;
	  
	key = PEM_read_bio_PrivateKey(in, NULL, NULL, pass);
	BIO_free(in);
    }

    return key;
}


#include <openssl/x509v3.h>
/*
 * This newer version is from Adrian Vogel. It looks for the email
 * address not only in the email address field, but also in an
 * X509v3 extension field, Subject Alternative Name.
 */
char **
get_x509_subject_email(X509 *x)
{
    char **result = NULL;
    int i, n;
    STACK_OF(OPENSSL_STRING) *emails = X509_get1_email(x);
    if ((n = sk_OPENSSL_STRING_num(emails)) > 0) {
	result = fs_get((n+1)*sizeof(char *));
	for(i = 0; i < n; i++)
	  result[i] = cpystr(sk_OPENSSL_STRING_value(emails, i));
	result[i] = NULL;
    }
    X509_email_free(emails);
    return result;
}


/*
 * Save the certificate for the given email address in
 * ~/.alpine-smime/public.
 *
 * Should consider the security hazards in making a file with
 * the email address that has come from the certificate.
 *
 * The argument email is destroyed.
 * 
 * args: ctype says where the user wants to save the certificate
 */
void
save_cert_for(char *email, X509 *cert, WhichCerts ctype)
{
    if(!ps_global->smime || ctype == Private)
      return;

    dprint((9, "save_cert_for(%s, %s)", email ? email : "?", ctype == Public ? _("Public") : ctype == Private ? _("Private") : "CACert"));
    emailstrclean(email);

    if(ps_global->smime->publictype == Keychain){
#ifdef APPLEKEYCHAIN

	OSStatus rc;
	SecCertificateRef secCertificateRef;
	CSSM_DATA certData;

	memset((void *) &certData, 0, sizeof(certData));
	memset((void *) &secCertificateRef, 0, sizeof(secCertificateRef));

	/* convert OpenSSL X509 cert data to MacOS certData */
	if((certData.Length = i2d_X509(cert, &(certData.Data))) > 0){

	    /*
	     * Put that certData into a SecCertificateRef.
	     * Version 3 should work for versions 1-3.
	     */
	    if(!(rc=SecCertificateCreateFromData(&certData,
					         CSSM_CERT_X_509v3,
						 CSSM_CERT_ENCODING_DER,
						 &secCertificateRef))){

		/* add it to the default keychain */
		if(!(rc=SecCertificateAddToKeychain(secCertificateRef, NULL))){
		    /* ok */
		}
		else if(rc == errSecDuplicateItem){
		    dprint((9, "save_cert_for: certificate for %s already in keychain", email));
		}
		else{
		    dprint((9, "SecCertificateAddToKeychain failed"));
		}
	    }
	    else{
		dprint((9, "SecCertificateCreateFromData failed"));
	    }
	}
	else{
	    dprint((9, "i2d_X509 failed"));
	}

#endif /* APPLEKEYCHAIN */
    }
    else if(SMHOLDERTYPE(ctype) == Container){
	REMDATA_S *rd = NULL;
	char	  *ret_dir = NULL;
	char       path[MAXPATH];
	char	   fpath[MAXPATH];
	char	  *upath = PATHCERTDIR(ctype);
	char      *tempfile = NULL;
	int        err = 0;
	CertList  *clist = DATACERT(ctype);

	add_to_end_of_certlist(&clist, email, X509_dup(cert));

	switch(ctype){
	 case Private: ps_global->smime->privatecertlist = clist; break;
	 case Public : ps_global->smime->publiccertlist = clist; break;
	 case CACert : ps_global->smime->cacertlist = clist; break;
	      default: break;
	}

	if(!upath)
	  return;

	if(IS_REMOTE(upath)){
	    rd = rd_create_remote(RemImap, upath, REMOTE_SMIME_SUBTYPE,
				  NULL, "Error: ",
				  _("Can't access remote smime configuration."));
	    if(!rd){
	      return;
	    }
	    
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

		    dprint((1, "save_cert_for: rd_update_local failed\n"));
		    rd_close_remdata(&rd);
		    return;
		}
	    }
	    else
	      rd_open_remote(rd);

	    if(rd->access != ReadWrite || rd_remote_is_readonly(rd)){
		rd_close_remdata(&rd);
		return;
	    }

	    rd->flags |= DO_REMTRIM;

	    strncpy(path, rd->lf, sizeof(path)-1);
	    path[sizeof(path)-1] = '\0';
	}
	else{
	    strncpy(path, upath, sizeof(path)-1);
	    path[sizeof(path)-1] = '\0';
	}

	tempfile = tempfile_in_same_dir(path, "az", &ret_dir);
	if(tempfile){
	    if(certlist_to_file(tempfile, DATACERT(ctype)))
	      err++;

	    if(!err && ret_dir){
		if(IS_REMOTE(upath)){
		   strncpy(fpath, rd->lf, sizeof(fpath));
		   fpath[sizeof(fpath)-1] = '\0';
		}
		else{
		   if(strlen(path) + strlen(tempfile) - strlen(ret_dir) + 1 < sizeof(path))
		     snprintf(fpath, sizeof(fpath), "%s%c%s", 
			path, tempfile[strlen(ret_dir)], tempfile + strlen(ret_dir) + 1);
		   else
		     err++;
		}
	    }
	    else err++;

	    fs_give((void **)&ret_dir);

	    if(!err){
		if(rename_file(tempfile, fpath) < 0){
		    q_status_message2(SM_ORDER, 3, 3,
			_("Can't rename %s to %s"), tempfile, fpath);
		    err++;
		}
	    }

	    if(!err && IS_REMOTE(upath)){
		int   e, we_cancel;
		char datebuf[200];

		datebuf[0] = '\0';

		we_cancel = busy_cue(_("Copying to remote smime container"), NULL, 1);
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
       _("Copy of smime cert to remote folder failed, changes NOT saved remotely"));
		}
		else{
		    rd_update_metadata(rd, datebuf);
		    rd->read_status = 'W';
		}

		rd_close_remdata(&rd);

		if(we_cancel)
		  cancel_busy_cue(-1);
	    }

	    fs_give((void **) &tempfile);
	}
    }
    else if(SMHOLDERTYPE(ctype) == Directory){
	char   *path = PATHCERTDIR(ctype);
	char    certfilename[MAXPATH];
	BIO    *bio_out;

	build_path(certfilename, path, email, sizeof(certfilename));
	strncat(certfilename, ".crt", sizeof(certfilename)-1-strlen(certfilename));
	certfilename[sizeof(certfilename)-1] = 0;

	bio_out = BIO_new_file(certfilename, "w");
	if(bio_out){
	    PEM_write_bio_X509(bio_out, cert);
	    BIO_free(bio_out);
	    q_status_message1(SM_ORDER, 1, 1, _("Saved certificate for <%s>"), email);
	}
	else{
	    q_status_message1(SM_ORDER, 1, 1, _("Couldn't save certificate for <%s>"), email);
	}
    }
}


/*
 * Try to retrieve the certificate for the given email address.
 * The caller should free the cert.
 */
X509 *
get_cert_for(char *email, WhichCerts ctype, int tolower)
{
    char	certfilename[MAXPATH];
    char    	emailaddr[MAXPATH];
    X509       *cert = NULL;
    BIO	       *in;

    if(ctype == Password){
	build_path(certfilename, PATHCERTDIR(ctype), email, sizeof(certfilename));
	strncat(certfilename, EXTCERT(Public), sizeof(certfilename)-1-strlen(certfilename));
	certfilename[sizeof(certfilename)-1] = 0;

	if((in = BIO_new_file(certfilename, "r"))!=0){

	    cert = PEM_read_bio_X509(in, NULL, NULL, NULL);

	    if(cert){
		/* could check email addr in cert matches */
	    }

	    BIO_free(in);
	}

       return cert;
    }

    if(!ps_global->smime)
      return cert;

    dprint((9, "get_cert_for(%s, %s)", email ? email : "?", "none yet"));

    if(ctype == Private)	/* there is no private certificate info */
      ctype = Public;		/* return public information instead    */
    strncpy(emailaddr, email, sizeof(emailaddr)-1);
    emailaddr[sizeof(emailaddr)-1] = 0;
    
    /* clean it up (lowercase, space removal) */
    if(tolower)
       emailstrclean(emailaddr);

    if(ps_global->smime->publictype == Keychain){
#ifdef APPLEKEYCHAIN

	OSStatus rc;
	SecKeychainItemRef itemRef = nil;
	SecKeychainAttributeList attrList;
	SecKeychainAttribute attrib;
	SecKeychainSearchRef searchRef = nil;
	CSSM_DATA certData;

	/* low-level form of MacOS data */
	memset((void *) &certData, 0, sizeof(certData));
	
	attrList.count = 1;
	attrList.attr = &attrib;

	/* kSecAlias means email address for a certificate */
	attrib.tag    = kSecAlias;
	attrib.data   = emailaddr;
	attrib.length = strlen(attrib.data);

	/* Find the certificate in the default keychain */
	if(!(rc=SecKeychainSearchCreateFromAttributes(NULL,
						       kSecCertificateItemClass,
						       &attrList,
						       &searchRef))){

	    if(!(rc=SecKeychainSearchCopyNext(searchRef, &itemRef))){

		/* extract the data portion of the certificate */
		if(!(rc=SecCertificateGetData((SecCertificateRef) itemRef, &certData))){

		    /*
		     * Convert it from MacOS form to OpenSSL form.
		     * The input is certData from above and the output
		     * is the X509 *cert.
		     */
		    if(!d2i_X509(&cert, &(certData.Data), certData.Length)){
			dprint((9, "d2i_X509 failed"));
		    }
		}
		else{
		    dprint((9, "SecCertificateGetData failed"));
		}
	    }
	    else if(rc == errSecItemNotFound){
		dprint((9, "get_cert_for: Public cert for %s not found", emailaddr));
	    }
	    else{
		dprint((9, "SecKeychainSearchCopyNext failed"));
	    }
	}
	else{
	    dprint((9, "SecKeychainSearchCreateFromAttributes failed"));
	}

	if(searchRef)
	  CFRelease(searchRef);

#endif /* APPLEKEYCHAIN */
    }
    else if(SMHOLDERTYPE(ctype) == Container){
	    CertList *cl;

	    for(cl = DATACERT(ctype); cl; cl = cl->next){
		if(cl->name && !strucmp(emailaddr, cl->name))
		  break;
	    }

	    if(cl)
	      cert = X509_dup((X509 *) cl->x509_cert);
    }
    else if(SMHOLDERTYPE(ctype) == Directory){
	build_path(certfilename, PATHCERTDIR(ctype), emailaddr, sizeof(certfilename));
	strncat(certfilename, EXTCERT(ctype), sizeof(certfilename)-1-strlen(certfilename));
	certfilename[sizeof(certfilename)-1] = 0;

	if((in = BIO_new_file(certfilename, "r"))!=0){

	    cert = PEM_read_bio_X509(in, NULL, NULL, NULL);

	    if(cert){
		/* could check email addr in cert matches */
	    }

	    BIO_free(in);
	}

    }

    return cert;
}

/*
 * load_cert_for_key finds a certificate in pathdir that matches a private key
 * pkey. It returns its name in certfile, and the certificate in *pcert.
 * return value: success: different from zero, failure 0. If both certfile
 * and pcert are NULL, this function returns if there is certificate that
 * matches the given key.
 */
int
load_cert_for_key(char *pathdir, EVP_PKEY *pkey, char **certfile, X509 **pcert)
{
#ifndef _WINDOWS
   DIR *dirp;
   struct dirent *d;
#else /* _WINDOWS */
    struct _finddata_t dbuf;
    char bufn[_MAX_PATH + 4];
    long findrv;
#endif /* ! _WINDOWS */
   size_t ll;
   int rv = 0;
   BIO *in;
   X509 *x;
   char buf[MAXPATH+1], pathcert[MAXPATH+1], *fname;

   if(pathdir == NULL || pkey == NULL)
    return 0;

   if(certfile) *certfile = NULL;
   if(pcert)    *pcert = NULL;
 
#ifndef _WINDOWS
   if((dirp = opendir(pathdir)) != NULL){
      while(rv == 0 && (d=readdir(dirp)) != NULL){
	fname = d->d_name;
#else
   snprintf(bufn, sizeof(bufn), "%s%s*.*", pathdir, (pathdir[strlen(pathdir)-1] == '\\') ? "" : "\\");
   bufn[sizeof(bufn)-1] = '\0';   
   if((findrv = _findfirst(bufn, &dbuf)) >= 0){
      do{
        fname = fname_to_utf8(dbuf.name);
#endif /* ! _WINDOWS */
	if((ll=strlen(fname)) && ll > 4){
	   if(!strcmp(fname+ll-4, ".crt")){
	     strncpy(buf, fname, sizeof(buf));
	     buf[sizeof(buf)-1] = '\0';
	     build_path(pathcert, pathdir, buf, sizeof(pathcert));
	     if((in = BIO_new_file(pathcert, "r")) != NULL){
	        if((x = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL){
		  if(X509_check_private_key(x, pkey) > 0){
		    rv = 1;
		    if(certfile) *certfile = cpystr(buf);
		    if(pcert)    *pcert = x;
		  }
		  else
		    X509_free(x);
		}
	        BIO_free(in);
	     }
	   }
        }
#ifndef _WINDOWS
      }
      closedir(dirp);
#else /* _WINDOWS */
      } while(_findnext(findrv, &dbuf) == 0);
	  _findclose(findrv);
#endif
   }
   return rv;
}


PERSONAL_CERT *
mem_to_personal_certs(char *contents)
{
    PERSONAL_CERT *result = NULL;
    char *p, *q, *line, *name, *keytext, *save_p;
    X509 *cert = NULL;

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

	    if(strncmp(EMAILADDRLEADER, line, strlen(EMAILADDRLEADER)) == 0){
		name = line + strlen(EMAILADDRLEADER);
		cert = get_cert_for(name, Public, 1);
		keytext = p;

		/* advance p past this record */
		if((q = strstr(keytext, "-----END")) != NULL){
		    while(*q && *q != '\n')
		      q++;

		    if(*q == '\n')
		      q++;

		    p = q;
		}
		else{
		    p = p + strlen(p);
		    q_status_message(SM_ORDER | SM_DING, 3, 3, _("Error in privatekey container, missing END"));
		}

		if(cert){
		    PERSONAL_CERT *pc;

		    pc = (PERSONAL_CERT *) fs_get(sizeof(*pc));
		    pc->cert = cert;
		    pc->name = cpystr(name);
		    pc->cname = NULL;
		    pc->keytext = keytext;	/* a pointer into contents */

		    pc->key = load_key(pc, "", SM_NORMALCERT);

		    pc->next = result;
		    result = pc;
		}
	    }

	    if(save_p)
	      *save_p = '\n';
	}
    }

    return result;
}


CertList *
mem_to_certlist(char *contents, WhichCerts ctype)
{
    CertList *ret = NULL;
    char *p, *q, *line, *name, *certtext, *save_p;
    X509 *cert = NULL;
    BIO *in;
    char *sep = (ctype == Public || ctype == Private)
		? EMAILADDRLEADER : CACERTSTORELEADER;

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

	    if(strncmp(sep, line, strlen(sep)) == 0){
		name = line + strlen(sep);
		cert = NULL;
		certtext = strstr(p, "-----BEGIN");
		if(certtext != NULL){
		    if((q = strstr(certtext, sep)) != NULL)
			p = q;
		    else
			p = q = certtext+strlen(certtext);

		    if((in = BIO_new_mem_buf(certtext, q-certtext)) != 0){
			cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
			BIO_free(in);
		    }
		}
		else{
		    q_status_message2(SM_ORDER | SM_DING, 3, 3, _("Error in %scert container, missing BEGIN, certtext=%s"), ctype == Public ? _("public") : _("ca"), p);
		    p = p + strlen(p);
		}

		if(name && cert)
		    add_to_end_of_certlist(&ret, name, cert);
	    }

	    if(save_p)
	      *save_p = '\n';
	}
    }
    if(ret != NULL)
       resort_certificates(&ret, ctype);

    return ret;
}


/*
 * Add the CACert Container contents into the CACert store.
 *
 * Returns > 0 for success, 0 for failure
 */
int
mem_add_extra_cacerts(char *contents, X509_LOOKUP *lookup)
{
    char *p, *q, *line, *certtext, *save_p;
    BIO  *in, *out;
    int   len, failed = 0;
    char *tempfile;
    char  iobuf[4096];

    /*
     * The most straight-forward way to do this is to write
     * the container contents to a temp file and then load the
     * contents of the file with X509_LOOKUP_load_file(), like
     * is done in add_certs_in_dir(). What we don't know is if
     * each file should consist of one cacert or if they can all
     * just be jammed together into one file. To be safe, we'll use
     * one file per and do each in a separate operation.
     */

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

	    /* look for separator line */
	    if(strncmp(CACERTSTORELEADER, line, strlen(CACERTSTORELEADER)) == 0){
		/* certtext is the content that should go in a file */
		certtext = strstr(p, "-----BEGIN");
		if(certtext != NULL){
		    if((q = strstr(certtext, CACERTSTORELEADER)) != NULL){
			p = q;
		    }
		    else{		/* end of file */
			q = certtext + strlen(certtext);
			p = q;
		    }

		    in = BIO_new_mem_buf(certtext, q-certtext);
		    if(in){
			tempfile = temp_nam(NULL, "az");
			out = tempfile != NULL ? BIO_new_file(tempfile, "w") : NULL;
			if(out != NULL){
			    while((len = BIO_read(in, iobuf, sizeof(iobuf))) > 0)
			      BIO_write(out, iobuf, len);

			    BIO_free(out);
			    if(!X509_LOOKUP_load_file(lookup, tempfile, X509_FILETYPE_PEM))
			      failed++;

			}
			if(tempfile != NULL){
			   unlink(tempfile);
			   fs_give((void **) &tempfile);
			}
			  
			BIO_free(in);
		    }
		}
		else{
		    p = p + strlen(p);
		    q_status_message1(SM_ORDER | SM_DING, 3, 3, _("Error in cacert container, missing BEGIN, certtext=%s"), certtext);
		}
	    }
	    else{
		p = p + strlen(p);
                q_status_message1(SM_ORDER | SM_DING, 3, 3, _("Error in cacert container, missing separator, line=%s"), line);
	    }

	    if(save_p)
	      *save_p = '\n';
	}
    }

    return(!failed);
}


int
certlist_to_file(char *filename, CertList *certlist)
{
    CertList *cl;
    BIO      *bio_out = NULL;
    int       ret = -1;

    if(filename && (bio_out=BIO_new_file(filename, "w")) != NULL){
	ret = 0;
	for(cl = certlist; cl; cl = cl->next){
	    if(cl->name && cl->name[0] && cl->x509_cert){
		if(!((BIO_puts(bio_out, EMAILADDRLEADER) > 0)
		     && (BIO_puts(bio_out, cl->name) > 0)
		     && (BIO_puts(bio_out, "\n") > 0)))
		  ret = -1;

		if(!PEM_write_bio_X509(bio_out, (X509 *) cl->x509_cert))
		  ret = -1;
	    }
	}

	BIO_free(bio_out);
    }

    return ret;
}


void
add_to_end_of_certlist(CertList **cl, char *name, X509 *cert)
{
    CertList *new;

    if(!cl)
      return;

    new = smime_X509_to_cert_info(cert, name);
    new->next = *cl;
    *cl = new;
}


void
free_certlist(CertList **cl)
{
    if(cl && *cl){
	if((*cl)->data.date_from)
	  fs_give((void **) &(*cl)->data.date_from);

	if((*cl)->data.date_to)
	  fs_give((void **) &(*cl)->data.date_to);

	if((*cl)->data.md5)
	  fs_give((void **) &(*cl)->data.md5);

	if((*cl)->name)
	  fs_give((void **) &(*cl)->name);

	if((*cl)->cn)
	  fs_give((void **) &(*cl)->cn);

	if((*cl)->x509_cert)
	  X509_free((X509 *) (*cl)->x509_cert);

	free_certlist(&(*cl)->next);

	fs_give((void **) cl);
    }
}


void
free_personal_certs(PERSONAL_CERT **pc)
{
    if(pc && *pc){
	if((*pc)->name)
	  fs_give((void **) &(*pc)->name);
	
	if((*pc)->cname)
	  fs_give((void **) &(*pc)->cname);

	if((*pc)->cert)
	  X509_free((*pc)->cert);

	if((*pc)->key)
	  EVP_PKEY_free((*pc)->key);

	free_personal_certs(&(*pc)->next);

	fs_give((void **) pc);
    }
}

#endif /* SMIME */
