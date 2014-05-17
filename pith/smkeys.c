#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: smkeys.c 1266 2009-07-14 18:39:12Z hubert@u.washington.edu $";
#endif

/*
 * ========================================================================
 * Copyright 2013-2014 Eduardo Chappa
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

void
get_fingerprint(X509 *cert, const EVP_MD *type, char *buf, size_t maxLen)
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

	if(i != 0)
	  *b++ = ':';

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


/*
 * Add a lookup for each "*.crt" file in the given directory.
 */
int
add_certs_in_dir(X509_LOOKUP *lookup, char *path, char *ext, CertList **cdata)
{
    char buf[MAXPATH];
    struct direct *d;
    DIR	*dirp;
    CertList *cert, *cl;
    int  ret = 0;

    if((dirp = opendir(path)) != NULL){
        while(!ret && (d=readdir(dirp)) != NULL){
            if(srchrstr(d->d_name, ext)){
    	    	build_path(buf, path, d->d_name, sizeof(buf));

    	    	if(!X509_LOOKUP_load_file(lookup, buf, X509_FILETYPE_PEM)){
		    q_status_message1(SM_ORDER, 3, 3, _("Error loading file %s"), buf);
		    ret = -1;
		} else {
		  if(cdata){
		     cert = fs_get(sizeof(CertList));
		     memset((void *)cert, 0, sizeof(CertList));
		     cert->name = cpystr(d->d_name);
		     if(*cdata == NULL)
			*cdata = cert;
		     else{
		        for (cl = *cdata; cl && cl->next; cl = cl->next);
		           cl->next = cert;
		     }
		  }

		}
            }

        }

        closedir(dirp);
    }

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
	X509_STORE_free(store);
	return NULL;
    }
    
    if(ps_global->smime && ps_global->smime->catype == Container
       && ps_global->smime->cacontent){

	if(!mem_add_extra_cacerts(ps_global->smime->cacontent, lookup)){
	    X509_STORE_free(store);
	    return NULL;
	}
    }
    else if(ps_global->smime && ps_global->smime->catype == Directory
	    && ps_global->smime->capath){
	if(add_certs_in_dir(lookup, ps_global->smime->capath, ".crt", &ps_global->smime->cacertlist) < 0){
	    X509_STORE_free(store);
	    return NULL;
	}
    }

    if(!(lookup=X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir()))){
	X509_STORE_free(store);
	return NULL;
    }

#ifdef SMIME_SSLCERTS
    dprint((9, "get_ca_store(): adding cacerts from %s", SMIME_SSLCERTS));
    X509_LOOKUP_add_dir(lookup, SMIME_SSLCERTS, X509_FILETYPE_PEM);
#endif

    return store;
}


EVP_PKEY *
load_key(PERSONAL_CERT *pc, char *pass)
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
 * X509v3 extension field, Subject Altenative Name.
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
		if(strlen(path) + strlen(tempfile) - strlen(ret_dir) + 1 < sizeof(path))
		   snprintf(fpath, sizeof(fpath), "%s%c%s", 
			path, tempfile[strlen(ret_dir)], tempfile + strlen(ret_dir) + 1);
		else
		   err++;
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
get_cert_for(char *email, WhichCerts ctype)
{
    char	certfilename[MAXPATH];
    char    	emailaddr[MAXPATH];
    X509       *cert = NULL;
    BIO	       *in;

    if(!ps_global->smime)
      return cert;

    dprint((9, "get_cert_for(%s, %s)", email ? email : "?", "none yet"));

    if(ctype == Private)	/* there is no private certificate info */
      ctype = Public;		/* return public information instead    */
    strncpy(emailaddr, email, sizeof(emailaddr)-1);
    emailaddr[sizeof(emailaddr)-1] = 0;
    
    /* clean it up (lowercase, space removal) */
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
   DIR *dirp;
   struct dirent *d;
   int rv = 0;
   BIO *in;
   X509 *x;
   char buf[MAXPATH+1], pathcert[MAXPATH+1];

   if(pathdir == NULL || pkey == NULL)
    return 0;

   if(certfile) *certfile = NULL;
   if(pcert)    *pcert = NULL;
           
   if((dirp = opendir(pathdir)) != NULL){
      while(rv == 0 && (d=readdir(dirp)) != NULL){
        size_t ll;
    
	if((ll=strlen(d->d_name)) && ll > 4){
	   if(!strcmp(d->d_name+ll-4, ".crt")){
	     strncpy(buf, d->d_name, sizeof(buf));
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
      }
      closedir(dirp);
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
		cert = get_cert_for(name, Public);
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
		    pc->keytext = keytext;	/* a pointer into contents */

		    pc->key = load_key(pc, "");

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
			out = NULL;
			if(tempfile)
			  out = BIO_new_file(tempfile, "w");

			if(out){
			    while((len = BIO_read(in, iobuf, sizeof(iobuf))) > 0)
			      BIO_write(out, iobuf, len);

			    BIO_free(out);
			    if(!X509_LOOKUP_load_file(lookup, tempfile, X509_FILETYPE_PEM))
			      failed++;

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
    CertList *new, *clp;

    if(!cl)
      return;

    new = (CertList *) fs_get(sizeof(*new));
    memset((void *) new, 0, sizeof(*new));
    new->x509_cert = cert;
    new->name = name ? cpystr(name) : NULL;

    if(!*cl){
	*cl = new;
    }
    else{
	for(clp = (*cl); clp->next; clp = clp->next)
	  ;

	clp->next = new;
    }
}


void
free_certlist(CertList **cl)
{
    if(cl && *cl){
	free_certlist(&(*cl)->next);
	if((*cl)->name)
	  fs_give((void **) &(*cl)->name);

	if((*cl)->x509_cert)
	  X509_free((X509 *) (*cl)->x509_cert);

	fs_give((void **) cl);
    }
}


void
free_personal_certs(PERSONAL_CERT **pc)
{
    if(pc && *pc){
	free_personal_certs(&(*pc)->next);
	if((*pc)->name)
	  fs_give((void **) &(*pc)->name);
	
	if((*pc)->name)
	  fs_give((void **) &(*pc)->name);

	if((*pc)->cert)
	  X509_free((*pc)->cert);

	if((*pc)->key)
	  EVP_PKEY_free((*pc)->key);

	fs_give((void **) pc);
    }
}

#endif /* SMIME */
