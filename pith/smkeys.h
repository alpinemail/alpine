/*
 * $Id: smkeys.h 1074 2008-06-04 00:08:43Z hubert@u.washington.edu $
 *
 * ========================================================================
 * Copyrighr 2013-2014 Eduardo Chappa
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

#ifdef SMIME
#ifndef PITH_SMKEYS_INCLUDED
#define PITH_SMKEYS_INCLUDED


#include "../pith/state.h"
#include "../pith/send.h"

#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>


#define EMAILADDRLEADER "emailAddress="
#define CACERTSTORELEADER "cacert="


typedef struct personal_cert {
    X509    	    	 *cert;
    EVP_PKEY	    	 *key;
    char                 *name;
    char                 *keytext;
    struct personal_cert *next;
} PERSONAL_CERT;

/* flags that tell us where to look for certificates/keys */
#define SM_NORMALCERT	0x1	/* look in normal user defined directory */
#define SM_BACKUPCERT	0x2	/* look in backup directory */

/* exported protoypes */
int	       add_certs_in_dir(X509_LOOKUP *lookup, char *path, char *ext, CertList **cdata);
X509_STORE    *get_ca_store(void);
PERSONAL_CERT *get_personal_certs(char *d);
X509          *get_cert_for(char *email, WhichCerts ctype);
void           save_cert_for(char *email, X509 *cert, WhichCerts ctype);
char         **get_x509_subject_email(X509 *x);
EVP_PKEY      *load_key(PERSONAL_CERT *pc, char *pass, int flag);
CertList      *mem_to_certlist(char *contents, WhichCerts ctype);
void           add_to_end_of_certlist(CertList **cl, char *name, X509 *cert);
void           free_certlist(CertList **cl);
PERSONAL_CERT *mem_to_personal_certs(char *contents);
void           free_personal_certs(PERSONAL_CERT **pc);
void	       get_fingerprint(X509 *cert, const EVP_MD *type, char *buf, size_t maxLen, char *s);
int	       certlist_to_file(char *filename, CertList *certlist);
int	       load_cert_for_key(char *pathdir, EVP_PKEY *pkey, char **certfile, X509 **pcert);
char           *smime_get_date(ASN1_GENERALIZEDTIME *tm);
void	       resort_certificates(CertList **data, WhichCerts ctype);
int	       setup_certs_backup_by_type(WhichCerts ctype);

#endif /* PITH_SMKEYS_INCLUDED */
#endif /* SMIME */
