/*
 * $Id: smkeys.h 1074 2008-06-04 00:08:43Z hubert@u.washington.edu $
 *
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
#include <openssl/safestack.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_1_1_0
#define X509_get0_notBefore(x) ((x) && (x)->cert_info                   \
                                ? (x)->cert_info->validity->notBefore   \
                                : NULL)
#define X509_get0_notAfter(x) ((x) && (x)->cert_info                    \
                                ? (x)->cert_info->validity->notAfter    \
                                : NULL)
#define X509_getm_notBefore(x) ((x) && (x)->cert_info                   \
                                ? (x)->cert_info->validity->notBefore	\
                                : NULL)
#define X509_getm_notAfter(x) ((x) && (x)->cert_info                    \
                                ? (x)->cert_info->validity->notAfter	\
                                : NULL)
#define X509_REQ_get0_pubkey(x) (X509_REQ_get_pubkey((x)))
#else
#include <openssl/rsa.h>
#include <openssl/bn.h>
#endif /* OPENSSL_1_1_0 */

#define EMAILADDRLEADER "emailAddress="
#define CACERTSTORELEADER "cacert="
#define MASTERNAME "MasterPassword"

typedef struct personal_cert {
    X509    	    	 *cert;
    EVP_PKEY	    	 *key;
    char                 *name;		/* name of key */
    char		 *cname;	/* name of cert */
    char                 *keytext;
    struct personal_cert *next;
} PERSONAL_CERT;

/* flags that tell us where to look for certificates/keys */
#define SM_NORMALCERT	0x1	/* look in normal user defined directory */
#define SM_BACKUPCERT	0x2	/* look in backup directory */

/* exported prototypes */
int	       add_certs_in_dir(X509_LOOKUP *lookup, char *path, char *ext, CertList **cdata);
X509_STORE    *get_ca_store(void);
void	       free_x509_store(X509_STORE **);
PERSONAL_CERT *get_personal_certs(char *d);
X509          *get_cert_for(char *email, WhichCerts ctype, int tolower);
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
char           *smime_get_date(const ASN1_TIME *tm);
void	       resort_certificates(CertList **data, WhichCerts ctype);
int	       setup_certs_backup_by_type(WhichCerts ctype);
char 	       *smime_get_cn(X509 *);
CertList       *smime_X509_to_cert_info(X509 *, char *);
PERSONAL_CERT  *ALPINE_self_signed_certificate(char *, int, char *, char *);

#endif /* PITH_SMKEYS_INCLUDED */
#endif /* SMIME */
