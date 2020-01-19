/*
 * $Id: smime.h 1074 2008-06-04 00:08:43Z hubert@u.washington.edu $
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
#ifndef PITH_SMIME_INCLUDED
#define PITH_SMIME_INCLUDED


#include "../pith/state.h"
#include "../pith/send.h"
#include "../pith/filttype.h"
#include "../pith/smkeys.h"

#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef PASSFILE
#define DF_PASSWORD_DIR ".alpine-smime/.pwd"
#endif
#define DF_SMIMETMPDIR  ".alpine-smime/smtmp"

#define OUR_PKCS7_ENCLOSURE_SUBTYPE "x-pkcs7-enclosure"


/* exported prototypes */
int	       smime_validate_cert(X509 *cert, long *error);
int	       encrypt_file(char *fp, char *text, PERSONAL_CERT *pc);
char 	      *decrypt_file(char *fp, int *rv, PERSONAL_CERT *pc);
int            is_pkcs7_body(BODY *b);
int            fiddle_smime_message(BODY *b, long msgno);
int            encrypt_outgoing_message(METAENV *header, BODY **bodyP);
int            sign_outgoing_message(METAENV *header, BODY **bodyP, int dont_detach, BODY **bp);
void           gf_puts_uline(char *txt, gf_io_t pc);
PERSONAL_CERT *find_certificate_matching_recip_info(PKCS7_RECIP_INFO *ri);
PERSONAL_CERT *get_personal_certs(char *path);
void           smime_init(void);
void           smime_deinit(void);
void           smime_reinit(void);
void	       renew_store(void);
void	       renew_cert_data(CertList **data, WhichCerts ctype);
BIO	      *print_private_key_information(char *email, int itype);

SMIME_STUFF_S *new_smime_struct(void);
int            copy_publiccert_dir_to_container(void);
int            copy_publiccert_container_to_dir(void);
int            copy_privatecert_dir_to_container(void);
int            copy_privatecert_container_to_dir(void);
int            copy_cacert_dir_to_container(void);
int            copy_cacert_container_to_dir(void);
int	       import_certificate(WhichCerts, PERSONAL_CERT *, char *);
int	       copy_dir_to_container(WhichCerts which, char *contents);
#ifdef APPLEKEYCHAIN
int            copy_publiccert_container_to_keychain(void);
int            copy_publiccert_keychain_to_container(void);
#endif /* APPLEKEYCHAIN */
#ifdef PASSFILE                                       
int           setup_pwdcert(void **pwdcert);
#endif /* PASSFILE */
void	       mark_cert_deleted(WhichCerts ctype, int num, unsigned state);
unsigned       get_cert_deleted(WhichCerts ctype, int num);
int	       smime_expunge_cert(WhichCerts ctype);
int	       add_file_to_container(WhichCerts ctype, char *fpath, char *altname);
STACK_OF(X509)       *get_chain_for_cert(X509 *cert, int *error, int *level);
CertList      *certlist_from_personal_certs(PERSONAL_CERT *pc);
int 	smime_path(char *rpath, char *fpath, size_t len);

#endif /* PITH_SMIME_INCLUDED */
#endif /* SMIME */
