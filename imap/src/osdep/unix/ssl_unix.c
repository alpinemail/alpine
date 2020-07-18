/* ========================================================================
 * Copyright 2019 Eduardo Chappa
 * Copyright 2008-2009 Mark Crispin
 * ========================================================================
 */

/*
 * Program:	SSL authentication/encryption module
 *
 * Author:	Mark Crispin
 *
 * Date:	22 September 1998
 * Last Edited:	8 November 2009
 *
 * Previous versions of this file were
 *
 * Copyright 1988-2008 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#define crypt ssl_private_crypt
#define STRING OPENSSL_STRING
#include <x509v3.h>
#include <ssl.h>
#include <err.h>
#include <pem.h>
#include <buffer.h>
#include <bio.h>
#include <crypto.h>
#include <rand.h>
#ifdef OPENSSL_1_1_0
#include <rsa.h>
#include <bn.h>
#endif /* OPENSSL_1_1_0 */
#undef STRING
#undef crypt

#define SSLBUFLEN 8192

/*
 * PCI auditing compliance, disable:
 *  SSLv2
 *  anonymous D-H (no certificate
 *  export encryption ciphers (40 and 56 bits)
 *  low encryption cipher suites (40 and 56 bits, excluding export)
 *  null encryption (disabling implied by "ALL")
 *
 * UW imapd just disables low-grade and null ("ALL:!LOW").  This setting
 * will break clients that attempt to use the newly-prohibited mechanisms.
 *
 * I question the value of disabling SSLv2, as opposed to disabling the SSL
 * ports (e.g., 993 for IMAP, 995 for POP3) and using TLS exclusively.
 */

#define SSLCIPHERLIST "ALL:!SSLv2:!ADH:!EXP:!LOW"

/* SSL I/O stream */

typedef struct ssl_stream {
  TCPSTREAM *tcpstream;		/* TCP stream */
  SSL_CTX *context;		/* SSL context */
  SSL *con;			/* SSL connection */
  int ictr;			/* input counter */
  char *iptr;			/* input pointer */
  char ibuf[SSLBUFLEN];		/* input buffer */
} SSLSTREAM;

#include "sslio.h"

/* Function prototypes */
int ssl_disable_mask(int ssl_version, int direction);
const SSL_METHOD *ssl_connect_mthd(int flag, int *minv, int *maxv);
static SSLSTREAM *ssl_start(TCPSTREAM *tstream,char *host,unsigned long flags);
static char *ssl_start_work (SSLSTREAM *stream,char *host,unsigned long flags);
static int ssl_open_verify (int ok,X509_STORE_CTX *ctx);
static char *ssl_validate_cert (X509 *cert,char *host);
static long ssl_compare_hostnames (unsigned char *s,unsigned char *pat);
static char *ssl_getline_work (SSLSTREAM *stream,unsigned long *size,
			       long *contd);
static long ssl_abort (SSLSTREAM *stream);

#ifdef OPENSSL_1_1_0
#define SSL_CTX_TYPE SSL_CTX
#else
#define SSL_CTX_TYPE SSL
#endif /* OPENSSL_1_1_0 */

static RSA *ssl_genkey (SSL_CTX_TYPE *con,int export,int keylength);

typedef struct ssl_versions_s {
        char *name;
        int   version;
} SSL_VERSIONS_S;

int
pith_ssl_encryption_version(char *s)
{
        SSL_VERSIONS_S ssl_versions[] = {
        { "no_min", 0 },
        { "ssl3",   SSL3_VERSION },
        { "tls1",   TLS1_VERSION },
        { "tls1_1", TLS1_1_VERSION },
        { "tls1_2", TLS1_2_VERSION },
#ifdef TLS1_3_VERSION
        { "tls1_3", TLS1_3_VERSION },
#endif /* TLS1_3_VERSION */
        { "no_max", 0 },        /* set this last in the list */
        { NULL, 0 },
        };
        int i;

        if (s == NULL || *s == '\0')
                return -1;

        for (i = 0; ssl_versions[i].name != NULL; i++)
                if (strcmp(ssl_versions[i].name, s) == 0)
                        break;

        if (strcmp(s, "no_max") == 0) i--;

        return ssl_versions[i].name != NULL ? ssl_versions[i].version : -1;
}



/* Secure Sockets Layer network driver dispatch */

static struct ssl_driver ssldriver = {
  ssl_open,			/* open connection */
  ssl_aopen,			/* open preauthenticated connection */
  ssl_getline,			/* get a line */
  ssl_getbuffer,		/* get a buffer */
  ssl_soutr,			/* output pushed data */
  ssl_sout,			/* output string */
  ssl_close,			/* close connection */
  ssl_host,			/* return host name */
  ssl_remotehost,		/* return remote host name */
  ssl_port,			/* return port number */
  ssl_localhost,		/* return local host name */
  ssl_getsize			/* return needed number of bytes */
};
				/* non-NIL if doing SSL primary I/O */
static SSLSTDIOSTREAM *sslstdio = NIL;
static char *start_tls = NIL;	/* non-NIL if start TLS requested */

/* One-time SSL initialization */

static int sslonceonly = 0;

void ssl_onceonlyinit (void)
{
  if (!sslonceonly++) {		/* only need to call it once */
    int fd;
    char tmp[MAILTMPLEN];
    struct stat sbuf;
				/* if system doesn't have /dev/urandom */
    if (stat ("/dev/urandom",&sbuf)) {
      strcpy(tmp, "SSLXXXXXX");
      while ((fd = mkstemp(tmp)) < 0) sleep (1);
      fstat (fd,&sbuf);		/* get information about the file */
      close (fd);		/* flush descriptor */
      unlink (tmp);		/* don't need the file */
				/* not great but it'll have to do */
      sprintf (tmp + strlen (tmp),"%.80s%lx%.80s%lx%lx%lx%lx%lx",
	       tcp_serveraddr (),(unsigned long) tcp_serverport (),
	       tcp_clientaddr (),(unsigned long) tcp_clientport (),
	       (unsigned long) sbuf.st_ino,(unsigned long) time (0),
	       (unsigned long) gethostid (),(unsigned long) getpid ());
      RAND_seed (tmp,strlen (tmp));
    }
				/* apply runtime linkage */
    mail_parameters (NIL,SET_SSLDRIVER,(void *) &ssldriver);
    mail_parameters (NIL,SET_SSLSTART,(void *) ssl_start);
#ifdef OPENSSL_1_1_0
    OPENSSL_init_ssl(0, NULL);
#else
    SSL_library_init ();	/* add all algorithms */
#endif /* OPENSSL_1_1_0 */
  }
}

/* SSL open
 * Accepts: host name
 *	    contact service name
 *	    contact port number
 * Returns: SSL stream if success else NIL
 */

SSLSTREAM *ssl_open (char *host,char *service,unsigned long port)
{
  TCPSTREAM *stream = tcp_open (host,service,port);
  return stream ? ssl_start (stream,host,port) : NIL;
}


/* SSL authenticated open
 * Accepts: host name
 *	    service name
 *	    returned user name buffer
 * Returns: SSL stream if success else NIL
 */

SSLSTREAM *ssl_aopen (NETMBX *mb,char *service,char *usrbuf)
{
  return NIL;			/* don't use this mechanism with SSL */
}

typedef struct ssl_disable_s {
  int   version;
  int   disable_code;
} SSL_DISABLE_S;
        
SSL_DISABLE_S ssl_disable[] = {
    {SSL2_VERSION, SSL_OP_NO_SSLv2},
    {SSL3_VERSION, SSL_OP_NO_SSLv3},
    {TLS1_VERSION, SSL_OP_NO_TLSv1},
    {TLS1_1_VERSION, SSL_OP_NO_TLSv1_1},
    {TLS1_2_VERSION, SSL_OP_NO_TLSv1_2},
#ifdef TLS1_3_VERSION
    {TLS1_3_VERSION, SSL_OP_NO_TLSv1_3},
#endif /* TLS1_3_VERSION */
    {0, 0}
};

#define NUMBER_SSL_VERSIONS (sizeof(ssl_disable)/sizeof(ssl_disable[0]) - 1)

/* returns the mask to disable a specific version.
 * If version not found, returns 0.
 * 
 * Arguments: version, and direction.
 * If direction is -1, returns mask to disable versions less than given version.
 * If direction is +1, returns mask to disable versions bigger than given version.
 */
int ssl_disable_mask(int ssl_version, int direction)
{
  int rv = 0;
  int i;
  for(i = 0; ssl_disable[i].version != 0 
		&& ssl_disable[i].version != ssl_version; i++);
  if(i == 0 
     || i == NUMBER_SSL_VERSIONS - 1 
     || ssl_disable[i].version == 0) 
    return rv;
  i += direction; 	/* move in the direction */
  for(; i >= 0 && i <= NUMBER_SSL_VERSIONS - 1; i += direction)
     rv |= ssl_disable[i].disable_code;
  return rv;
}


/* ssl_connect_mthd: returns a context pointer to the connection to
 * a ssl server
 */
const SSL_METHOD *ssl_connect_mthd(int flag, int *minv, int *maxv)
{
  int client_request;
  client_request = (flag & NET_TRYTLS1) ? TLS1_VERSION
		 : (flag & NET_TRYTLS1_1) ? TLS1_1_VERSION
		 : (flag & NET_TRYTLS1_2) ? TLS1_2_VERSION
#ifdef TLS1_3_VERSION
		 : (flag & NET_TRYTLS1_3) ? TLS1_3_VERSION
#else
		 : (flag & NET_TRYTLS1_3) ? -2
#endif
		 : 0;

  *minv = *(int *) mail_parameters(NULL, GET_ENCRYPTION_RANGE_MIN, NULL);
  *maxv = *(int *) mail_parameters(NULL, GET_ENCRYPTION_RANGE_MAX, NULL);

  /* 
   * if no special request, negotiate the maximum the client is configured
   * to negotiate
   */
  if(client_request == 0)
    client_request = *maxv;

  if(client_request < *minv || client_request > *maxv)
    return NIL;		/* out of range? bail out */

  /* Some Linux distributors seem to believe that it is ok to disable some of
   * these methods for their users, so we have to test that every requested
   * method has actually been compiled in into their openssl/libressl library.
   * Oh well...
   */
#ifndef OPENSSL_1_1_0
  if(client_request == SSL3_VERSION)
#ifndef OPENSSL_NO_SSL3_METHOD
     return SSLv3_client_method();
#else
     return NIL;
#endif /* OPENSSL_NO_SSL3_METHOD */
  else if(client_request == TLS1_VERSION)
#ifndef OPENSSL_NO_TLS1_METHOD
     return TLSv1_client_method();
#else
     return NIL;
#endif /* OPENSSL_NO_TLS1_METHOD */
  else if(client_request == TLS1_1_VERSION)
#ifndef OPENSSL_NO_TLS1_1_METHOD
     return TLSv1_1_client_method();
#else
     return NIL;
#endif /* OPENSSL_NO_TLS1_1_METHOD */
  else if(client_request == TLS1_2_VERSION)
#ifndef OPENSSL_NO_TLS1_2_METHOD
     return TLSv1_2_client_method();
#else
     return NIL;
#endif /* OPENSSL_NO_TLS1_2_METHOD */
#ifdef TLS1_3_VERSION	/* this is only reachable if TLS1_3 support exists */
  else if(client_request == TLS1_3_VERSION)
#ifndef OPENSSL_NO_TLS1_3_METHOD
     return TLS_client_method();
#else
     return NIL;
#endif /* #ifndef OPENSSL_NO_TLS1_2_METHOD */
#endif /* TLS1_3_VERSION */
#endif /* ifndef OPENSSL_1_1_0 */

  return SSLv23_client_method();
}

/* Start SSL/TLS negotiations
 * Accepts: open TCP stream of session
 *	    user's host name
 *	    flags
 * Returns: SSL stream if success else NIL
 */

static SSLSTREAM *ssl_start (TCPSTREAM *tstream,char *host,unsigned long flags)
{
  char *reason,tmp[MAILTMPLEN];
  sslfailure_t sf = (sslfailure_t) mail_parameters (NIL,GET_SSLFAILURE,NIL);
  blocknotify_t bn = (blocknotify_t) mail_parameters (NIL,GET_BLOCKNOTIFY,NIL);
  void *data = (*bn) (BLOCK_SENSITIVE,NIL);
  SSLSTREAM *stream = (SSLSTREAM *) memset (fs_get (sizeof (SSLSTREAM)),0,
					    sizeof (SSLSTREAM));
  stream->tcpstream = tstream;	/* bind TCP stream */
				/* do the work */
  reason = ssl_start_work (stream,host,flags);
  (*bn) (BLOCK_NONSENSITIVE,data);
  if (reason) {			/* failed? */
    ssl_close (stream);		/* failed to do SSL */
    stream = NIL;		/* no stream returned */
    switch (*reason) {		/* analyze reason */
    case '*':			/* certificate failure */
      ++reason;			/* skip over certificate failure indication */
				/* pass to error callback */
      if (sf) (*sf) (host,reason,flags);
      else {			/* no error callback, build error message */
	sprintf (tmp,"Certificate failure for %.80s: %.512s",host,reason);
	mm_log (tmp,ERROR);
      }
    case '\0':			/* user answered no to certificate callback */
      if (flags & NET_TRYSSL)	/* return dummy stream to stop tryssl */
	stream = (SSLSTREAM *) memset (fs_get (sizeof (SSLSTREAM)),0,
				       sizeof (SSLSTREAM));
      break;
    default:			/* non-certificate failure */
      if (flags & NET_TRYSSL);	/* no error output if tryssl */
				/* pass to error callback */
      else if (sf) (*sf) (host,reason,flags);
      else {			/* no error callback, build error message */
	sprintf (tmp,"TLS/SSL failure for %.80s: %.512s",host,reason);
	mm_log (tmp,ERROR);
      }
      break;
    }
  }
  return stream;
}

/* Start SSL/TLS negotiations worker routine
 * Accepts: SSL stream
 *	    user's host name
 *	    flags
 * Returns: NIL if success, else error reason
 */

				/* evil but I had no choice */
static char *ssl_last_error = NIL;
static char *ssl_last_host = NIL;

static char *ssl_start_work (SSLSTREAM *stream,char *host,unsigned long flags)
{
  BIO *bio;
  X509 *cert;
  unsigned long sl,tl;
  int minv, maxv;
  int masklow, maskhigh;
  char *s,*t,*err,tmp[MAILTMPLEN], buf[256];
  char *CAfile, *CApath;
  sslcertificatequery_t scq =
    (sslcertificatequery_t) mail_parameters (NIL,GET_SSLCERTIFICATEQUERY,NIL);
  sslclientcert_t scc =
    (sslclientcert_t) mail_parameters (NIL,GET_SSLCLIENTCERT,NIL);
  sslclientkey_t sck =
    (sslclientkey_t) mail_parameters (NIL,GET_SSLCLIENTKEY,NIL);
  if (ssl_last_error) fs_give ((void **) &ssl_last_error);
  ssl_last_host = host;
  if (!(stream->context = SSL_CTX_new (ssl_connect_mthd(flags, &minv, &maxv))))
    return "SSL context failed";
  SSL_CTX_set_options (stream->context,0);
  masklow = ssl_disable_mask(minv, -1);
  maskhigh = ssl_disable_mask(maxv, 1);
  SSL_CTX_set_options(stream->context, masklow|maskhigh);
				/* disable certificate validation? */
  if (flags & NET_NOVALIDATECERT)
    SSL_CTX_set_verify (stream->context,SSL_VERIFY_NONE,NIL);
  else SSL_CTX_set_verify (stream->context,SSL_VERIFY_PEER,ssl_open_verify);
				/* if a non-standard path desired */
  CAfile = (char *) mail_parameters (NIL,GET_SSLCAFILE,NIL);
  CApath = (char *) mail_parameters (NIL,GET_SSLCAPATH,NIL);
  if (CAfile != NIL || CApath != NIL)
    SSL_CTX_load_verify_locations (stream->context, CAfile, CApath);
  else				/* set default paths to CAs... */
  SSL_CTX_set_default_verify_paths (stream->context);
				/* Load app certificates */
  CAfile = (char *) mail_parameters (NIL,GET_SSLAPPCAFILE,NIL);
  CApath = (char *) mail_parameters (NIL,GET_SSLAPPCAPATH,NIL);
  if (CAfile != NIL || CApath != NIL)
    SSL_CTX_load_verify_locations (stream->context, CAfile, CApath);
				/* want to send client certificate? */
  if (scc && (s = (*scc) ()) && (sl = strlen (s))) {
    if ((cert = PEM_read_bio_X509 (bio = BIO_new_mem_buf (s,sl),NIL,NIL,NIL)) != NULL) {
      SSL_CTX_use_certificate (stream->context,cert);
      X509_free (cert);
    }
    BIO_free (bio);
    if (!cert) return "SSL client certificate failed";
				/* want to supply private key? */
    if ((t = (sck ? (*sck) () : s)) && (tl = strlen (t))) {
      EVP_PKEY *key;
      if ((key = PEM_read_bio_PrivateKey (bio = BIO_new_mem_buf (t,tl),
					 NIL,NIL,"")) != NULL) {
	SSL_CTX_use_PrivateKey (stream->context,key);
	EVP_PKEY_free (key);
      }
      BIO_free (bio);
      memset (t,0,tl);		/* erase key */
    }
    if (s != t) memset (s,0,sl);/* erase certificate if different from key */
  }

				/* create connection */
  if (!(stream->con = (SSL *) SSL_new (stream->context)))
    return "SSL connection failed";
  if (host && !SSL_set_tlsext_host_name(stream->con, host)){
    return "Server Name Identification (SNI) failed";
  }
  bio = BIO_new_socket (stream->tcpstream->tcpsi,BIO_NOCLOSE);
  SSL_set_bio (stream->con,bio,bio);
  SSL_set_connect_state (stream->con);
  if (SSL_in_init (stream->con)) SSL_total_renegotiations (stream->con);
				/* now negotiate SSL */
  if (SSL_write (stream->con,"",0) < 0)
    return ssl_last_error ? ssl_last_error : "SSL negotiation failed";
				/* need to validate host names? */
  if (!(flags & NET_NOVALIDATECERT) &&
      (err = ssl_validate_cert (cert = SSL_get_peer_certificate (stream->con),
				host))) {
				/* application callback */
    X509_NAME_oneline (X509_get_subject_name(cert), buf, sizeof(buf));
    if (scq) return (*scq) (err,host,cert ? buf : "???") ? NIL : "";
				/* error message to return via mm_log() */
    sprintf (tmp,"*%.128s: %.255s",err,cert ? buf : "???");
    return ssl_last_error = cpystr (tmp);
  }
  return NIL;
}

/* SSL certificate verification callback
 * Accepts: error flag
 *	    X509 context
 * Returns: error flag
 */

static int ssl_open_verify (int ok,X509_STORE_CTX *ctx)
{
  char *err,cert[256],tmp[MAILTMPLEN];
  sslcertificatequery_t scq =
    (sslcertificatequery_t) mail_parameters (NIL,GET_SSLCERTIFICATEQUERY,NIL);
  if (!ok) {			/* in case failure */
    err = (char *) X509_verify_cert_error_string
      (X509_STORE_CTX_get_error (ctx));
    X509_NAME_oneline (X509_get_subject_name
		       (X509_STORE_CTX_get_current_cert (ctx)),cert,255);
    if (!scq) {			/* mm_log() error message if no callback */
      sprintf (tmp,"*%.128s: %.255s",err,cert);
      ssl_last_error = cpystr (tmp);
    }
				/* ignore error if application says to */
    else if ((*scq) (err,ssl_last_host,cert)) ok = T;
				/* application wants punt */
    else ssl_last_error = cpystr ("");
  }
  return ok;
}


/* SSL validate certificate
 * Accepts: certificate
 *	    host to validate against
 * Returns: NIL if validated, else string of error message
 */

static char *ssl_validate_cert (X509 *cert,char *host)
{
  int i,j,n, m = 0;
  char *s=NULL,*t,*ret = NIL;
  void *ext;
  GENERAL_NAME *name;
  X509_NAME *cname;
  X509_NAME_ENTRY *e;
  char    buf[256];
				/* make sure have a certificate */
  if (!cert) return "No certificate from server";
				/* Method 1: locate CN */
#ifndef OPENSSL_1_1_0
  if (cert->name == NIL)
     ret = "No name in certificate";
  else if ((s = strstr (cert->name,"/CN=")) != NIL) {
     m++; /* count that we tried this method */
     if (t = strchr (s += 4,'/')) *t = '\0';
				/* host name matches pattern? */
     ret = ssl_compare_hostnames (host,s) ? NIL :
      "Server name does not match certificate";
     if (t) *t = '/';		/* restore smashed delimiter */
				/* if mismatch, see if in extensions */
     if (ret && (ext = X509_get_ext_d2i (cert,NID_subject_alt_name,NIL,NIL)) &&
	(n = sk_GENERAL_NAME_num (ext)))
       /* older versions of OpenSSL use "ia5" instead of dNSName */
       for (i = 0; ret && (i < n); i++)
	 if ((name = sk_GENERAL_NAME_value (ext,i)) &&
	    (name->type = GEN_DNS) && (s = name->d.ia5->data) &&
	    ssl_compare_hostnames (host,s)) ret = NIL;
  }
#endif /* OPENSSL_1_1_0 */
				/* Method 2, use cname */
  if(m == 0 || ret != NIL){
     cname = X509_get_subject_name(cert);
     for(j = 0, ret = NIL; j < X509_NAME_entry_count(cname) && ret == NIL; j++){
        if((e = X509_NAME_get_entry(cname, j)) != NULL){
           X509_NAME_get_text_by_OBJ(cname, X509_NAME_ENTRY_get_object(e), buf, sizeof(buf));
           s = (char *) buf;
        }
        else s = NIL;
        if (s != NIL) {
				/* host name matches pattern? */
	   ret = ssl_compare_hostnames (host,s) ? NIL :
		 "Server name does not match certificate";
				/* if mismatch, see if in extensions */
	   if (ret && (ext = X509_get_ext_d2i (cert,NID_subject_alt_name,NIL,NIL)) &&
		(n = sk_GENERAL_NAME_num (ext)))
	           /* older versions of OpenSSL use "ia5" instead of dNSName */
	      for (i = 0; ret && (i < n); i++)
		  if ((name = sk_GENERAL_NAME_value (ext,i)) &&
		     (name->type = GEN_DNS) && (s = name->d.ia5->data) &&
		     ssl_compare_hostnames (host,s)) ret = NIL;
        }
     }
  }

  if (ret == NIL
#ifndef OPENSSL_1_1_0
       && !cert->name
#endif /* OPENSSL_1_1_0 */
       && !X509_get_subject_name(cert))
	ret = "No name in certificate";

  if (ret == NIL && s == NIL) 
	ret = "Unable to locate common name in certificate";

  return ret;
}

/* Case-independent wildcard pattern match
 * Accepts: base string
 *	    pattern string
 * Returns: T if pattern matches base, else NIL
 */

static long ssl_compare_hostnames (unsigned char *s,unsigned char *pat)
{
  long ret = NIL;
  switch (*pat) {
  case '*':			/* wildcard */
    if (pat[1]) {		/* there must be a pattern suffix */
				/* there is, scan base against it */
      do if (ssl_compare_hostnames (s,pat+1)) ret = LONGT;
      while (!ret && (*s != '.') && *s++);
    }
    break;
  case '\0':			/* end of pattern */
    if (!*s) ret = LONGT;	/* success if base is also at end */
    break;
  default:			/* non-wildcard, recurse if match */
    if (!compare_uchar (*pat,*s)) ret = ssl_compare_hostnames (s+1,pat+1);
    break;
  }
  return ret;
}

/* SSL receive line
 * Accepts: SSL stream
 * Returns: text line string or NIL if failure
 */

char *ssl_getline (SSLSTREAM *stream)
{
  unsigned long n,contd;
  char *ret = ssl_getline_work (stream,&n,&contd);
  if (ret && contd) {		/* got a line needing continuation? */
    STRINGLIST *stl = mail_newstringlist ();
    STRINGLIST *stc = stl;
    do {			/* collect additional lines */
      stc->text.data = (unsigned char *) ret;
      stc->text.size = n;
      stc = stc->next = mail_newstringlist ();
      ret = ssl_getline_work (stream,&n,&contd);
    } while (ret && contd);
    if (ret) {			/* stash final part of line on list */
      stc->text.data = (unsigned char *) ret;
      stc->text.size = n;
				/* determine how large a buffer we need */
      for (n = 0, stc = stl; stc; stc = stc->next) n += stc->text.size;
      ret = fs_get (n + 1);	/* copy parts into buffer */
      for (n = 0, stc = stl; stc; n += stc->text.size, stc = stc->next)
	memcpy (ret + n,stc->text.data,stc->text.size);
      ret[n] = '\0';
    }
    mail_free_stringlist (&stl);/* either way, done with list */
  }
  return ret;
}

char *ssl_getsize (SSLSTREAM *stream, unsigned long size)
{
  char *ret = NIL;
  unsigned long got = 0L, need = size, n;
  
  do {
     if(!ssl_getdata (stream)) return ret;      /* return what we have */
     n = stream->ictr < need ? stream->ictr : need;
     fs_resize((void **) &ret, (got + n + 1)*sizeof(char));
     memcpy(ret + got, stream->iptr, n);
     ret[got+n] = '\0';
     got  += n;   
     need -= n;
     stream->iptr += n;
     stream->ictr -= n;
  } while (need > 0);

  return ret;
}
/* SSL receive line or partial line
 * Accepts: SSL stream
 *	    pointer to return size
 *	    pointer to return continuation flag
 * Returns: text line string, size and continuation flag, or NIL if failure
 */

static char *ssl_getline_work (SSLSTREAM *stream,unsigned long *size,
			       long *contd)
{
  unsigned long n;
  char *s,*ret,c,d;
  *contd = NIL;			/* assume no continuation */
				/* make sure have data */
  if (!ssl_getdata (stream)) return NIL;
  for (s = stream->iptr, n = 0, c = '\0'; stream->ictr--; n++, c = d) {
    d = *stream->iptr++;	/* slurp another character */
    if ((c == '\015') && (d == '\012')) {
      ret = (char *) fs_get (n--);
      memcpy (ret,s,*size = n);	/* copy into a free storage string */
      ret[n] = '\0';		/* tie off string with null */
      return ret;
    }
  }
				/* copy partial string from buffer */
  memcpy ((ret = (char *) fs_get (n)),s,*size = n);
				/* get more data from the net */
  if (!ssl_getdata (stream)) fs_give ((void **) &ret);
				/* special case of newline broken by buffer */
  else if ((c == '\015') && (*stream->iptr == '\012')) {
    stream->iptr++;		/* eat the line feed */
    stream->ictr--;
    ret[*size = --n] = '\0';	/* tie off string with null */
  }
  else *contd = LONGT;		/* continuation needed */
  return ret;
}

/* SSL receive buffer
 * Accepts: SSL stream
 *	    size in bytes
 *	    buffer to read into
 * Returns: T if success, NIL otherwise
 */

long ssl_getbuffer (SSLSTREAM *stream,unsigned long size,char *buffer)
{
  unsigned long n;
  while (size > 0) {		/* until request satisfied */
    if (!ssl_getdata (stream)) return NIL;
    n = min (size,stream->ictr);/* number of bytes to transfer */
				/* do the copy */
    memcpy (buffer,stream->iptr,n);
    buffer += n;		/* update pointer */
    stream->iptr += n;
    size -= n;			/* update # of bytes to do */
    stream->ictr -= n;
  }
  buffer[0] = '\0';		/* tie off string */
  return T;
}

/* SSL receive data
 * Accepts: TCP/IP stream
 * Returns: T if success, NIL otherwise
 */

long ssl_getdata (SSLSTREAM *stream)
{
  int i,sock;
  fd_set fds,efds;
  struct timeval tmo;
  tcptimeout_t tmoh = (tcptimeout_t) mail_parameters (NIL,GET_TIMEOUT,NIL);
  long ttmo_read = (long) mail_parameters (NIL,GET_READTIMEOUT,NIL);
  time_t t = time (0);
  blocknotify_t bn = (blocknotify_t) mail_parameters (NIL,GET_BLOCKNOTIFY,NIL);
  if (!stream->con || ((sock = SSL_get_fd (stream->con)) < 0)) return NIL;
				/* tcp_unix should have prevented this */
  if (sock >= FD_SETSIZE) fatal ("unselectable socket in ssl_getdata()");
  (*bn) (BLOCK_TCPREAD,NIL);
  while (stream->ictr < 1) {	/* if nothing in the buffer */
    time_t tl = time (0);	/* start of request */
    time_t now = tl;
    int ti = ttmo_read ? now + ttmo_read : 0;
    if (SSL_pending (stream->con)) i = 1;
    else {
      if (tcpdebug) mm_log ("Reading SSL data",TCPDEBUG);
      tmo.tv_usec = 0;
      FD_ZERO (&fds);		/* initialize selection vector */
      FD_ZERO (&efds);		/* handle errors too */
      FD_SET (sock,&fds);	/* set bit in selection vector */
      FD_SET (sock,&efds);	/* set bit in error selection vector */
      errno = NIL;		/* block and read */
      do {			/* block under timeout */
	tmo.tv_sec = ti ? ti - now : 0;
	i = select (sock+1,&fds,0,&efds,ti ? &tmo : 0);
	now = time (0);		/* fake timeout if interrupt & time expired */
	if ((i < 0) && (errno == EINTR) && ti && (ti <= now)) i = 0;
      } while ((i < 0) && (errno == EINTR));
    }
    if (i) {			/* non-timeout result from select? */
      errno = 0;		/* just in case */
      if (i > 0)		/* read what we can */
	while (((i = SSL_read (stream->con,stream->ibuf,SSLBUFLEN)) < 0) &&
	       ((errno == EINTR) ||
		(SSL_get_error (stream->con,i) == SSL_ERROR_WANT_READ)));
      if (i <= 0) {		/* error seen? */
	if (tcpdebug) {
	  char *s,tmp[MAILTMPLEN];
	  if (i) sprintf (s = tmp,"SSL data read I/O error %d SSL error %d",
			  errno,SSL_get_error (stream->con,i));
	  else s = "SSL data read end of file";
	  mm_log (s,TCPDEBUG);
	}
	return ssl_abort (stream);
      }
      stream->iptr = stream->ibuf;/* point at TCP buffer */
      stream->ictr = i;		/* set new byte count */
      if (tcpdebug) mm_log ("Successfully read SSL data",TCPDEBUG);
    }
				/* timeout, punt unless told not to */
    else if (!tmoh || !(*tmoh) (now - t,now - tl, stream->tcpstream->host)) {
      if (tcpdebug) mm_log ("SSL data read timeout",TCPDEBUG);
      return ssl_abort (stream);
    }
  }
  (*bn) (BLOCK_NONE,NIL);
  return T;
}

/* SSL send string as record
 * Accepts: SSL stream
 *	    string pointer
 * Returns: T if success else NIL
 */

long ssl_soutr (SSLSTREAM *stream,char *string)
{
  return ssl_sout (stream,string,(unsigned long) strlen (string));
}


/* SSL send string
 * Accepts: SSL stream
 *	    string pointer
 *	    byte count
 * Returns: T if success else NIL
 */

long ssl_sout (SSLSTREAM *stream,char *string,unsigned long size)
{
  long i;
  blocknotify_t bn = (blocknotify_t) mail_parameters (NIL,GET_BLOCKNOTIFY,NIL);
  if (!stream->con) return NIL;
  (*bn) (BLOCK_TCPWRITE,NIL);
  if (tcpdebug) mm_log ("Writing to SSL",TCPDEBUG);
				/* until request satisfied */
  for (i = 0; size > 0; string += i,size -= i)
				/* write as much as we can */
    if ((i = SSL_write (stream->con,string,(int) min (SSLBUFLEN,size))) < 0) {
      if (tcpdebug) {
	char tmp[MAILTMPLEN];
	sprintf (tmp,"SSL data write I/O error %d SSL error %d",
		 errno,SSL_get_error (stream->con,i));
	mm_log (tmp,TCPDEBUG);
      }
      return ssl_abort (stream);/* write failed */
    }
  if (tcpdebug) mm_log ("successfully wrote to TCP",TCPDEBUG);
  (*bn) (BLOCK_NONE,NIL);
  return LONGT;			/* all done */
}

/* SSL close
 * Accepts: SSL stream
 */

void ssl_close (SSLSTREAM *stream)
{
  ssl_abort (stream);		/* nuke the stream */
  fs_give ((void **) &stream);	/* flush the stream */
}


/* SSL abort stream
 * Accepts: SSL stream
 * Returns: NIL always
 */

static long ssl_abort (SSLSTREAM *stream)
{
  blocknotify_t bn = (blocknotify_t) mail_parameters (NIL,GET_BLOCKNOTIFY,NIL);
  if (stream->con) {		/* close SSL connection */
    SSL_shutdown (stream->con);
    SSL_free (stream->con);
    stream->con = NIL;
  }
  if (stream->context) {	/* clean up context */
    SSL_CTX_free (stream->context);
    stream->context = NIL;
  }
  if (stream->tcpstream) {	/* close TCP stream */
    tcp_close (stream->tcpstream);
    stream->tcpstream = NIL;
  }
  (*bn) (BLOCK_NONE,NIL);
  return NIL;
}

/* SSL get host name
 * Accepts: SSL stream
 * Returns: host name for this stream
 */

char *ssl_host (SSLSTREAM *stream)
{
  return stream ? tcp_host (stream->tcpstream) : "UNKNOWN";
}


/* SSL get remote host name
 * Accepts: SSL stream
 * Returns: host name for this stream
 */

char *ssl_remotehost (SSLSTREAM *stream)
{
  return tcp_remotehost (stream->tcpstream);
}


/* SSL return port for this stream
 * Accepts: SSL stream
 * Returns: port number for this stream
 */

unsigned long ssl_port (SSLSTREAM *stream)
{
  return tcp_port (stream->tcpstream);
}


/* SSL get local host name
 * Accepts: SSL stream
 * Returns: local host name
 */

char *ssl_localhost (SSLSTREAM *stream)
{
  return tcp_localhost (stream->tcpstream);
}

/* Start TLS
 * Accepts: /etc/services service name
 * Returns: cpystr'd error string if TLS failed, else NIL for success
 */

char *ssl_start_tls (char *server)
{
  char tmp[MAILTMPLEN];
  struct stat sbuf;
  if (sslstdio) return cpystr ("Already in an SSL session");
  if (start_tls) return cpystr ("TLS already started");
  if (server) {			/* build specific certificate/key file name */
    sprintf (tmp,"%s/%s-%s.pem",SSL_CERT_DIRECTORY,server,tcp_serveraddr ());
    if (stat (tmp,&sbuf)) {	/* use non-specific name if no specific file */
      sprintf (tmp,"%s/%s.pem",SSL_CERT_DIRECTORY,server);
      if (stat (tmp,&sbuf)) return cpystr ("Server certificate not installed");
    }
    start_tls = server;		/* switch to STARTTLS mode */
  }
  return NIL;
}

/* Init server for SSL
 * Accepts: server name
 */

void ssl_server_init (char *server)
{
  char cert[MAILTMPLEN],key[MAILTMPLEN];
  unsigned long i;
  struct stat sbuf;
  SSLSTREAM *stream = (SSLSTREAM *) memset (fs_get (sizeof (SSLSTREAM)),0,
					    sizeof (SSLSTREAM));
  ssl_onceonlyinit ();		/* make sure algorithms added */
#ifdef OPENSSL_1_1_0
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS|OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#else
  ERR_load_crypto_strings ();
  SSL_load_error_strings ();
#endif /* OPENSSL_1_1_0 */
				/* build specific certificate/key file names */
  sprintf (cert,"%s/%s-%s.pem",SSL_CERT_DIRECTORY,server,tcp_serveraddr ());
  sprintf (key,"%s/%s-%s.pem",SSL_KEY_DIRECTORY,server,tcp_serveraddr ());
				/* use non-specific name if no specific cert */
  if (stat (cert,&sbuf)) sprintf (cert,"%s/%s.pem",SSL_CERT_DIRECTORY,server);
  if (stat (key,&sbuf)) {	/* use non-specific name if no specific key */
    sprintf (key,"%s/%s.pem",SSL_KEY_DIRECTORY,server);
				/* use cert file as fallback for key */
    if (stat (key,&sbuf)) strcpy (key,cert);
  }
				/* create context */
#ifdef OPENSSL_1_1_0
  if (!(stream->context = SSL_CTX_new (start_tls ?
				       TLS_server_method () :
				       SSLv23_server_method ())))
#else
  if (!(stream->context = SSL_CTX_new (start_tls ?
				       TLSv1_server_method () :
				       SSLv23_server_method ())))
#endif /* OPENSSL_1_1_0 */
    syslog (LOG_ALERT,"Unable to create SSL context, host=%.80s",
	    tcp_clienthost ());
  else {			/* set context options */
    SSL_CTX_set_options (stream->context,SSL_OP_ALL);
				/* set cipher list */
    if (!SSL_CTX_set_cipher_list (stream->context,SSLCIPHERLIST))
      syslog (LOG_ALERT,"Unable to set cipher list %.80s, host=%.80s",
	      SSLCIPHERLIST,tcp_clienthost ());
				/* load certificate */
    else if (!SSL_CTX_use_certificate_chain_file (stream->context,cert))
      syslog (LOG_ALERT,"Unable to load certificate from %.80s, host=%.80s",
	      cert,tcp_clienthost ());
				/* load key */
    else if (!(SSL_CTX_use_RSAPrivateKey_file (stream->context,key,
					       SSL_FILETYPE_PEM)))
      syslog (LOG_ALERT,"Unable to load private key from %.80s, host=%.80s",
	      key,tcp_clienthost ());

    else {			/* generate key if needed */
#ifdef OPENSSL_1_1_0
      if (0)
	ssl_genkey(stream->context, 0, 0);
#else
      if (SSL_CTX_need_tmp_RSA (stream->context))
	SSL_CTX_set_tmp_rsa_callback (stream->context,ssl_genkey);
#endif /* OPENSSL_1_1_0 */
				/* create new SSL connection */
      if (!(stream->con = SSL_new (stream->context)))
	syslog (LOG_ALERT,"Unable to create SSL connection, host=%.80s",
		tcp_clienthost ());
      else {			/* set file descriptor */
	SSL_set_fd (stream->con,0);
				/* all OK if accepted */
	if (SSL_accept (stream->con) < 0)
	  syslog (LOG_INFO,"Unable to accept SSL connection, host=%.80s",
		  tcp_clienthost ());
	else {			/* server set up */
	  sslstdio = (SSLSTDIOSTREAM *)
	    memset (fs_get (sizeof(SSLSTDIOSTREAM)),0,sizeof (SSLSTDIOSTREAM));
	  sslstdio->sslstream = stream;
				/* available space in output buffer */
	  sslstdio->octr = SSLBUFLEN;
				/* current output buffer pointer */
	  sslstdio->optr = sslstdio->obuf;
				/* allow plaintext if disable value was 2 */
	  if ((long) mail_parameters (NIL,GET_DISABLEPLAINTEXT,NIL) > 1)
	    mail_parameters (NIL,SET_DISABLEPLAINTEXT,NIL);
				/* unhide PLAIN SASL authenticator */
	  mail_parameters (NIL,UNHIDE_AUTHENTICATOR,"PLAIN");
	  mail_parameters (NIL,UNHIDE_AUTHENTICATOR,"LOGIN");
	  return;
	}
      }
    }  
  }
  while ((i = ERR_get_error ())	!= 0L) /* SSL failure */
    syslog (LOG_ERR,"SSL error status: %.80s",ERR_error_string (i,NIL));
  ssl_close (stream);		/* punt stream */
  exit (1);			/* punt this program too */
}

/* Generate one-time key for server
 * Accepts: SSL connection
 *	    export flag
 *	    keylength
 * Returns: generated key, always
 */

static RSA *ssl_genkey (SSL_CTX_TYPE *con,int export,int keylength)
{
  unsigned long i;
  static RSA *key = NIL;
  if (!key) {			/* if don't have a key already */
				/* generate key */
#ifdef OPENSSL_1_1_0
    BIGNUM *e = BN_new();
    if (!RSA_generate_key_ex (key, export ? keylength : 1024, e,NIL)) {
#else
    if (!(key = RSA_generate_key (export ? keylength : 1024,RSA_F4,NIL,NIL))) {
#endif /* OPENSSL_1_1_0 */
      syslog (LOG_ALERT,"Unable to generate temp key, host=%.80s",
	      tcp_clienthost ());
      while ((i = ERR_get_error ()) != 0L)
	syslog (LOG_ALERT,"SSL error status: %s",ERR_error_string (i,NIL));
      exit (1);
    }
#ifdef OPENSSL_1_1_0
    BN_free(e);
    e = NULL;
#endif /* OPENSSL_1_1_0 */
  }
  return key;
}

/* Wait for stdin input
 * Accepts: timeout in seconds
 * Returns: T if have input on stdin, else NIL
 */

long ssl_server_input_wait (long seconds)
{
  int i,sock;
  fd_set fds,efd;
  struct timeval tmo;
  SSLSTREAM *stream;
  if (!sslstdio) return server_input_wait (seconds);
				/* input available in buffer */
  if (((stream = sslstdio->sslstream)->ictr > 0) ||
      !stream->con || ((sock = SSL_get_fd (stream->con)) < 0)) return LONGT;
				/* sock ought to be 0 always */
  if (sock >= FD_SETSIZE) fatal ("unselectable socket in ssl_getdata()");
				/* input available from SSL */
  if (SSL_pending (stream->con) &&
      ((i = SSL_read (stream->con,stream->ibuf,SSLBUFLEN)) > 0)) {
    stream->iptr = stream->ibuf;/* point at TCP buffer */
    stream->ictr = i;		/* set new byte count */
    return LONGT;
  }
  FD_ZERO (&fds);		/* initialize selection vector */
  FD_ZERO (&efd);		/* initialize selection vector */
  FD_SET (sock,&fds);		/* set bit in selection vector */
  FD_SET (sock,&efd);		/* set bit in selection vector */
  tmo.tv_sec = seconds; tmo.tv_usec = 0;
				/* see if input available from the socket */
  return select (sock+1,&fds,0,&efd,&tmo) ? LONGT : NIL;
}

#include "sslstdio.c"
