/*
 * Copyright 2018-2020 Eduardo Chappa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include "c-client.h"
#include "flstring.h"
#include "netmsg.h"
#include "http.h"

//char t[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~";
static char http_notok[] = "\1\2\3\4\5\6\7\10\11\12\13\14\15\16\17\20\21\22\23\24\25\26\27\30\31\32\33\34\35\36\37\40\42\50\51\54\57\72\73\74\75\76\77\100\133\134\135\173\175\177\200\201\202\203\204\205\206\207\210\211\212\213\214\215\216\217\220\221\222\223\224\225\226\227\230\231\232\233\234\235\236\237\240\241\242\243\244\245\246\247\250\251\252\253\254\255\256\257\260\261\262\263\264\265\266\267\270\271\272\273\274\275\276\277\300\301\302\303\304\305\306\307\310\311\312\313\314\315\316\317\320\321\322\323\324\325\326\327\330\331\332\333\334\335\336\337\340\341\342\343\344\345\346\347\350\351\352\353\354\355\356\357\360\361\362\363\364\365\366\367\370\371\372\373\374\375\376\377";
static char http_noparam_val[] = "\1\2\3\4\5\6\7\10\12\13\14\15\16\17\20\21\22\23\24\25\26\27\30\31\32\33\34\35\36\37\42\134\177";

#define HTTPTCPPORT (long) 80	/* assigned TCP contact port */
#define HTTPSSLPORT (long) 443	/* assigned SSL TCP contact port */

typedef struct http_request_s {
  unsigned char *request;
  unsigned char *header;
  unsigned char *body;
} HTTP_REQUEST_S;

#define HTP_NOVAL	0x001	/* the header accepts parameters without value */

#define HTP_UNLIMITED	(-1)	/* parse and infinite list */

#if 0
typedef struct http_val_param_s {
  unsigned char *value;
  PARAMETER *plist;
} HTTP_VAL_PARAM_S;

typedef struct http_param_list_s {
  HTTP_VAL_PARAM_S *vp;
  struct http_param_list_s *next;
} HTTP_PARAM_LIST_S;

typedef struct http_header_value_s {
  unsigned char *data;
  HTTP_PARAM_LIST_S *p;
} HTTP_HEADER_S;

typedef struct http_header_data_s {
  HTTP_HEADER_S *accept,		/* RFC 7231, Section 5.3.2 */
		*accept_charset,	/* RFC 7231, Section 5.3.3 */
		*accept_encoding,	/* RFC 7231, Section 5.3.4 */
		*accept_language,	/* RFC 7231, Section 5.3.5 */
		*accept_ranges,		/* RFC 7233, Section 2.3 */
		*age,			/* RFC 7234, Section 5.1 */
		*allow,			/* RFC 7231, Section 7.4.1 */
		*cache_control,		/* RFC 7234, Section 5.2 */
		*connection,		/* RFC 7230, Section 6.1 */
		*content_encoding,	/* RFC 7231, Section 3.1.2.2 */
		*content_disposition,	/* RFC 6266 */
		*content_language,	/* RFC 7231, Section 3.1.3.2 */
		*content_length,	/* RFC 7230, Section 3.3.2 */
		*content_location,	/* RFC 7231, Section 3.1.4.2 */
		*content_type,		/* RFC 7231, Section 3.1.1.5 */
		*date,			/* RFC 7231, Section 7.1.1.2 */
		*etag,			/* RFC 7232, Section 2.3 */
		*expect,		/* RFC 7231, Section 5.1.1 */
		*expires,		/* RFC 7234, Section 5.3 */
		*from,			/* RFC 7231, Section 5.5.1 */
		*host,			/* RFC 7230, Section 5.4 */
		*last_modified,		/* RFC 7232, Section 2.2 */
		*location,		/* RFC 7231, Section 7.1.2 */
		*max_forwards,		/* RFC 7231, Section 5.1.2  */
		*mime_version,		/* RFC 7231, Appendix A.1 */
		*pragma,		/* RFC 7234, Section 5.4 */
		*proxy_authenticate,	/* RFC 7235, Section 4.3 */
		*referer,		/* RFC 7231, Section 5.5.2 */
		*retry_after,		/* RFC 7231, Section 7.1.3 */
		*server,		/* RFC 7231, Section 7.4.2 */
		*te,			/* RFC 7230, Section 4.3 */
		*trailer,		/* RFC 7230, Section 4.4 */
		*transfer_encoding,	/* RFC 7230, Section 3.3.1 */
		*upgrade,		/* RFC 7230, Section 6.7 */
		*user_agent,		/* RFC 7231, Section 5.5.3 */
		*via,			/* RFC 7230, Section 5.7.1 */
		*vary,			/* RFC 7231, Section 7.1.4 */
		*warning,		/* RFC 7234, Section 5.5 */
		*www_authenticate;	/* RFC 7235, Section 4.1 */
} HTTP_HEADER_DATA_S;
#endif

/* helper functions */
HTTP_STATUS_S *http_status_line_get(unsigned char *);
void http_status_line_free(HTTP_STATUS_S **);
HTTP_REQUEST_S *http_request_get(void);
void http_request_free(HTTP_REQUEST_S **);
unsigned char *http_request_line(unsigned char *, unsigned char *, unsigned char *);
void http_add_header(HTTP_REQUEST_S **, unsigned char *, unsigned char *);
void http_add_body(HTTP_REQUEST_S **, unsigned char *);
void buffer_add(unsigned char **, unsigned char *);
unsigned char *hex_escape_url_part(unsigned char *, unsigned char *);
unsigned char *encode_url_body_part(unsigned char *, unsigned char *);
unsigned char *http_response_from_reply(HTTPSTREAM *);

/* HTTP function prototypes */
int http_valid_net_parse (unsigned char *, NETMBX *);
void *http_parameters (long function,void *value);

long http_send (HTTPSTREAM *, HTTP_REQUEST_S *);
long http_reply (HTTPSTREAM *);
long http_fake (HTTPSTREAM *, unsigned char *);

void http_skipows(unsigned char **);
void http_remove_trailing_ows(unsigned char *);

int valid_dquote_text(unsigned char *);
#define valid_token_name(X)  (strpbrk((X), http_notok) ? 0 : 1)
#define valid_parameter_value(X) \
	((valid_token_name((X)) || valid_dquote_text((X))) ? 1 : 0)

/* HTTP HEADER FUNCTIONS */
void http_add_header_data(HTTPSTREAM *, unsigned char *);
void http_add_data_to_header(HTTP_HEADER_S **, unsigned char *);

HTTP_PARAM_LIST_S *http_parse_token_parameter(unsigned char *, int);
HTTP_PARAM_LIST_S *http_parse_token_list(unsigned char *, int);
PARAMETER *http_parse_parameter(unsigned char *, int);

void http_parse_headers(HTTPSTREAM *);

unsigned char *
http_response_from_reply(HTTPSTREAM *stream)
{
  unsigned char *rv = NULL, *s, *t;

  if(stream == NULL || stream->reply == NULL || stream->header == NULL) 
     return rv;

  if(stream->header->content_length){
     s = strstr(stream->reply, "\r\n\r\n");
     if(s != NULL) rv = s + 4;
  }
  else if (stream->header->transfer_encoding){
     HTTP_PARAM_LIST_S *p = stream->header->transfer_encoding->p;
     for(; p ; p = p->next){
	if(!compare_cstring(p->vp->value, "chunked"))
	   break;
     }
     if(p && p->vp->value){	/* chunked transfer */
        if((s = strstr(stream->reply, "\r\n\r\n")) != NULL
	    && (t = strstr(s + 4, "\r\n")) != NULL)
	rv = t + 2;
     }
  }
  return rv;
}

void
http_parse_headers(HTTPSTREAM *stream)
{
  HTTP_HEADER_DATA_S *hd;
  HTTP_HEADER_S *h;

  if(!stream || !stream->header) return;

  hd = stream->header;

  if(((h = hd->accept)) && h->data){		/* RFC 7231, Section 5.3.2 */
     h->p = http_parse_token_parameter(h->data, HTP_NOVAL);
     fs_give((void **) &h->data);
  }

  if(((h = hd->accept_charset)) && h->data){	/* RFC 7231, Section 5.3.3 */
     h->p = http_parse_token_parameter(h->data, 0);
     fs_give((void **) &h->data);
  }

  if(((h = hd->accept_encoding)) && h->data){	/* RFC 7231, Section 5.3.4 */
     h->p = http_parse_token_parameter(h->data, 0);
     fs_give((void **) &h->data);
  }

  if(((h = hd->accept_language)) && h->data){	/* RFC 7231, Section 5.3.5 */
     h->p = http_parse_token_parameter(h->data, 0);
     fs_give((void **) &h->data);
  }

  if(((h = hd->accept_ranges)) && h->data){	/* RFC 7233, Section 2.3 */
     h->p = http_parse_token_parameter(h->data, 0);
     fs_give((void **) &h->data);
  }

  if(((h = hd->age)) && h->data){		/* RFC 7234, Section 5.1 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->allow)) && h->data){		/* RFC 7231, Section 7.4.1 */
     h->p = http_parse_token_list(h->data, HTP_UNLIMITED);
     fs_give((void **) &h->data);
  }

  if(((h = hd->cache_control)) && h->data){	/* RFC 7234, Section 5.2 */
     h->p = http_parse_token_parameter(h->data, HTP_NOVAL);
     fs_give((void **) &h->data);
  }

  if(((h = hd->connection)) && h->data){	/* RFC 7230, Section 6.1 */
     h->p = http_parse_token_list(h->data, HTP_UNLIMITED);
     fs_give((void **) &h->data);
  }

  if(((h = hd->content_encoding)) && h->data){	/* RFC 7231, Section 3.1.2.2 */
     h->p = http_parse_token_list(h->data, HTP_UNLIMITED);
     fs_give((void **) &h->data);
  }

  if(((h = hd->content_disposition)) && h->data){	/* RFC 6266 */
     h->p = http_parse_token_parameter(h->data, HTP_NOVAL);
     fs_give((void **) &h->data);
  }

  if(((h = hd->content_language)) && h->data){	/* RFC 7231, Section 3.1.3.2 */
     h->p = http_parse_token_list(h->data, HTP_UNLIMITED);
     fs_give((void **) &h->data);
  }

  if(((h = hd->content_length)) && h->data){	/* RFC 7230, Section 3.3.2 */
     h->p = http_parse_token_list(h->data, HTP_UNLIMITED);
     fs_give((void **) &h->data);
  }

  if(((h = hd->content_location)) && h->data){	/* RFC 7231, Section 3.1.4.2 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->content_type)) && h->data){	/* RFC 7231, Section 3.1.1.5 */
     h->p = http_parse_token_parameter(h->data, 0);
     fs_give((void **) &h->data);
  }

  if(((h = hd->date)) && h->data){	/* RFC 7231, Section 7.1.1.2 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->etag)) && h->data){	/* Rewrite this. RFC 7232, Section 2.3 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->expect)) && h->data){	/* Rewrite this. RFC 7231, Section 5.1.1 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->expires)) && h->data){	/* Rewrite this. RFC 7234, Section 5.3 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->from)) && h->data){	/* Rewrite this. RFC 7231, Section 5.5.1 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->host)) && h->data){	/* Rewrite this. RFC 7230, Section 5.4 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->last_modified)) && h->data){	/* Rewrite this. RFC 7232, Section 2.2 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->location)) && h->data){	/* Rewrite this. RFC 7231, Section 7.1.2 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->max_forwards)) && h->data){	/* RFC 7231, Section 5.1.2  */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->mime_version)) && h->data){	/* Rewrite this. RFC 7231, Appendix A.1 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->pragma)) && h->data){		/* RFC 7234, Section 5.4 */
     h->p = http_parse_token_parameter(h->data, HTP_NOVAL);
     fs_give((void **) &h->data);
  }

  if(((h = hd->proxy_authenticate)) && h->data){	/* Rewrite this. RFC 7235, Section 4.3 */
     h->p = http_parse_token_parameter(h->data, 0);
     fs_give((void **) &h->data);
  }

  if(((h = hd->referer)) && h->data){	/* Rewrite this. RFC 7231, Section 5.5.2 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->retry_after)) && h->data){	/* Rewrite this. RFC 7231, Section 7.1.3 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->server)) && h->data){	/* Rewrite this. RFC 7231, Section 7.4.2 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->te)) && h->data){	/* Rewrite this. RFC 7230, Section 4.3 */
     h->p = http_parse_token_parameter(h->data, 0);
     fs_give((void **) &h->data);
  }

  if(((h = hd->trailer)) && h->data){	/* RFC 7230, Section 4.4 */
     h->p = http_parse_token_list(h->data, HTP_UNLIMITED);
     fs_give((void **) &h->data);
  }

  if(((h = hd->transfer_encoding)) && h->data){	/* Rewrite this. RFC 7230, Section 3.3.1 */
     h->p = http_parse_token_parameter(h->data, 0);
     fs_give((void **) &h->data);
  }

  if(((h = hd->upgrade)) && h->data){	/* Rewrite this. RFC 7230, Section 6.7 */
     h->p = http_parse_token_list(h->data, 1);
     fs_give((void **) &h->data);
  }

  if(((h = hd->user_agent)) && h->data){	/* Rewrite this. RFC 7231, Section 5.5.3 */
     h->p = http_parse_token_list(h->data, HTP_UNLIMITED);
     fs_give((void **) &h->data);
  }

  if(((h = hd->via)) && h->data){	/* Rewrite this. RFC 7230, Section 5.7.1 */
     h->p = http_parse_token_list(h->data, HTP_UNLIMITED);
     fs_give((void **) &h->data);
  }

  if(((h = hd->vary)) && h->data){	/* Rewrite this. RFC 7231, Section 7.1.4 */
     h->p = http_parse_token_list(h->data, HTP_UNLIMITED);
     fs_give((void **) &h->data);
  }

  if(((h = hd->warning)) && h->data){	/* Rewrite this. RFC 7234, Section 5.5 */
     h->p = http_parse_token_list(h->data, HTP_UNLIMITED);
     fs_give((void **) &h->data);
  }

  if(((h = hd->www_authenticate)) && h->data){	/* Rewrite this. RFC 7235, Section 4.1 */
     h->p = http_parse_token_parameter(h->data, 0);
     fs_give((void **) &h->data);
  }
}


void
http_add_data_to_header(HTTP_HEADER_S **headerp,  unsigned char *data)
{
  HTTP_HEADER_S *h = *headerp;

  if(!h){
      h = fs_get(sizeof(HTTP_HEADER_S));
      memset((void *)h, 0, sizeof(HTTP_HEADER_S));
  }

  if(h->data) buffer_add(&h->data, ", ");
  buffer_add(&h->data, data);
  *headerp = h;
}

void
http_add_header_data(HTTPSTREAM *stream, unsigned char *hdata)
{
  unsigned char *hname, *h;
  int found = 1;

  if(!stream || !hdata || !*hdata) return;

  if(!stream->header){
     stream->header = fs_get(sizeof(HTTP_HEADER_DATA_S));
     memset((void *) stream->header, 0, sizeof(HTTP_HEADER_DATA_S));
  }


  /* extract header name first */
  if((h = strchr(hdata, ':'))){
    *h = '\0';
    hname = fs_get((h-hdata+2)*sizeof(char));
    strncpy(hname, hdata, h-hdata);
    hname[h-hdata] = '\0';
    if(!valid_token_name(hname))
       return;
    hname[h-hdata] = ':';
    hname[h-hdata+1] = '\0';
    *h++ = ':';
  }
  else return;

  switch(*hname){
     case 'A':
     case 'a':  if(!compare_cstring(hname+1, "ccept:"))  /* RFC 7231, Section 5.3.2 */
		  http_add_data_to_header(&stream->header->accept,  h);
		else if(!compare_cstring(hname+1, "ccept-charset:")) /* RFC 7231, Section 5.3.3 */
		  http_add_data_to_header(&stream->header->accept_charset,  h);
		else if(!compare_cstring(hname+1, "ccept-encoding:")) /* RFC 7231, Section 5.3.4 */
		  http_add_data_to_header(&stream->header->accept_encoding,  h);
		else if(!compare_cstring(hname+1, "ccept-language:")) /* RFC 7231, Section 5.3.5 */
		  http_add_data_to_header(&stream->header->accept_language,  h);
		else if(!compare_cstring(hname+1, "ccept-ranges:")) /* RFC 7233, Section 2.3 */
		  http_add_data_to_header(&stream->header->accept_ranges,  h);
		else if(!compare_cstring(hname+1, "ge:")) /* RFC 7234, Section 5.1 */
		  http_add_data_to_header(&stream->header->age,  h);
		else if(!compare_cstring(hname+1, "llow:")) /* RFC 7231, Section 7.4.1 */
		  http_add_data_to_header(&stream->header->allow,  h);
		else found = 0;
		break;

     case 'C':
     case 'c':  if(!compare_cstring(hname+1, "ache-control:"))	 /* RFC 7234, Section 5.2 */
		  http_add_data_to_header(&stream->header->cache_control,  h);
		else if(!compare_cstring(hname+1, "onnection:")) /* RFC 7230, Section 6.1 */
		  http_add_data_to_header(&stream->header->connection,  h);
		else if(!compare_cstring(hname+1, "ontent-disposition:")) /* RFC 6266 */
		  http_add_data_to_header(&stream->header->content_disposition,  h);
		else if(!compare_cstring(hname+1, "ontent-encoding:")) /* RFC 7231, Section 3.1.2.2 */
		  http_add_data_to_header(&stream->header->content_encoding,  h);
		else if(!compare_cstring(hname+1, "ontent-language:"))	/* RFC 7231, Section 3.1.3.2 */
/* rewrite this */  http_add_data_to_header(&stream->header->content_language,  h);
		else if(!compare_cstring(hname+1, "ontent-length:"))	/* RFC 7230, Section 3.3.2 */
		  http_add_data_to_header(&stream->header->content_length,  h);
		else if(!compare_cstring(hname+1, "ontent-location:"))	/* RFC 7231, Section 3.1.4.2 */
/* rewrite this */  http_add_data_to_header(&stream->header->content_location,  h);
		else if(!compare_cstring(hname+1, "ontent-type:"))	/* RFC 7231, Section 3.1.1.5 */
		  http_add_data_to_header(&stream->header->content_type,  h);
		else found = 0;
		break;

     case 'D':
     case 'd':	if(!compare_cstring(hname+1, "ate:"))	/* RFC 7231, Section 7.1.1.2 */
/* revise this */  http_add_data_to_header(&stream->header->date,  h);
		else found = 0;
		break;

     case 'E':
     case 'e':  if(!compare_cstring(hname+1, "tag:"))	/* RFC 7232, Section 2.3 */
/* rewrite this */  http_add_data_to_header(&stream->header->etag,  h);
		else if(!compare_cstring(hname+1, "xpect:"))	/* RFC 7231, Section 5.1.1 */
/* rewrite this */  http_add_data_to_header(&stream->header->expect,  h);
		else if(!compare_cstring(hname+1, "xpires:"))	/* RFC 7234, Section 5.3 */
/* rewrite this */  http_add_data_to_header(&stream->header->expires,  h);
		else found = 0;
		break;

     case 'F':
     case 'f':	if(!compare_cstring(hname+1, "rom:"))	/* RFC 7231, Section 5.5.1 */
/* rewrite this */  http_add_data_to_header(&stream->header->from,  h);
		else found = 0;
		break;

     case 'H':
     case 'h':	if(!compare_cstring(hname+1, "ost:"))	/* RFC 7230, Section 5.4 */
		  http_add_data_to_header(&stream->header->host,  h);
		else found = 0;
		break;

     case 'L':
     case 'l':	if(!compare_cstring(hname+1, "ast-modified:"))	/* RFC 7232, Section 2.2 */
		  http_add_data_to_header(&stream->header->last_modified,  h);
		else if(!compare_cstring(hname+1, "ocation:"))	/* RFC 7231, Section 7.1.2 */
		  http_add_data_to_header(&stream->header->location,  h);
		else found = 0;
		break;

     case 'M':
     case 'm':	if(!compare_cstring(hname+1, "ax-forwards:"))	/* RFC 7231, Section 5.1.2  */
		  http_add_data_to_header(&stream->header->max_forwards,  h);
		else if(!compare_cstring(hname+1, "ime-version:")) /* RFC 7231, Appendix A.1 */
		  http_add_data_to_header(&stream->header->mime_version,  h);
		else found = 0;
		break;

     case 'P':
     case 'p':	if(!compare_cstring(hname+1, "ragma:")) /* RFC 7234, Section 5.4 */
		  http_add_data_to_header(&stream->header->pragma,  h);
		else if(!compare_cstring(hname+1, "roxy-authenticate:")) /* RFC 7235, Section 4.3 */
		  http_add_data_to_header(&stream->header->proxy_authenticate,  h);
		else found = 0;
		break;

     case 'R':
     case 'r':	if(!compare_cstring(hname+1, "eferer:"))	/* RFC 7231, Section 5.5.2 */
		  http_add_data_to_header(&stream->header->referer,  h);
		else if(!compare_cstring(hname+1, "etry-after:")) /* RFC 7231, Section 7.1.3 */
		  http_add_data_to_header(&stream->header->retry_after,  h);
		else found = 0;
		break;

     case 'S':
     case 's':	if(!compare_cstring(hname+1, "erver:")) /* RFC 7231, Section 7.4.2 */
		  http_add_data_to_header(&stream->header->server,  h);
		else found = 0;
		break;

     case 'T':
     case 't':	if(!compare_cstring(hname+1, "e:"))	/* RFC 7230, Section 4.3 */
		  http_add_data_to_header(&stream->header->te,  h);
		else if(!compare_cstring(hname+1, "railer:")) /* RFC 7230, Section 4.4 */
		  http_add_data_to_header(&stream->header->trailer,  h);
		else if(!compare_cstring(hname+1, "ransfer-encoding:")) /* RFC 7230, Section 3.3.1 */
		  http_add_data_to_header(&stream->header->transfer_encoding,  h);
		else found = 0;
		break;
		break;

     case 'U':
     case 'u':	if(!compare_cstring(hname+1, "pgrade:"))	/* RFC 7230, Section 6.7 */
		  http_add_data_to_header(&stream->header->upgrade,  h);
		else if(!compare_cstring(hname+1, "ser-agent:")) /* RFC 7231, Section 5.5.3 */
		  http_add_data_to_header(&stream->header->user_agent,  h);
		else found = 0;
		break;

     case 'V':
     case 'v':	if(!compare_cstring(hname+1, "ia:"))	/* RFC 7230, Section 5.7.1 */
		  http_add_data_to_header(&stream->header->via,  h);
		else if(!compare_cstring(hname+1, "ary:")) /* RFC 7231, Section 7.1.4 */
		  http_add_data_to_header(&stream->header->vary,  h);
		else found = 0;
		break;

     case 'W':
     case 'w':	if(!compare_cstring(hname+1, "arning:"))	/* RFC 7234, Section 5.5 */
		  http_add_data_to_header(&stream->header->warning,  h);
		else if(!compare_cstring(hname+1, "ww-authenticate:")) /* RFC 7235, Section 4.1 */
		  http_add_data_to_header(&stream->header->www_authenticate,  h);
		else found = 0;
		break;

      default:  break;
  }
}


/* parse a list of tokens. If num is positive, parse at most
 * num members in the list. Set num to HTP_UNLIMITED for a list
 * without bounds
 */
HTTP_PARAM_LIST_S *
http_parse_token_list(unsigned char *h, int num)
{
  unsigned char *s = h, *t, c;
  HTTP_PARAM_LIST_S *rv = NIL;

  if(!s || !*s || num == 0) return NIL;
  http_skipows(&s);
  if(!*s) return NIL;
  for(t = s; *t != '\0' && *t != ','; t++);
  c = *t; *t = '\0';
  http_remove_trailing_ows(s);

  if(!valid_token_name(s))
    return c == ',' ? http_parse_token_list(t+1, num) : NIL;

  if(num > 0) num--;	/* this one counts! */
  rv = fs_get(sizeof(HTTP_PARAM_LIST_S));
  memset((void *) rv, 0, sizeof(HTTP_PARAM_LIST_S));
  rv->vp = fs_get(sizeof(HTTP_VAL_PARAM_S));
  memset((void *) rv->vp, 0, sizeof(HTTP_VAL_PARAM_S));
  rv->vp->value = cpystr(s);
  *t = c;
  if(c == ',')
    rv->next = http_parse_token_list(t+1, num);

  return rv;
}


/* 
 * parse a list of tokens with optional parameters
 * into a HEADER_DATA structure. Do not parse into
 * it anything invalid.
 */
HTTP_PARAM_LIST_S *
http_parse_token_parameter(unsigned char *h, int flag)
{
  unsigned char *s = h, *t, *u, c, d;
  HTTP_PARAM_LIST_S *rv = NIL;

  /* 
   * Step 1: 
   * isolate first list element from list and remove 
   * leading and trailing white space.
   */
  if(!s) return NIL;
  http_skipows(&s);
  if(!*s) return NIL;
  for(t = s; *t != '\0' && *t != ','; t++);
  c = *t; *t = '\0';
  http_remove_trailing_ows(s);

  /* 
   * Step 2:
   * isolate token name from its parameters. Remove
   * any trailing spaces. If not valid token, move
   * to the next entry in the list.
   */
  for(u = s; *u != '\0' && *u != ';'; u++);
  d = *u; *u = '\0';
  http_remove_trailing_ows(s);
  if(!valid_token_name(s))
    return c == ',' ? http_parse_token_parameter(t+1, flag) : NIL;

  /* 
   * Step 3:
   * If we make it this far, create a non-null reply
   * and parse the token and parameters into a
   * HTTP_HEADER_DATA_S structure
   */
  rv = fs_get(sizeof(HTTP_PARAM_LIST_S));
  memset((void *) rv, 0, sizeof(HTTP_PARAM_LIST_S));
  rv->vp = fs_get(sizeof(HTTP_VAL_PARAM_S));
  memset((void *) rv->vp, 0, sizeof(HTTP_VAL_PARAM_S));
  rv->vp->value = cpystr(s);
  if(d == ';')
    rv->vp->plist = http_parse_parameter(u+1, flag);
  *u = d;
  *t = c;
  if(c == ',')
    rv->next = http_parse_token_parameter(t+1, flag);

  return rv;
}

int
valid_dquote_text(unsigned char *s)
{
  unsigned char *t;

  if(!s || *s != '\"') return 0;

  t = strchr(s+1, '\"');
  return (t && !t[1]) ? 1 : 0;
}


void
http_skipows(unsigned char **sp)
{
  unsigned char *s = *sp;
  for(; *s == ' ' || *s == '\t'; s++);
  *sp = s;
}

void
http_remove_trailing_ows(unsigned char *s)
{
  unsigned char *t;
  for(t = s; strlen(t) > 0 ;)
     if(t[strlen(t)-1] == ' ' || t[strlen(t)-1] == '\t')
	t[strlen(t)-1] = '\0';
     else
	break;
}

PARAMETER *
http_parse_parameter(unsigned char *s, int flag)
{
  PARAMETER *p;
  unsigned char *t, *u, c;

  /* Step 1:
   * separate the parameters into a list separated by ";"
   */
  if(!s || !*s) return NIL;
  http_skipows(&s);
  if(!*s) return NIL;
  for(t = s; *t != '\0' && *t != ';'; t++);
  c = *t; *t = '\0';

  /* Now we look for separation of attribute and value */
  u = strchr(s, '=');

  if(u){
    *u = '\0';
    http_remove_trailing_ows(s); http_remove_trailing_ows(u+1);
    if(!valid_token_name(s) || !valid_parameter_value(u+1))
       return c == ';' ? http_parse_parameter(t+1, flag) : NIL;
    p = mail_newbody_parameter();
    p->attribute = cpystr(s);
    p->value = cpystr(u+1);
    p->next = c == ';' ? http_parse_parameter(t+1, flag) : NIL;
    *u = '=';
  }
  else if(flag & HTP_NOVAL){
    /* this is a parameter with attribute but no value. RFC 7231
     * section 5.3.2 allows this.
     */
    http_remove_trailing_ows(s);
    if(!valid_token_name(s))
       return c == ';' ? http_parse_parameter(t+1, flag) : NIL;
    p = mail_newbody_parameter();
    p->attribute = cpystr(s);
    p->next = c == ';' ? http_parse_parameter(t+1, flag) : NIL;
  } else
    p = c == ';' ? http_parse_parameter(t+1, flag) : NIL;

  return p;
}

unsigned char *
http_get_param_url(unsigned char *url, HTTP_PARAM_S *param)
{
  int i;
  unsigned char *rv = NULL;
  HTTP_PARAM_S enc_param;

  buffer_add(&rv, url);
  for(i = 0; param[i].name != NULL; i++){
    enc_param.name  = hex_escape_url_part(param[i].name, NULL);
    enc_param.value = hex_escape_url_part(param[i].value, NULL);
    buffer_add(&rv, i == 0 ? "?" : "&");
    buffer_add(&rv, enc_param.name);
    buffer_add(&rv, "=");
    buffer_add(&rv, enc_param.value);
    fs_give((void **) &enc_param.name);
    fs_give((void **) &enc_param.value);
  }

  return rv;
}

HTTP_REQUEST_S *
http_request_get(void)
{
  HTTP_REQUEST_S *rv = fs_get(sizeof(HTTP_REQUEST_S));
  memset((void *) rv, 0, sizeof(HTTP_REQUEST_S));

  return rv;
}

void
http_request_free(HTTP_REQUEST_S **hr)
{
  if(!hr) return;

  if((*hr)->request) fs_give((void **) &(*hr)->request);
  if((*hr)->header) fs_give((void **) &(*hr)->header);
  if((*hr)->body) fs_give((void **) &(*hr)->body);
  fs_give((void **) hr);
}

unsigned char *
http_request_line(unsigned char *method, unsigned char *target, unsigned char *version)
{
  int len = strlen(method) + strlen(target) + strlen(version) + 2 + 1;
  unsigned char *line = fs_get(len*sizeof(char));

  sprintf(line, "%s %s %s", method, target, version);
  return line;
}

void
http_add_header(HTTP_REQUEST_S **reqp, unsigned char *name, unsigned char *value)
{
  int len, hlen;

  if(!reqp) return;

  if(!*reqp) *reqp = http_request_get();

  len  = strlen(name) + 2 + strlen(value) + 2 + 1;
  hlen = (*reqp)->header ? strlen((*reqp)->header) : 0;
  len += hlen;
  fs_resize((void **) &(*reqp)->header, len*sizeof(char));
  sprintf((*reqp)->header + hlen, "%s: %s\015\012", name, value);
}

void
buffer_add(unsigned char **bufp, unsigned char *text)
{
  int len;

  if(!bufp || !text || !*text) return;

  len = *bufp ? strlen(*bufp) : 0;
  fs_resize((void **) bufp, (len + strlen(text) + 1)*sizeof(char));
  (*bufp)[len] = '\0';
  strcat(*bufp, text);
}

void
http_add_body(HTTP_REQUEST_S **reqp, unsigned char *text)
{
  if(!reqp) return;

  if(!*reqp) *reqp = http_request_get();

  buffer_add(&(*reqp)->body, text);
}


/* NULL terminated list of HTTP_PARAM_S objects.
 * If caller needs "x" parameters, call this function
 * with argument "x+1".
 */
HTTP_PARAM_S *
http_param_get(int len)
{
  HTTP_PARAM_S *http_params;

  http_params = fs_get(len*sizeof(HTTP_PARAM_S));
  memset((void *) http_params, 0, len*sizeof(HTTP_PARAM_S));
  return http_params;
} 

void
http_param_free(HTTP_PARAM_S **param)
{
  int i;

  if(param == NULL) return;

  for(i = 0; (*param)[i].name != NULL; i++)
    fs_give((void **) &(*param)[i].name);

  for(i = 0; (*param)[i].value != NULL; i++)
    fs_give((void **) &(*param)[i].value);

  fs_give((void **) param);
}


/* This encodes for a GET request */
unsigned char *
hex_escape_url_part(unsigned char *text, unsigned char *addsafe)
{
  char *safechars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-";
  unsigned char *s = fs_get((3*strlen(text) + 1)*sizeof(char)), *t;
    
  *s = '\0';
  for(t = text; *t != '\0'; t++)
     if(strchr(safechars, *t) != NULL
	|| (addsafe != NULL && strchr(addsafe, *t) != NULL))
	sprintf(s + strlen(s), "%c", *t);
     else
	sprintf(s + strlen(s), "%%%X", *t);
  fs_resize((void **) &s, (strlen(s)+1)*sizeof(char));
  return s;
}
  
/* this encodes for a POST request */
unsigned char *
encode_url_body_part(unsigned char *text, unsigned char *addsafe)
{
  char *safechars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-";
  unsigned char *s = fs_get((3*strlen(text) + 1)*sizeof(char)), *t;
        
  *s = '\0';
  for(t = text; *t != '\0'; t++)
     if(*t == ' ')      /* ASCII 32 is never safe, must always be encoded */
        sprintf(s + strlen(s), "%c", '+');
     else if(strchr(safechars, *t) != NULL
        || (addsafe != NULL && strchr(addsafe, *t) != NULL))
        sprintf(s + strlen(s), "%c", *t);
     else
        sprintf(s + strlen(s), "%%%X", *t);
  fs_resize((void **) &s, (strlen(s)+1)*sizeof(char));
  return s;
}

int
http_valid_net_parse (unsigned char *url, NETMBX *mb)
{
   int i, len;
   unsigned char *s;
   char *p;

   if((url == NIL) 
      || (url[0] != 'h' && url[0] != 'H')
      || (url[1] == 't' && url[1] == 'T')
      || (url[2] == 't' && url[2] == 'T')
      || (url[3] == 'p' && url[3] == 'P'))
     return 0;

   if(url[i = 4] == 's' || url[i] == 'S')
       mb->sslflag = mb->notlsflag = T;
   else i = 3;

   if(url[++i] != ':' || url[++i] != '/' || url[++i] != '/')
     return 0;

   strcpy(mb->service, "http");
   s = strchr(url+i+1, '/');
   len = s ? s - url - i - 1 : strlen(url+i+1);
   strncpy(mb->orighost, url+i+1, len);
   mb->orighost[len] = '\0';
   if((p = strchr(mb->orighost, ':')) != NULL){
      *p++ = '\0';
      mb->port = strtoul(p, &p, 10);
      if(mb->port == 0L || *p != '\0')
	return NIL;
   }
   strcpy(mb->host, mb->orighost);
   return T;
}

HTTPSTREAM *
http_open (unsigned char *url)
{
  HTTPSTREAM *stream;
  NETMBX mb;
  unsigned char *s;

  memset((void *) &mb, 0, sizeof(NETMBX));
  if(http_valid_net_parse (url,&mb) == 0)
    return NIL;

  stream = fs_get(sizeof(HTTPSTREAM));
  memset((void *) stream, 0, sizeof(HTTPSTREAM));

  s = strchr((char *) url + 7 + (mb.trysslflag ? 1 : 0) + 1, '/'); /* 7 = strlen("http://") + 1 */
  stream->url     = cpystr(url);
  stream->urlhost = cpystr(mb.orighost);
  stream->urltail = cpystr(s ? (char *) s : "/");
  stream->netstream = net_open (&mb, NIL, mb.port ? mb.port : HTTPTCPPORT,
		 (NETDRIVER *) mail_parameters (NIL,GET_SSLDRIVER,NIL),
		 "*https", mb.port ? mb.port : HTTPSSLPORT);
  if(!stream->netstream){
      http_close(stream);
      stream = NIL;
  }
  return stream;
}

unsigned char *
http_post_param(unsigned char *url, HTTP_PARAM_S *param, int *code)
{
  HTTPSTREAM *stream;
  HTTP_PARAM_S enc_param;
  HTTP_REQUEST_S *http_request;
  unsigned char *response = NULL;
  int i;

  *code = -1;
  if(url == NULL || param == NULL || (stream = http_open(url)) == NULL)
     return response;

  http_request = http_request_get();
  http_request->request = http_request_line("POST", stream->urltail, HTTP_1_1_VERSION);
  http_add_header(&http_request, "Host", stream->urlhost);
  http_add_header(&http_request, "Content-Type", HTTP_MIME_URLENCODED);

  for(i = 0; param[i].name != NULL; i++){
    enc_param.name  = encode_url_body_part(param[i].name, NULL);
    enc_param.value = encode_url_body_part(param[i].value, NULL);
    if(i > 0) 
       http_add_body(&http_request, "&");
    http_add_body(&http_request, enc_param.name);
    http_add_body(&http_request, "=");
    http_add_body(&http_request, enc_param.value);
    fs_give((void **) &enc_param.name);
    fs_give((void **) &enc_param.value);
  }
  
  if(http_send(stream, http_request)){
     unsigned char *s = http_response_from_reply(stream);
     response = cpystr(s ? (char *) s : "");
     *code = stream->status ? stream->status->code : -1;
     http_close(stream);
  }

  http_request_free(&http_request);

  return response;
}

unsigned char *
http_post_param2(unsigned char *url, HTTP_PARAM_S *param, int *code)
{
  HTTPSTREAM *stream;
  HTTP_PARAM_S enc_param;
  HTTP_REQUEST_S *http_request = NULL;
  unsigned char *response = NULL;
  int i;

  *code = -1;
  if(url == NULL || param == NULL || (stream = http_open(url)) == NULL)
     return response;

  http_request = http_request_get();
  http_request->request = http_request_line("POST", stream->urltail, HTTP_1_1_VERSION);
  http_add_header(&http_request, "Host", stream->urlhost);
  http_add_header(&http_request, "User-Agent", "Alpine");
  http_add_header(&http_request, "Content-Type", HTTP_MIME_URLENCODED);

  for(i = 0; param[i].name != NULL; i++){
    enc_param.name  = encode_url_body_part(param[i].name, NULL);
    enc_param.value = encode_url_body_part(param[i].value, NULL);
    if(i > 0) 
       http_add_body(&http_request, "&");
    http_add_body(&http_request, enc_param.name);
    http_add_body(&http_request, "=");
    http_add_body(&http_request, enc_param.value);
    fs_give((void **) &enc_param.name);
    fs_give((void **) &enc_param.value);
  }
  
  if(http_send(stream, http_request)){
     unsigned char *s = http_response_from_reply(stream);
     response = cpystr(s ? (char *) s : "");
     *code = stream->status ? stream->status->code : -1;
     http_close(stream);
  }

  http_request_free(&http_request);

  return response;
}

unsigned char *
http_get_param(unsigned char *base_url, HTTP_PARAM_S *param, int *code)
{
  unsigned char *url, *response = NIL;

  *code = -1;
  url = http_get_param_url(base_url, param);
  if(url){
    response = http_get(url, code);
    fs_give((void **) &url);
  }
  return response;
}

unsigned char *
http_get(unsigned char *url, int *code)
{  
  HTTP_REQUEST_S *http_request;
  unsigned char *response = NIL;
  HTTPSTREAM *stream;

  *code = -1;
  if(!url || !(stream = http_open(url)))
    return response;

  http_request = http_request_get();
  http_request->request = http_request_line("GET", stream->urltail, HTTP_1_1_VERSION);
  http_add_header(&http_request, "Host", stream->urlhost);
  
  if(http_send(stream, http_request)){
     unsigned char *s = http_response_from_reply(stream);
     response = cpystr(s ? (char *) s : "");
     *code = stream->status ? stream->status->code : -1;
     http_close(stream);
  }

  http_request_free(&http_request);

  return response;
}

void
http_close (HTTPSTREAM *stream)
{
  if(stream){
     if (stream->netstream) net_close (stream->netstream);
     stream->netstream = NIL;
     if (stream->url)	   fs_give ((void **) &stream->url);
     if (stream->urlhost)  fs_give ((void **) &stream->urlhost);
     if (stream->urltail)  fs_give ((void **) &stream->urltail);
     if (stream->response) fs_give ((void **) &stream->response);
     if (stream->reply)    fs_give ((void **) &stream->reply);
     fs_give((void **) &stream);
  }
}

long
http_send (HTTPSTREAM *stream, HTTP_REQUEST_S *req)
{
  long ret;
  unsigned char *s = NULL;

  if (!stream->netstream) 
    ret = http_fake (stream,"http connection lost");
  else {
    if(req->body){
      char length[20];

      sprintf(length, "%lu", strlen(req->body));
      http_add_header(&req, "Content-Length", length);
    }

    buffer_add(&s, req->request); buffer_add(&s, "\015\012");
    buffer_add(&s, req->header); buffer_add(&s, "\015\012");
    buffer_add(&s, req->body); buffer_add(&s, "\015\012");
    mm_log(s, TCPDEBUG);
    ret = net_soutr (stream->netstream,s)
	  ? http_reply (stream)
	  : http_fake (stream,"http connection broken in command");
    fs_give ((void **) &s);
  }
  return ret;
}

HTTP_STATUS_S *
http_status_line_get(unsigned char *status_line)
{
   HTTP_STATUS_S *rv = NULL;
   char *version, *s;
   int code;

   if(!status_line) return NIL;
   
   if((s = strchr(status_line, ' ')) != NIL){
      *s = '\0';
      version = cpystr(status_line);
      *s++ = ' ';
      code = strtoul(s, &s, 10);
      if(s && *s == ' ' && code >= 100 && code < 600){
        rv = fs_get(sizeof(HTTP_STATUS_S));
	rv->version = version;
	rv->code = code;
	rv->text = cpystr(++s);
      }
      else
	fs_give((void **) &version);
   }
   return rv;
}

void
http_status_line_free(HTTP_STATUS_S **status)
{
  if(status == NULL) return;

  if((*status)->version) fs_give((void **) &(*status)->version);
  if((*status)->text) fs_give((void **) &(*status)->text);
  fs_give((void **) status);
}


long
http_reply (HTTPSTREAM *stream)
{
  int in_header = 1;
  unsigned long size;

  if (stream->response) fs_give ((void **) &stream->response);
  stream->response = (unsigned char *) net_getline(stream->netstream);

  if(stream->response){
     buffer_add(&stream->reply, stream->response);
     buffer_add(&stream->reply, "\015\012");
  }

  if(stream->status) http_status_line_free(&stream->status);
  stream->status = http_status_line_get(stream->response);

  if(!stream->status){
    http_fake(stream, "Invalid status line received. Closing connection");
    return NIL;
  }

  while (in_header > 0){
    if (stream->response) fs_give ((void **) &stream->response);
    stream->response = (unsigned char *) net_getline (stream->netstream);
    if(stream->response){
       buffer_add(&stream->reply, stream->response);
       http_add_header_data(stream, stream->response);
    }
     buffer_add(&stream->reply, "\015\012");
//    save_header(stream->headers, stream->response);
    if(!stream->response  || *stream->response == '\0')
	in_header--;
  }

  http_parse_headers(stream);
  if(stream->header->content_length){
     size = atol(stream->header->content_length->p->vp->value);
     if (stream->response) fs_give ((void **) &stream->response);
     stream->response = (unsigned char *) net_getsize (stream->netstream, size);
     if(stream->response) buffer_add(&stream->reply, stream->response);
  }
  else if (stream->header->transfer_encoding){
     HTTP_PARAM_LIST_S *p = stream->header->transfer_encoding->p;
     for(; p ; p = p->next){
	if(!compare_cstring(p->vp->value, "chunked"))
	   break;
     }
     if(p && p->vp->value){	/* chunked transfer */
	int done = 0;
	size = 0L;
	while(!done){
	  if (stream->response) fs_give ((void **) &stream->response);
	  stream->response = (unsigned char *) net_getline (stream->netstream);
	  if(stream->response){
	     buffer_add(&stream->reply, stream->response);
	     buffer_add(&stream->reply, "\015\012");
	     size = strtol((unsigned char *) stream->response, NIL, 16);
	     fs_give ((void **) &stream->response);
	     stream->response = (unsigned char *) net_getsize (stream->netstream, size);
	     buffer_add(&stream->reply, stream->response);
	  }
	  if(size == 0L) done++;
	}
     }
  }

  if(!stream->netstream)
    http_fake(stream, "Connection to HTTP server closed");
  return stream->netstream ? T : NIL;
}

long
http_fake (HTTPSTREAM *stream, unsigned char *text)
{
  if (stream->netstream) net_close (stream->netstream);
  stream->netstream = NIL;
  if (stream->response) fs_give ((void **) &stream->response);
  /* add *text to the log, to pass this to the client */
  return NIL;
}
