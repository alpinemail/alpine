/*
 * Copyright 2018 Eduardo Chappa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Last Edited: July 23, 2018 Eduardo Chappa <chappa@washington.edu>
 *
 */

typedef struct http_val_param_s {
  char *value;
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
		*content_disposition,	/* RFC 6266 */
		*content_encoding,	/* RFC 7231, Section 3.1.2.2 */
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
		*user_agent,		/* RFC 7231, Section 5.5.3 */
		*te,			/* RFC 7230, Section 4.3 */
		*trailer,		/* RFC 7230, Section 4.4 */
		*transfer_encoding,	/* RFC 7230, Section 3.3.1 */
		*upgrade,		/* RFC 7230, Section 6.7 */
		*via,			/* RFC 7230, Section 5.7.1 */
		*vary,			/* RFC 7231, Section 7.1.4 */
		*warning,		/* RFC 7234, Section 5.5 */
		*www_authenticate;	/* RFC 7235, Section 4.1 */
} HTTP_HEADER_DATA_S;

#define HTTP_MIME_URLENCODED	"application/x-www-form-urlencoded"

#define HTTP_1_1_VERSION	"HTTP/1.1"
#define HTTP_OK			200
#define HTTP_BAD		400
#define HTTP_UNAUTHORIZED	401

#define GET_HTTPPORT (long) 490
#define SET_HTTPPORT (long) 491
#define GET_SSLHTTPPORT (long) 492
#define SET_SSLHTTPPORT (long) 493

typedef struct http_status_s {
  char *version;  
  int   code;
  char *text;
} HTTP_STATUS_S;


typedef struct http_stream {
  NETSTREAM *netstream;
  HTTP_HEADER_DATA_S *header;	/* headers sent by the server */
  char *url;		/* original url */
  char *urlhost;	/* get original host */
  char *urltail;	/* the part of the URL after the original host */
  HTTP_STATUS_S *status;/* parsed status line from server */
  unsigned char *response;	/* last reply line from server */
  unsigned char *reply;	/* the full reply from the server */
} HTTPSTREAM;

/* parameters for a get or post call */
typedef struct http_param_s {
   char *name;                          
   char *value;
} HTTP_PARAM_S;

/* exported prototypes */
HTTPSTREAM *http_open (unsigned char *);
unsigned char *http_post_param(unsigned char *, HTTP_PARAM_S *, int *);
unsigned char *http_post_param2(unsigned char *, HTTP_PARAM_S *, int *);
unsigned char *http_get_param(unsigned char *, HTTP_PARAM_S *, int *);
unsigned char *http_get(unsigned char *, int *);
void http_close (HTTPSTREAM *stream);

HTTP_PARAM_S *http_param_get(int);
void http_param_free(HTTP_PARAM_S **);

/* Ugghh.... just construct the URL for a get request */
unsigned char *http_get_param_url(unsigned char *, HTTP_PARAM_S *);
