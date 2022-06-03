/*
 * Copyright 2021-2022 Eduardo Chappa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */
/* This algorithm is taken from the code in RFC 4634 */

#include "c-client.h"
#include "sha.h"
#include "hmac.c"
#include "sha1.c"
#include "usha.c"
#include "sha224-256.c"
#include "sha384-512.c"

struct hash {
    char *name;
    SHAversion whichSha;
    int hashsize;
} hashes[] = {
  {"SHA1", CCSHA1, SHA1HashSize},
  {"SHA224", CCSHA224, SHA224HashSize},
  {"SHA256", CCSHA256, SHA256HashSize},
  {"SHA384", CCSHA384, SHA384HashSize},
  {"SHA512", CCSHA512, SHA512HashSize},
  {NIL, CCSHA512, SHA512HashSize}
};
static const char hexdigits[] = "0123456789abcdef";

char *hash_from_sizedtext(char *hash, char *text, size_t len, unsigned char **digest)
{
  char *rv = NIL;
  USHAContext sha;
  HMACContext hmac;
  uint8_t Message_Digest[USHAMaxHashSize];
  int i, hashno;
  unsigned long len2;

  if(digest) *digest = NIL;

  if(!hash || !text) return NIL;

  for(hashno = 0; hashes[hashno].name != NIL; hashno++)
     if(!compare_cstring(hashes[hashno].name, hash))
	break;

  if(hashno >= 0 && hashno <= USHAMaxHashSize && hashes[hashno].name){
     memset(&sha, '\343', sizeof(USHAContext));
     memset(&hmac, '\343', sizeof(HMACContext));
     if(USHAReset(&sha, hashes[hashno].whichSha) == shaSuccess
	&& USHAInput(&sha, (const uint8_t *) text, len) == shaSuccess){
	if(USHAResult(&sha, (uint8_t *) Message_Digest) == shaSuccess){
	   if(digest) *digest = rfc822_urlbinary((void *) Message_Digest, hashes[hashno].hashsize, &len2);
	   rv = fs_get(2*hashes[hashno].hashsize + 1);
	   for (i = 0; i < hashes[hashno].hashsize ; ++i) {
	      rv[2*i]   = hexdigits[(Message_Digest[i] >> 4) & 0xF];
	      rv[2*i+1] = hexdigits[Message_Digest[i] & 0xF];
	   }
	   rv[2*i] = '\0';
	}
     }
  }
  return rv;
}
