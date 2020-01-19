/*
 * ========================================================================
 * Copyright 2013-2020 Eduardo Chappa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 */

#include "../pith/headers.h"
#include "../pith/body.h"
#include "../pith/smime.h"
#include "../pith/ical.h"

void *
create_body_sparep(SpareType stype, void *s)
{
  BODY_SPARE_S *rv;

  rv = fs_get(sizeof(BODY_SPARE_S));
  rv->sptype = stype;
  rv->data   = s;
  return (void *) rv;
}

SpareType
get_body_sparep_type(void *s)
{
  return ((BODY_SPARE_S *)s)->sptype;
}

void *
get_body_sparep_data(void *s)
{
  return ((BODY_SPARE_S *)s)->data;
}

void
free_body_sparep(void **sparep)
{
    char *s;
    SIZEDTEXT *st;
    VCALENDAR_S *vcal;

    if(sparep && *sparep){
	switch(get_body_sparep_type(*sparep)){
#ifdef SMIME
	  case P7Type:  PKCS7_free((PKCS7 *) get_body_sparep_data(*sparep));
			break;
#endif /* SMIME */
	  case CharType: s = (char *)get_body_sparep_data(*sparep);
			 fs_give((void **)  &s);
			 break;
	  case SizedText: st = (SIZEDTEXT *)get_body_sparep_data(*sparep);
			 fs_give((void **) &st->data);
			 fs_give((void **) &st);
			 break;
	  case iCalType: vcal = (VCALENDAR_S *)get_body_sparep_data(*sparep);
			 ical_free_vcalendar((void **) &vcal);
			 break;
	  default : break;
	}
	((BODY_SPARE_S *)(*sparep))->data = NULL;
	fs_give(sparep);
    }
}
