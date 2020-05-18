/*
 * Copyright 2018 Eduardo Chappa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */
#ifdef STANDALONE
#include "headers.h"
#include "mem.h"
#include "readfile.h"
#include "json.h"
#else
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include "c-client.h"
#include "json.h"
#endif /* STANDALONE */

#define NIL 0

#define json_ws(X) (((X) == ' ' || (X) == '\t' || (X) == '\n' || (X) == '\r') ? 1 : 0)

#define json_skipws(X) for(; json_ws(*(X)); (X)++)

#define json_skipchar(X) {					\
	(X)++;							\
	json_skipws((X));					\
}

#define json_last_char(X) (((X) == ',' || (X) == ']'  || (X) == '}') ? 1 : 0)

JObjType json_number_type(unsigned char *);
unsigned char *json_strchr(unsigned char *, unsigned char);
JSON_S *json_parse_work(unsigned char **);
JSON_S *json_parse_pairs(unsigned char **);

JSON_X *json_value_parse(unsigned char **);
void    json_value_free(JSON_X **);

/* An array is a JSON object where the name is null */
JSON_S *json_array_parse_work(unsigned char **);
JSON_S *json_array_parse(unsigned char **);
void    json_array_free(JSON_S **);

/* we are parsing from the text of the json object, so it is
 * never possible to have a null character, unless something
 * is corrupt, in whose case we return JNumberError.
 */
JObjType json_number_type(unsigned char *s)
{
  unsigned char *w = s, *u;
  int PossibleDecimal, PossibleExponential;

  PossibleDecimal = PossibleExponential = 0;

  if(*w == '+' || *w == '-')
    w++;

  if (*w == '0'){
     u = w + 1;
     if(json_ws(*u)) json_skipws(u);
     if(json_last_char(*u)) return JLong;
     else if(*(w+1) == '.'){
	for(u = w+2; *u >= '0' && *u <= '9'; u++);
	if(json_ws(*u)) json_skipws(u);
	if(json_last_char(*u)) return JDecimal;
	else return JNumberError;
     }
     else return JNumberError;
  }

  if(*w < '1' || *w > '9')
    return JNumberError;

  u = w + 1;
  if(json_ws(*u)) json_skipws(u);
  if(json_last_char(*u)) return JLong;
  else if (*(w+1) == 'e' || *(w+1) == 'E'){
    PossibleExponential++;
    w += 2;
  }
  else if(*(w+1) == '.'){
    PossibleDecimal++;
    PossibleExponential++;
    w += 2;
  } else {
    for(; *w >= '0' && *w <= '9'; w++);
    if(*w == '.'){
      PossibleDecimal++;
      w++;
    }
    else {
      if(json_ws(*w)) json_skipws(w);
      if(json_last_char(*w)) return JLong;
      else return JNumberError;
    }
  }

  if(PossibleDecimal){
    for(; *w >= '0' && *w <= '9'; w++);
    u = w;
    if(json_ws(*u)) json_skipws(u);
    if(json_last_char(*u)) return JDecimal;
    else if (*w == 'e' || *w == 'E'){
       PossibleExponential++;
       w++;
    }
    else return JNumberError;
  }

  if(PossibleExponential){
     if(*w == '+' || *w == '-')
	w++;
     if(*w == '0'){
       u = w + 1;
       if(json_ws(*u)) json_skipws(u);
       if(json_last_char(*u)) return JExponential;
       else return JNumberError;
     }
     if(*w < '1' || *w > '9')
	return JNumberError;
     for(; *w >= '0' && *w <= '9'; w++);
     if(json_ws(*w)) json_skipws(w);
     if(json_last_char(*w)) return JExponential;
     else return JNumberError;
  }
  return JNumberError;	/* never reached */
}


JSON_X *
json_body_value(JSON_S *j, unsigned char *s)
{
  JSON_S *js;

  if(!j || !j->value|| j->value->jtype != JObject) return NIL;

  for(js = (JSON_S *) j->value->value; js ; js = js->next)
    if(js->name && !compare_cstring(js->name, s))
	break;

  return js ? js->value : NIL;
}

unsigned char *
json_strchr(unsigned char *s, unsigned char c)
{
   unsigned char *t, d;
   int escaped, extended;

   if(c == '\0'){
      t = s + strlen((char *) s);
      return t;
   }

   escaped = extended = 0;
   for(t = s; (d = *t) != '\0';){
      if(escaped){
	if (d == '\"' || d == '\\' || d == '/' || d == 'b'
	   || d == 'f' || d == 'n' || d == 'r' || d == 't'){
	   escaped = 0;
	   t++;
	   continue;
	}
	else{
	   if(d == 'u'){
	     escaped  = 0;
	     extended = 1;
	     t++;
	   }
	   else
	     return NIL;
	}
      }
      else {
	if(d == '\\'){
	  escaped = 1;
	  t++;
	  continue;
	}
	else if(extended){
	   int i;
	   static char HEX[] = "abcdefABCDEF0123456789";

	   if(strlen((char *) t) < 4)
	      return NIL;

	   for(i = 0; i < 4; i++){
	      if(!strchr(HEX, *t))
		return NIL;
	      else
		t++;
	   }
	   extended = 0;
	}
	else if (d == c)
	   break;
	else t++;
      }
   }
   return (*t == '\0') ? NULL : t;
}

JSON_X *
json_value_parse(unsigned char **s)
{
  JSON_X *jx;
  unsigned char *u, *w;
  unsigned long *l;

  w = *s;
  json_skipws(w);
  jx = fs_get(sizeof(JSON_X));
  memset((void **) jx, 0, sizeof(JSON_X));
  jx->jtype = JEnd;
  switch(*w){
     case '\"': jx->jtype = JString; break;
     case '{' : jx->jtype = JObject; break;
     case '[' : jx->jtype = JArray; break;
     case 'f' : if(strlen((char *) w) > 5
		    && !strncmp((char *) w, "false", 5)){
		   u = w+5;
		   json_skipws(u);
		   if(json_last_char(*u))
		     jx->jtype = JBoolean;
		}
		break;
     case 'n' : if(strlen((char *) w) > 4
		    && !strncmp((char *) w, "null", 4)){
		   u = w+4;
		   json_skipws(u);
		   if(json_last_char(*u))
		     jx->jtype = JNull;
		}
		break;
     case 't' : if(strlen((char *) w) > 4 
		    && !strncmp((char *) w, "true", 4)){
		   u = w+4;
		   json_skipws(u);
		   if(json_last_char(*u))
		     jx->jtype = JBoolean;
		}
		break;
       default: jx->jtype = json_number_type(w);
		break;		
  }

  switch(jx->jtype){
     case JString: u = json_strchr(w+1, '\"');
		   if(u != NULL){
		     *u = '\0';
		     jx->value = (void *) cpystr((char *) w+1);
		     *u = '\"';
		     json_skipchar(u);
		     w = u;
		   }
		   break;

     case JObject: jx->value = (void *) json_parse(&w);
		   break;

     case JLong  : l = fs_get(sizeof(unsigned long));
		   *l = strtoul((char *) w, (char **) &w, 10);
		   jx->value = (void *) l;
		   json_skipws(w);
		   break;

     case JDecimal :
     case JExponential: l = fs_get(sizeof(double));
		     *l = strtod((char *) w, (char **) &w);
		     jx->value = (void *) l;
		     json_skipws(w);
		     break;

     case JBoolean: if(*w == 't'){
		      jx->value = (void *) cpystr("true");
		      w += 4;
		    }
		    else{
		      jx->value = (void *) cpystr("false");
		      w += 5;
		    }
		    json_skipws(w);
		    break;

     case  JNull: jx->value = (void *) cpystr("null");
		  w += 4;
		  json_skipws(w);
		  break;

     case JArray: jx->value = json_array_parse(&w);
		  json_skipchar(w);
		 break;

	default:  break;   /* let caller handle this */
  }
  *s = w;
  return jx;
}

JSON_S *
json_array_parse(unsigned char **s)
{
  JSON_S *j = NIL;
  unsigned char *w = *s;

  json_skipws(w);
  if(*w == '['){
     json_skipchar(w);
     j = json_array_parse_work(&w);
  }
  *s = w;
  return j;
}

JSON_S *
json_array_parse_work(unsigned char **s)
{
  unsigned char *w = *s;
  JSON_S *j;

  json_skipws(w);
  j = fs_get(sizeof(JSON_S));
  memset((void *) j, 0, sizeof(JSON_S));
  j->value = json_value_parse(&w);
  json_skipws(w);
  switch(*w){
        case ',' : json_skipchar(w);
		   j->next = json_array_parse_work(&w);
		   break;

        case ']' : break;
         default : json_free(&j);
  }
  *s = w;
  return j;
}

void
json_array_free(JSON_S **j)
{
  json_free(j);
}

JSON_S *
json_parse_pairs(unsigned char **s)
{
  JSON_S *j;
  unsigned char *u, *w = *s;

  json_skipws(w);
  if(*w++ != '\"')
    return NIL;

  u = json_strchr(w, '\"');
  if(!u)
    return NIL;

  *u = '\0';
  j = fs_get(sizeof(JSON_S));
  memset((void *) j, 0, sizeof(JSON_S));
  j->name = (unsigned char *) cpystr((char *) w);

  *u = '\"';
  json_skipchar(u);
  if(*u != ':')
    return j;
  json_skipchar(u);

  j->value = json_value_parse(&u);
  json_skipws(u);
  if (*u == ','){
    json_skipchar(u);
    j->next = json_parse_pairs(&u);
  }
  *s = u;
  return j;
}

void
json_value_free(JSON_X **jxp)
{
  if(!jxp || !*jxp)
    return;

  switch((*jxp)->jtype){
	case  JString:
	case  JLong  :
	case JDecimal:
	case JExponential:
	case JBoolean:
	case    JNull: fs_give((void **)  &(*jxp)->value);
		       break;

	case   JArray: json_array_free((JSON_S **) &(*jxp)->value);
		       break;

	case  JObject: json_free((JSON_S **) &(*jxp)->value);
		       break;

	      default: printf("Unhandled case in json_value_free");
			exit(1);
  }
}

void
json_free(JSON_S **jp)
{

  if(jp == NULL || *jp == NULL) return;

  if((*jp)->name) fs_give((void **) &(*jp)->name);
  if((*jp)->value) json_value_free(&(*jp)->value);
  if((*jp)->next) json_free(&(*jp)->next);
  fs_give((void **) jp);
}

JSON_S *
json_parse(unsigned char **s)
{
  JSON_S *j = NULL;
  JSON_X *jx;
  unsigned char *w = *s;

  json_skipws(w);
  if(*w == '{'){
     json_skipchar(w);
     jx = fs_get(sizeof(JSON_X));
     memset((void *) jx, 0, sizeof(JSON_X));
     jx->jtype = JObject;
     jx->value = (void *) json_parse_pairs(&w);
     j = fs_get(sizeof(JSON_S));
     memset((void *) j, 0, sizeof(JSON_S));
     j->value = jx;
     json_skipws(w);
     if(*w == '}'){
        json_skipchar(w);
     }
     else
        json_free(&j);
  }
  *s = w;
  return j;  
}
