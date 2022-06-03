/*
 * Copyright 2018-2022 Eduardo Chappa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */
#ifndef JSON_H_INCLUDED
#define JSON_H_INCLUDED

typedef enum {JValue, JString, JLong, JDecimal, JExponential, JNumberError, 
	      JObject, JArray, JBoolean, JNull, JEnd} JObjType;

typedef struct json_s {
   JObjType jtype;
   unsigned char *name;
   void *value;
   struct json_s *next;
} JSON_S;

#define json_value_type(J, I, T) 					\
	(((jx = json_body_value((J), (I))) != NIL)			\
	  && jx->jtype == (T) && jx->value)				\
	? ((T) == JLong							\
	    ? *(long *) jx->value					\
	    : ((T) == JBoolean						\
	        ? (compare_cstring("false", (char *) jx->value) ? 1 : 0)\
		: NIL							\
	      )								\
          )								\
	: NIL

void json_assign(void **, JSON_S *, char *, JObjType);
JSON_S *json_by_name_and_type(JSON_S *, char *, JObjType);
JSON_S *json_parse(unsigned char *);
JSON_S *json_body_value(JSON_S *, unsigned char *);
void json_free(JSON_S **);

#endif /* JSON_H_INCLUDED */
