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
#ifndef JSON_H_INCLUDED
#define JSON_H_INCLUDED

typedef enum {JValue, JString, JLong, JDecimal, JExponential, JNumberError, 
	      JObject, JArray, JBoolean, JNull, JEnd} JObjType;

typedef struct json_x {
   JObjType jtype;
   void *value;
} JSON_X;

typedef struct json_s {
   unsigned char *name;
   JSON_X *value;
   struct json_s *next;
} JSON_S;

JSON_S *json_parse(unsigned char **);
JSON_X *json_body_value(JSON_S *, unsigned char *);
void json_free(JSON_S **);

#endif /* JSON_H_INCLUDED */
