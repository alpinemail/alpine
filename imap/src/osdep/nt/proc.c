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

#include <stdio.h>
#include <stdlib.h>  
#include <string.h>
#include <ctype.h>

int main(int, char **);

int
main(int argc, char *argv[])
{
  int rv = 0, i;
  FILE *fph, *fpc, *fpa;
  char *opt;

  fph = fpc = fpa = NULL;
  if(argc < 2){
    fprintf(stdout, "Not enough arguments.\n");
    fprintf(stdout, "Usage: %s opt ...\n", argv[0]);
    fprintf(stdout, "opt can be drivers, mkauths, version, setproto or sslinit\n");
    exit(1);
  }

  opt = argv[1];
  if(!strcmp(opt, "drivers")){
    fph = fopen("linkage.h", "w");
    fpc = fopen("linkage.c", "w");
    for (i = 2; i < argc; i++){
       fprintf(fph, "extern DRIVER %sdriver;\n", argv[i]);
       fprintf(fpc, "  mail_link (&%sdriver);   /* link in the %s driver */\n",
			 argv[i], argv[i]);
    }
  }
  else if(!strcmp(opt, "mkauths")){
    fph = fopen("linkage.h", "a");
    fpc = fopen("linkage.c", "a");
    fpa = fopen("auths.c", "w");
    for (i = 2; i < argc; i++){
       fprintf(fph, "extern AUTHENTICATOR auth_%s;\n", argv[i]);
       fprintf(fpc, "  auth_link (&auth_%s);   /* link in the %s authenticator */\n", 
			argv[i], argv[i]);
       fprintf(fpa, "#include \"auth_%s.c\"\n", argv[i]);
    }
  }
  else if(!strcmp(opt, "setproto")){
    if(argc != 4){
	fprintf(stdout, "setproto requires two additional arguments\n");
	exit(1);
    }
    fph = fopen("linkage.h", "a");
    fprintf(fph, "#define CREATEPROTO %sproto\n", argv[2]);
    fprintf(fph, "#define APPENDPROTO %sproto\n", argv[3]);
  }
  else if(!strcmp(opt, "sslinit")){
    fpc = fopen("linkage.c", "a");
    fprintf(fpc, "%s\n", "ssl_onceonlyinit();");
    fph = fopen("linkage.h", "a");
    fprintf(fph, "%s\n", "int  pith_ssl_encryption_version(char *);");
  }
  else if(!strcmp(opt, "version")){
    fpc = fopen("linkage.c", "a");
    fprintf(fpc, "%s\n", "mail_versioncheck(CCLIENTVERSION);");
  }
  else {
    fprintf(stdout, "Try: \"drivers\", \"mkauths\", \"setproto\", \"sslinit\", or \"version\".\n");
    exit(1);
  }
  if(fpa != NULL) fclose(fpa);
  if(fpc != NULL) fclose(fpc);
  if(fph != NULL) fclose(fph);
  exit(0);
}
