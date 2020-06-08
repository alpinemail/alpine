#include "../pith/headers.h"
#include "../pith/mailpart.h"
#include "../pith/store.h"
#include "../pith/ical.h"

typedef struct ical_iana_comp_s {
  char *comp;			/* component name */
  size_t len;			/* size of component name (strlen(x->comp)) */
  int pos;			/* position of this component in comp array */
  void *(*parse)(char **);	/* parser	  */
  void (*give)(void **);	/* free memory	  */
} ICAL_COMP_S;

typedef struct ical_iana_prop_s {
  char *prop;			/* component PROPerty name */
  size_t len;			/* size of component name (strlen(x->prop)) */
  int pos;			/* location of this component in the prop array */
  void *(*parse)();		/* parser */
  void (*give)(void **);	/* free memory	  */
} ICAL_PROP_S;

int ical_january_first(int);		/* args: year */
void ical_adjust_date(struct tm *, VTIMEZONE_S *);

void ical_initialize(void);

int ical_non_ascii_valid(unsigned char);
char *ical_unfold_line(char *);
ICLINE_S *ical_parse_line(char **, char *);

ICLINE_S *ical_cline_cpy(ICLINE_S *);
ICAL_PARAMETER_S *ical_parameter_cpy(ICAL_PARAMETER_S *param);

char *ical_get_value(char **);
unsigned char *ical_decode(char *, unsigned short);

/* parse component */
void	*ical_parse_vcalendar(char **);
void	*ical_parse_vevent(char **);
void	*ical_parse_vtodo(char **);
void	*ical_parse_vjournal(char **);
void	*ical_parse_vfreebusy(char **);
void	*ical_parse_vtimezone(char **);
void	*ical_parse_valarm(char **);
void	*ical_parse_timezone(char **);
ICAL_S 	*ical_parse_unknown_comp(char **, int);
ICAL_S 	*ical_parse_generic_comp(char **, int);

/* free components */
void ical_free_vevent(void **);
void ical_free_vtodo(void **);
void ical_free_vjournal(void **);
void ical_free_vfreebusy(void **);
void ical_free_vtimezone(void **);
void ical_free_timezone(void **);
void ical_free_valarm(void **);
void ical_free_unknown_comp(ICAL_S **);

/* parse properties */
void  *ical_cline_from_token(void *, char **, char *);
void  *ical_gencline_from_token(void *, char **, char *);

void  *ical_parse_rrule(void *, char **, char *);
void  *ical_parse_time(void *, char **, char *);
void  *ical_parse_offset(void *, char **, char *);

void  *ical_parse_freq(void *, char *);
void  *ical_parse_until(void *, char *);
void  *ical_parse_count(void *, char *);
void  *ical_parse_interval(void *, char *);
void  *ical_parse_weekday_list(void *, char *);
void  *ical_parse_number_list(void *, char *);

int  ical_get_number_value(char *, int, int);
void ical_set_date(ICLINE_S *, VTIMEZONE_S *);
void ical_set_date_vevent(void *, void *);

/* free properties */
void ical_free_prop(void ***, ICAL_PROP_S *, int);
void ical_free_cline(void **);
void ical_free_param(ICAL_PARAMETER_S **);
void ical_free_gencline(void **);
void ical_free_rrule(void **);
void ical_fs_give(void **);
void ical_free_weekday_list(void **);

/* utility functions */
void ical_date_time (char *, size_t, struct tm *);
char *ical_get_tzid(ICAL_PARAMETER_S *);

/* globals */
struct tm day_zero;	/* date for january 1, 1601 */
int month_len[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

#define UTF8_COMPLETE (1)
#define NEED_MORE     (2)

char *ical_buf;
unsigned long ical_buf_len;


/* parsing structures */

/* this is the list of V-components to a Calendar from RFC 5545 */
ICAL_COMP_S ical_comp[] = {
  {"VCALENDAR",	9,	VCalendar,	ical_parse_vcalendar,	ical_free_vcalendar},
  {"VTIMEZONE",	9,	VTimeZone,	ical_parse_vtimezone,	ical_free_vtimezone},
  {"VEVENT",	6,	VEvent,		ical_parse_vevent,	ical_free_vevent},
  {"VTODO",	5,	VTodo,		ical_parse_vtodo,	ical_free_vtodo},
  {"VJOURNAL",	8,	VJournal, 	ical_parse_vjournal,	ical_free_vjournal},
  {"VALARM",	6,	VAlarm,		ical_parse_valarm,	ical_free_valarm},
  {"VFREEBUSY",	9,	VFreeBusy,	ical_parse_vfreebusy,	ical_free_vfreebusy},
  {NULL,	0,	VUnknown,	NULL,			0}
};

/* array for properties */
ICAL_PROP_S rrule_prop[] = {
  {"FREQ",	4,	RRFreq,		ical_parse_freq,	ical_fs_give},
  {"UNTIL",	5,	RRUntil,	ical_parse_until,	ical_fs_give},
  {"COUNT",	5,	RRCount,	ical_parse_count,	ical_fs_give},
  {"INTERVAL",	8,	RRInterval,	ical_parse_interval,	ical_fs_give},
  {"BYSECOND",	8,	RRBysecond,	ical_parse_number_list,	ical_free_weekday_list},
  {"BYMINUTE",	8,	RRByminute,	ical_parse_number_list,	ical_free_weekday_list},
  {"BYHOUR",	6,	RRByhour,	ical_parse_number_list,	ical_free_weekday_list},
  {"BYDAY",	5,	RRByday,	ical_parse_weekday_list,ical_free_weekday_list},
  {"BYWEEKNO",	8,	RRByweekno,	0,	0},
  {"BYMONTH",	7,	RRBymonth,	ical_parse_number_list,	ical_free_weekday_list},
  {"BYSETPOS",	8,	RRBysetpos,	0,	0},
  {"BYWKST",	6,	RRWkst,		0,	0},
  {"BYMONTHDAY",	
		10,	RRBymonthday,		0,	0},
  {"BYYEARDAY",	9,	RRByyearday,		0,	0},
  {NULL,	0,	RRUnknown,		0,	0}
};

ICAL_PROP_S event_prop[] = {
  {"DTSTAMP",		7,	EvDtstamp,	ical_cline_from_token,	ical_free_cline},
  {"UID",		3,	EvUid,		ical_cline_from_token,	ical_free_cline},
  {"DTSTART",		7,	EvDtstart,	ical_cline_from_token,	ical_free_cline},
  {"CLASS",		5,	EvClass,	ical_cline_from_token,	ical_free_cline},
  {"CREATED",		7,	EvCreated,	ical_cline_from_token,	ical_free_cline},
  {"DESCRIPTION",	11,	EvDescription,	ical_cline_from_token,	ical_free_cline},
  {"GEO",		3,	EvGeo,		ical_cline_from_token,	ical_free_cline},
  {"LASTMOD",		7,	EvLastMod,	ical_cline_from_token,	ical_free_cline},
  {"LOCATION",		8,	EvLocation,	ical_cline_from_token,	ical_free_cline},
  {"ORGANIZER",		9,	EvOrganizer,	ical_cline_from_token,	ical_free_cline},
  {"PRIORITY",		8,	EvPriority,	ical_cline_from_token,	ical_free_cline},
  {"SEQUENCE",		8,	EvSequence,	ical_cline_from_token,	ical_free_cline},
  {"STATUS",		6,	EvStatus,	ical_cline_from_token,	ical_free_cline},
  {"SUMMARY",		7,	EvSummary,	ical_cline_from_token,	ical_free_cline},
  {"TRANSP",		6,	EvTransp,	ical_cline_from_token,	ical_free_cline},
  {"URL",		3,	EvUrl,		ical_cline_from_token,	ical_free_cline},
  {"RECURRENCE-ID",	13,	EvRecurrence,	ical_cline_from_token,	ical_free_cline},
  {"RRULE",		5,	EvRrule,	ical_parse_rrule,	ical_free_rrule},
  {"DTEND",		5,	EvDtend,	ical_cline_from_token,	ical_free_cline},
  {"DURATION",		8,	EvDuration,	ical_cline_from_token,	ical_free_cline},
  {"ATTACH",		6,	EvAttach,	ical_gencline_from_token,	ical_free_gencline},
  {"ATTENDEE",		8,	EvAttendee,	ical_gencline_from_token,	ical_free_gencline},
  {"CATEGORIES",	10,	EvCategories,	ical_gencline_from_token,	ical_free_gencline},
  {"COMMENT",		7,	EvComment,	ical_gencline_from_token,	ical_free_gencline},
  {"CONTACT",		7,	EvContact,	ical_gencline_from_token,	ical_free_gencline},
  {"EXDATE",		6,	EvExdate,	ical_gencline_from_token,	ical_free_gencline},
  {"RSTATUS",		7,	EvRstatus,	ical_gencline_from_token,	ical_free_gencline},
  {"RELATED",		7,	EvRelated,	ical_gencline_from_token,	ical_free_gencline},
  {"RESOURCES",		9,	EvResources, 	ical_gencline_from_token,	ical_free_gencline},
  {"RDATE",		5,	EvRdate,	ical_gencline_from_token,	ical_free_gencline},
  {NULL,		0,	EvUnknown,	0,			0}
};

ICAL_PROP_S tz_comp[] = {
  {"TZID",		4,	TZCid,		ical_cline_from_token,	ical_free_cline},
  {"LAST-MODIFIED",	13,	TZCLastMod,	ical_cline_from_token,	ical_free_cline},
  {"TZURL",		5,	TZCUrl,		ical_cline_from_token,	ical_free_cline},
  {NULL,		0,	TZCUnknown,	0,			0}
};

ICAL_PROP_S tz_prop[] = {
  {"DTSTART",		7,	TZPDtstart,	ical_parse_time,	ical_fs_give},
  {"TZOFFSETTO",	10,	TZPOffsetto,	ical_parse_offset,	ical_fs_give},
  {"TZOFFSETFROM",	12,	TZPOffsetfrom,	ical_parse_offset,	ical_fs_give},
  {"RRULE",		5,	TZPRrule,	ical_parse_rrule,	ical_free_rrule},
  {"COMMENT",		7,	TZPComment,	ical_gencline_from_token,	ical_free_gencline},
  {"RDATE",		5,	TZPRdate,	ical_gencline_from_token,	ical_free_gencline},
  {"TZNAME",		6,	TZPTzname,	ical_gencline_from_token,	ical_free_gencline},
  {NULL,		0,	TZPUnknown,	0,			0}
};

ICAL_PROP_S alarm_prop[] = {
  {"ACTION",		6,	AlAction,	ical_cline_from_token,	ical_free_cline},
  {"TRIGGER",		7,	AlTrigger,	ical_cline_from_token,	ical_free_cline},
  {"DURATION",		8,	AlDuration,	ical_cline_from_token,	ical_free_cline},
  {"REPEAT",		6,	AlRepeat,	ical_cline_from_token,	ical_free_cline},
  {"DESCRIPTION",	11,	AlDescription,	ical_cline_from_token,	ical_free_cline},
  {"SUMMARY",		7,	AlSummary,	ical_cline_from_token,	ical_free_cline},
  {"ATTACH",		6,	AlAttach,	ical_gencline_from_token,	ical_free_gencline},
  {"ATTENDEE",		8,	AlAttendee,	ical_gencline_from_token,	ical_free_gencline},
  {NULL,		0,	AlUnknown,	0,			0}
};

/* some useful macros for character analysis */

#define ical_wspace(X)				\
	((X) == ' ' || (X) == '\t')

#define ical_name_allowed_char(X) 		\
	(((X) >= 'A' && (X) <= 'Z') ||		\
	 ((X) >= 'a' && (X) <= 'z') ||		\
	  (X) == '-' )

#define ical_control(X)				\
	(((X) >= 0x00 && (X) <= 0x08) ||	\
	 ((X) >= 0x0A && (X) <= 0x1F) ||	\
	  (X) == 0x7F)

#define ical_safe_char(X)			\
	(ical_non_ascii_valid(X) 		\
	 || ical_wspace(X)			\
	 || (X) == 0x21				\
	 || ((X) >= 0x23 && (X) <= 0x2B)	\
	 || ((X) >= 0x2D && (X) <= 0x39)	\
	 || ((X) >= 0x3C && (X) <= 0x7E))

#define ical_qsafe_char(X)			\
	(ical_non_ascii_valid((X)) 		\
	 || ical_wspace(X)			\
	 || (X) == 0x21				\
	 || ((X) >= 0x23 && (X) <= 0x7E))

#define ical_value_char(X)			\
	(ical_non_ascii_valid(X)		\
	 || ical_wspace(X)			\
	 || ((X) >= 0x21 && (X) <= 0x7E))

/* Finally, here begins the code. */

unsigned char *
ical_decode(char *text, unsigned short encoding)
{
  unsigned char *t;
  unsigned long callen;
  size_t tlen;
  if(encoding == ENCQUOTEDPRINTABLE){
     t = rfc822_qprint ((unsigned char *) text,strlen(text),&callen);
     if(t != NULL){
       tlen = strlen(text) + 1;
       strncpy(text, (char *) t, tlen);
       text[tlen - 1] = '\0';
       fs_give((void **) &t);
     }
  }
  return (unsigned char *) text;
}


/* Return code:
    0 - if no errors
   -1 - if an error occurred
   Args: a pointer to the text. If there is an error, the text is not modified.
 */
int
ical_remove_escapes(char **textp)
{
   char *text, *s, *t;
   int rv = 0;
   int escaped;
   size_t tlen;

   if(textp == NULL) return 0;

   t = cpystr(*textp); /* work on a copy of the text */
   tlen = strlen(*textp) + 1; 	/* and record its size */
   /* the variable text below points to the beginning of the filtered text */
   for (text = s = t, escaped = 0; rv == 0 && *s != '\0'; s++){
       if(*s == '\\' && escaped == 0){ 
	  escaped = 1;
	  continue;
       }
       if(escaped){
	  switch(*s){
	      case '\\':
	      case ',':
	      case ';':
		 *t++ = *s;
		 break;

	      case 'n':
	      case 'N':
		 *t++ = '\n';
		 break;
	      default: rv = -1;
		 break;
	  }
	  escaped = 0;
       }
       else *t++ = *s;
    }
    *t = '\0';	/* tie off filtered text */
    t = text;   /* reset t to the beginning */
    if(rv == 0){
      strncpy(*textp, t, tlen);	/* overwrite given text with filtered text */
      (*textp)[tlen - 1] = '\0';
    }
    fs_give((void **) &t);
    return rv;
}

void
ical_debug(char *fcn, char *text)
{
   char piece[50];
   strncpy(piece, text, 49);
   piece[sizeof(piece)-1] = '\0';
   dprint((2, "%s: %s\n", fcn, piece));
}

/***
 *** FREE MEMORY FUNCTIONS
 ***/

void 
ical_free_param(ICAL_PARAMETER_S **param)
{
  if(param == NULL || *param == NULL)
    return;

  if((*param)->name)  fs_give((void **) &(*param)->name);
  if((*param)->value) fs_give((void **) &(*param)->value);
  if((*param)->next)  ical_free_param(&(*param)->next);
  fs_give((void **)param);
}

void 
ical_free_cline(void **icv)
{
   ICLINE_S **ic = (ICLINE_S **) icv;

   if(ic == NULL || *ic == NULL)
     return;

   if((*ic)->token) fs_give((void **) &(*ic)->token);
   if((*ic)->param) ical_free_param(&(*ic)->param);
   if((*ic)->value) fs_give((void **) &(*ic)->value);
   fs_give(icv);
}

void
ical_free_gencline(void **giclpv)
{
  GEN_ICLINE_S **giclp = (GEN_ICLINE_S **) giclpv;

  if(giclp == NULL || *giclp == NULL) return;

  if((*giclp)->cline) ical_free_cline((void **) &(*giclp)->cline);
  if((*giclp)->next) ical_free_gencline((void **)  &(*giclp)->next);
  fs_give((void **)giclp);
}

void
ical_free_vcalendar(void **vcalpv)
{
  VCALENDAR_S **vcalp = (VCALENDAR_S **)vcalpv;

  if(vcalp == NULL || *vcalp == NULL) return;

  if((*vcalp)->prodid) ical_free_cline((void **) &(*vcalp)->prodid);
  if((*vcalp)->version) ical_free_cline((void **) &(*vcalp)->version);
  if((*vcalp)->calscale) ical_free_cline((void **) &(*vcalp)->calscale);
  if((*vcalp)->method) ical_free_cline((void **) &(*vcalp)->method);
  if((*vcalp)->uk_prop) ical_free_gencline((void **) &(*vcalp)->uk_prop);
  if((*vcalp)->comp){
     Cal_comp i;
     for(i = 0; i < VUnknown; i++)
	if((*vcalp)->comp[i]) (ical_comp[i].give)(&(*vcalp)->comp[i]);
     fs_give((void **) &(*vcalp)->comp);
  }
  if((*vcalp)->uk_comp) ical_free_unknown_comp(&(*vcalp)->uk_comp);
  fs_give(vcalpv);
}

void
ical_free_vevent(void **veventpv)
{
  VEVENT_S **veventp = (VEVENT_S **) veventpv;

  if(veventp == NULL || *veventp == NULL) return;

  ical_free_prop(&(*veventp)->prop, event_prop, EvUnknown);
  if((*veventp)->uk_prop) ical_free_gencline((void **) &(*veventp)->uk_prop);
  if((*veventp)->valarm) ical_free_valarm((void **) &(*veventp)->valarm);
  if((*veventp)->next) ical_free_vevent((void **) &(*veventp)->next);
  fs_give(veventpv);
}

void
ical_fs_give(void **x)
{
  if(x != NULL && *x != NULL)
    fs_give(x);
}

void
ical_free_rrule(void **rrulepv)
{
  RRULE_S **rrulep = (RRULE_S **) rrulepv;

  if(rrulep && *rrulep){
    ical_free_prop(&(*rrulep)->prop, rrule_prop, RRUnknown);
    ical_free_param(&(*rrulep)->param);
    fs_give(rrulepv);
  }
}

void
ical_free_weekday_list(void **wkdylv)
{
  BYWKDY_S **wkdyl = (BYWKDY_S **) wkdylv;

  if(wkdyl == NULL) return;

  if((*wkdyl)->next) 
     ical_free_weekday_list((void **) &(*wkdyl)->next);

  fs_give(wkdylv);
}


void
ical_free_vtodo(void **vtodopv)
{
}

void
ical_free_vjournal(void **vjournalpv)
{
}

void
ical_free_vfreebusy(void **vfbpv)
{
}

void
ical_free_prop(void ***propv, ICAL_PROP_S *aux_comp, int max)
{
  int i, j;

  if(propv == NULL || *propv == NULL) return;

  for(i = 0; i < max; i++)
     if((*propv)[i]){
	for(j = 0; aux_comp[j].prop != NULL && aux_comp[j].pos != i; j++);
	if(aux_comp[j].give) (aux_comp[j].give)(&(*propv)[i]);
     }
  fs_give((void **) propv);
}


void
ical_free_vtimezone(void **vtzpv)
{
  VTIMEZONE_S **vtzp = (VTIMEZONE_S **) vtzpv;
  TZ_comp i,j;

  if(vtzp == NULL || *vtzp == NULL) return;

  ical_free_prop(&(*vtzp)->prop, tz_comp, TZCUnknown);
  if((*vtzp)->uk_prop) ical_free_gencline((void **) &(*vtzp)->uk_prop);
  if((*vtzp)->standardc) ical_free_timezone((void **) &(*vtzp)->standardc);
  if((*vtzp)->daylightc) ical_free_timezone((void **) &(*vtzp)->daylightc);
  fs_give(vtzpv);
}

void
ical_free_timezone(void **tzpv)
{
  ICAL_TZPROP_S **tzp = (ICAL_TZPROP_S **) tzpv;

  if(tzp == NULL || *tzp == NULL) return;

  ical_free_prop(&(*tzp)->prop, tz_prop, TZPUnknown);
  if((*tzp)->uk_prop) ical_free_gencline((void **) &(*tzp)->uk_prop);
  if((*tzp)->next) ical_free_timezone((void **) &(*tzp)->next);
  fs_give(tzpv);
}

void
ical_free_valarm(void **valarmpv)
{
  VALARM_S **valarmp = (VALARM_S **) valarmpv;
  int i, j;

  if(valarmp == NULL || *valarmp == NULL) return;

  ical_free_prop(&(*valarmp)->prop, alarm_prop, AlUnknown);
  if((*valarmp)->uk_prop) ical_free_gencline((void **) &(*valarmp)->uk_prop);
  if((*valarmp)->next) ical_free_timezone((void **) &(*valarmp)->next);
  fs_give(valarmpv);
}

void
ical_free_unknown_comp(ICAL_S **icalp)
{
  int i;
  if(icalp == NULL || *icalp == NULL) return;
  for(i = 0; ical_comp[i].comp && strucmp((*icalp)->comp,ical_comp[i].comp); i++);
  if(ical_comp[i].give)
     (ical_comp[i].give)(&(*icalp)->value);
  else
     ical_free_gencline((void **) &(*icalp)->value);
  fs_give((void **)&(*icalp)->comp);
  ical_free_unknown_comp(&(*icalp)->next);
  ical_free_unknown_comp(&(*icalp)->branch);
  fs_give((void **)icalp);
}

char *
ical_unfold_line(char *line)
{
  int i, j;

  if(line == NULL)
    return NULL;

  for(i = 0, j = 0; line[j] != '\0';)
     switch(line[j]){
	case '\r': if(line[j+1] == '\n' && ical_wspace(line[j+2])){
		      j += 3;	/* get past white space */
		      continue;
		   }
	case '\n': if(ical_wspace(line[j+1])){
		      j += 2;	/* get past white space */
		      continue;
		   }
	default  : line[i++] = line[j++];
     }
  line[i] = '\0';
  return line;
}

ICAL_PARAMETER_S *
ical_get_parameter(char **line)
{
  ICAL_PARAMETER_S *param = NULL;
  char *s;
  
  if(line == NULL || *line == NULL)
    return NULL;

  for(s = *line; s && *s && ical_name_allowed_char(*s) ; s++);

  if(*s == '='){
    int quoted;
    char c;

    param = fs_get(sizeof(ICAL_PARAMETER_S));
    memset((void *)param, 0, sizeof(ICAL_PARAMETER_S));
    *s = '\0';
    param->name = cpystr(*line);
    *s = '=';
    *line = s+1;	/* step over '=' */
    quoted = **line == '"' ? 1 : 0;
    if(quoted != 0){
	for(s = ++*line; s && *s && ical_qsafe_char((unsigned char) *s); s++);
	if(*s != '"'){  /* error, do not parse this line */
	  ical_free_param(&param);
	  *line = strchr(s, ':');  /* reset line to closest ':' */
	  return NULL;
	}
    }
    else
	for(s = *line; s && *s && (ical_safe_char((unsigned char) *s)); s++);
    c = *s;
    *s = '\0';
    param->value  = cpystr(*line);
    *s = c;	/* restore character */
    *line = quoted ? s + 1 : s;

    if(**line == ';'){
      ++*line;
      param->next = ical_get_parameter(line);
    }
  }
  return param;
}

char *
ical_get_value(char **line)
{
  char *s, *t;

  if(line == NULL || *line == NULL)
    return NULL;

  for (s = *line; *s && ical_value_char((unsigned char) *s); s++);
  if(*s == '\r'){
    *s = '\0';
    t = cpystr(*line);
    *s = '\r';
    *line = s+2;
  }
  else{
    t = NULL;
    s = strchr(*line, '\r');
    if(s != NULL)
      *line = s + 2;
  }
  return t;
}

ICAL_PARAMETER_S *
ical_parameter_cpy(ICAL_PARAMETER_S *param)
{
   ICAL_PARAMETER_S *rv;

   if(param == NULL) return NULL;

   rv = fs_get(sizeof(ICAL_PARAMETER_S));
   memset((void *)rv, 0, sizeof(ICAL_PARAMETER_S));

   if(param->name)  rv->name  = cpystr(param->name);
   if(param->value) rv->value = cpystr(param->value);
   if(param->next)  rv->next  = ical_parameter_cpy(param->next);

   return rv;
}

ICLINE_S *
ical_cline_cpy(ICLINE_S *icl)
{
  ICLINE_S *rv;

  if(icl == NULL)
    return NULL;

  rv = fs_get(sizeof(ICLINE_S));
  memset((void *)rv, 0, sizeof(ICLINE_S));

  if(icl->token) rv->token = cpystr(icl->token);
  if(icl->param) rv->param = ical_parameter_cpy(icl->param);
  if(icl->value) rv->value = cpystr(icl->value);

  return rv;
}

/* Given a \r\n-ending line (called *text), isolate the occurrence 
 * of the token in that line.
 * Return the token, and modify the pointer to *text to point to the
 * end of the token. Modify sep to contain the character following
 * the token
 * ical-line = token ':'/';' rest of the line\r\n
 * on error return null, and set *text to the next line, if possible.
 */
char *
ical_isolate_token(char **text, char *sep)
{
   char *s, *t;

   for(t = s = *text; *t && ical_name_allowed_char(*s); s++);
				/* only followed by parameter or value */
   if(*s == ':' || *s == ';'){
      *sep = *s;
      *s = '\0';	/* isolate token at pointer s */
      *text = s;
   }
   else{		/* bad data - bail out of here */
      t = NULL;
      if(*s == '\0' || (s = strstr(s, "\r\n")) == NULL)
	*text = NULL;
      else	/* move to next line */
	*text = s + 2;
   }
   return t;
}


VCALENDAR_S *
ical_parse_text(char *text)
{
   char *s;
   VCALENDAR_S *vcal = NULL;

   ical_debug("ical_parse_text", text);
   ical_initialize();

   text = ical_unfold_line(text);
   for(s = text; s && *s != '\0'; s++){
	if(*s != 'B' && *s != 'b')
	  continue;
	if(!struncmp(s+1, "EGIN:VCALENDAR\r\n", 16)){
	   s += 17;	/* 17 = strlen("BEGIN:VCALENDAR\r\n") */
	   vcal = (VCALENDAR_S *) ical_parse_vcalendar(&s);
	   break;
	}
   }
   return vcal;
}

void *
ical_parse_time(void *ic_datep, char **text, char *token)
{
  struct tm *datep;
  ICLINE_S *icl; 

  datep = fs_get(sizeof(struct tm));
  icl = ical_parse_line(text, token);
  ical_parse_date(icl->value, datep);
  ical_free_cline((void **) &icl);
  ic_datep = (void *) datep;

  return ic_datep;
}

void *
ical_parse_interval(void *longvp, char *value)

{
  unsigned long *longp;

  longp  = fs_get(sizeof(unsigned long));
  *longp = atoi(value);
  longvp = (void *) longp;

  return longvp;
}


void *
ical_parse_offset(void *offsetv, char **text, char *token)
{
  ICLINE_S *icl;
  char *value;
  int h, m, *offset;

  offset = fs_get(sizeof(int));

  icl = ical_parse_line(text, token);

  if(*icl->value == '+' ||  *icl->value == '-')
    value = icl->value + 1;
  else
    value = icl->value;

  h = ical_get_number_value(value, 0, 2);
  m = ical_get_number_value(value, 2, 4);

  *offset = 60*(60*h + m);
  if(*icl->value == '-')
     *offset *= -1;

  ical_free_cline((void **) &icl);
  offsetv = (void *) offset;

  return offsetv;
}

/* This function processes the information in *text, and returns
 * a pointer to the information in iclp, but only if iclp is NULL
 * otherwise, it simply returns the current value and advances the
 * pointer to *text.
 * Call this function as follows
 *    rv = (cast here *) ical_cline_from_token((void *)rv, &text, token);
 */
void *
ical_cline_from_token(void *iclp, char **text, char *token)
{
   ICLINE_S *icl;

   ical_debug("ical_cline_from_token", *text);

   icl = ical_parse_line(text, token);

   if(iclp != NULL)
     ical_free_cline((void **)&icl);
   else
     iclp = (void *) icl;

   return iclp;
}

void *
ical_gencline_from_token(void *giclv, char **text, char *token)
{
  GEN_ICLINE_S *gicl= NULL;

  if(!struncmp(*text, token, strlen(token))){
     gicl = fs_get(sizeof(GEN_ICLINE_S));
     memset((void *) gicl, 0, sizeof(GEN_ICLINE_S));
     gicl->cline = ical_parse_line(text, token);
//     gicl->line = (ICLINE_S *) ical_cline_from_token((void *) gicl->cline, text, token);
     gicl->next = (GEN_ICLINE_S *) ical_gencline_from_token((void *) gicl->next, text, token);
  }

  if(giclv != NULL)
    ical_free_gencline((void **) &gicl);
  else
    giclv = (void *) gicl;

  return giclv;
}

/***
 *** PARSE COMPONENT FUNCTIONS
 ***/

void *
ical_parse_vcalendar(char **text)
{
  char *s, *t;
  char c;
  VCALENDAR_S *vcal;
  void *v;

  dprint((9, "ical_parse_vcalendar:\n"));
  ical_debug("ical_parse_vcalendar", *text);

  vcal = fs_get(sizeof(VCALENDAR_S));
  memset((void *) vcal, 0, sizeof(VCALENDAR_S));

  /* s must always point the the beginning of a line */
  for(s = *text; s && *s != '\0';){
     t = s; 
     s = ical_isolate_token(&t, &c);
     if(s == NULL){
	if(t != NULL)
	  s = t;
	continue;
     }

     *t = c;	/* restore character */
     if(s){	/* figure out the token */
	int ukn = 0;	/* unknown token */
	int i;
	switch(*s){
	   case 'B':
	   case 'b': if(!struncmp(s+1, "EGIN", 4)){
			s += 6;		/* 6 = strlen("BEGIN:") */
			for(i = 0; ical_comp[i].comp
				  && (struncmp(s, ical_comp[i].comp, ical_comp[i].len)
					|| struncmp(s + ical_comp[i].len, "\r\n", 2)); i++);

			if(ical_comp[i].parse){
			   s += ical_comp[i].len + 2;
		           v = (ical_comp[i].parse)(&s);
			   if(vcal->comp == NULL){
			     vcal->comp = fs_get((VUnknown+1)*sizeof(void *));
			     memset((void *) vcal->comp, 0, (VUnknown+1)*sizeof(void *));
			   }

			   if(vcal->comp[ical_comp[i].pos] == NULL)
			     vcal->comp[ical_comp[i].pos] = v;
			   else{
			     if((vcal->method && vcal->method->value
				  && strucmp(vcal->method->value, "PUBLISH"))
				|| struncmp(ical_comp[i].comp, "VEVENT", 6))
			        (ical_comp[i].give)(&v);
			     else{
				VEVENT_S *vevent = (VEVENT_S *) vcal->comp[VEvent];
				for(; vevent && vevent->next; vevent = vevent->next);
				vevent->next = v;
			     }
			   }
			} else {
			   v = (void *) ical_parse_unknown_comp(&s, 0);
			   if(vcal->uk_comp == NULL)
			      vcal->uk_comp = (ICAL_S *) v;
			   else{
			      ICAL_S *ic;
			      for(ic = vcal->uk_comp; ic && ic->branch; ic = ic->branch);
			      ic->branch = (ICAL_S *) v;
			   }
			}
		     } else ukn++;
		     break;

	   case 'C':
	   case 'c': if(!struncmp(s+1, "ALSCALE", 7)){
			v = (void *) vcal->calscale;
			v = ical_cline_from_token(v, &s, "CALSCALE");
			vcal->calscale = (ICLINE_S *) v;
		     }
		     else ukn++;
		     break;

	   case 'E':
	   case 'e': if(!struncmp(s+1, "ND", 2)){
			*t = c;
			s += 4;	  /* 4 = strlen("END:") */
			if(!struncmp(s, "VCALENDAR\r\n", 11)){
			   *text = s + 11;	/* 11 = strlen("VCALENDAR\r\n") */
			   return (void *) vcal;
			}
//			else ukn++; FIX THIS, this is not quite right
		     } else ukn++;
		     break;

	   case 'M':
	   case 'm': if(!struncmp(s+1, "ETHOD", 5)){
			v = (void *) vcal->method;
			v = ical_cline_from_token(v, &s, "METHOD");
			vcal->method = (ICLINE_S *) v;
		     }
		     else ukn++;
		     break;

	   case 'P':
	   case 'p': if(!struncmp(s+1, "RODID", 5)){
			v = (void *) vcal->prodid;
			v = ical_cline_from_token(v, &s, "PRODID");
			vcal->prodid = (ICLINE_S *) v;
		     }
		     else ukn++;
		     break;

	   case 'V':
	   case 'v': if(!struncmp(s+1, "ERSION", 6)){
			v = (void *) vcal->version;
			v = ical_cline_from_token(v, &s, "VERSION");
			vcal->version = (ICLINE_S *) v;
		     } else ukn++;
		     break;

	   default : ukn++;
		     break;
	} /* end of switch(*s) */
	if(ukn){
	  if(ical_buf_len < t - s){
	    fs_resize((void **)&ical_buf, t-s+1);
	    ical_buf_len = t-s;
	  }
	  *t = '\0';
	  strcpy(ical_buf, s);
	  *t = c;
	  if(vcal->uk_prop == NULL){
	    vcal->uk_prop = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)vcal->uk_prop, 0, sizeof(GEN_ICLINE_S));
	    vcal->uk_prop->cline = ical_parse_line(&s, ical_buf);
	  }
	  else{
	    GEN_ICLINE_S *gcl;
	    for (gcl = vcal->uk_prop; gcl && gcl->next; gcl = gcl->next);
	    gcl->next = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)gcl->next, 0, sizeof(GEN_ICLINE_S));
	    gcl->next->cline = ical_parse_line(&s, ical_buf);
	  }
	}
     } /* end of if(s) */
  }

  *text = s;

  /* ok, we have parsed the vcalendar, now parse some special properties */
  /* start by parsing dates */
  ical_set_date_vevent(vcal->comp[VEvent], vcal->comp[VTimeZone]);
  return (void *) vcal;
}

void *
ical_parse_vevent(char **text)
{
  char *s, *t;
  char c;
  VEVENT_S *vevent;

  ical_debug("ical_parse_vevent", *text);
  vevent = fs_get(sizeof(VEVENT_S));
  memset((void *)vevent, 0, sizeof(VEVENT_S));

  /* s must always point the the beginning of a line */
  for(s = *text; s && *s != '\0';){
     t = s; 
     s = ical_isolate_token(&t, &c);
     if(s == NULL){
	if(t != NULL)
	  s = t;
	continue;
     }
     *t = c;	/* restore separator */

     if(s){	/* figure out the token */
	int ukn = 0;	/* unknown token */
	if(!struncmp(s, "BEGIN", 5)){
	  s += 6;		/* 6 = strlen("BEGIN:") */
	  if(!struncmp(s, "VALARM\r\n", 8)){
	     s += 8; /* 8 = strlen("VALARM\r\n"); */
	     if(vevent->valarm == NULL)
	        vevent->valarm = ical_parse_valarm(&s); 
	     else{
	        VALARM_S *valrm;
	        for(valrm = vevent->valarm; valrm && valrm->next;
						valrm = valrm->next);
		valrm->next = ical_parse_valarm(&s);
	     }
	  } else {
	     ICAL_S *uk_comp = ical_parse_unknown_comp(&s, 0);
	     ical_free_unknown_comp(&uk_comp);
	  }
	} else if(!struncmp(s, "END", t-s-1)){
		s += 4;	  /* 4 = strlen("END:") */
		if(!struncmp(s, "VEVENT\r\n",8)){
		   *text = s + 8; /* 8 = strlen("VCALENDAR\r\n") */
		   return (void *) vevent;
		}
	} else{ Event_prop i;
		for(i = 0; i < EvUnknown; i++)
		   if(!struncmp(s, event_prop[i].prop, t-s))
		      break;
		if(event_prop[i].parse){
		   void *v;
		   if(vevent->prop == NULL){
		     vevent->prop = fs_get((EvUnknown+1)*sizeof(void *));
		     memset((void *)vevent->prop, 0, (EvUnknown+1)*sizeof(void *));
		   }
		   v = vevent->prop[event_prop[i].pos];
		   v = (event_prop[i].parse)(v , &s, event_prop[i].prop);
		   vevent->prop[event_prop[i].pos] = v;
		}
		else
		  ukn++;
	}

	if(ukn){
	  if(ical_buf_len < t - s){
	    fs_resize((void **)&ical_buf, t-s+1);
	    ical_buf_len = t-s;
	  }
	  *t = '\0';
	  strcpy(ical_buf, s);
	  *t = c;
	  if(vevent->uk_prop == NULL){
	    vevent->uk_prop = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)vevent->uk_prop, 0, sizeof(GEN_ICLINE_S));
	    vevent->uk_prop->cline = ical_parse_line(&s, ical_buf);
	  }
	  else{
	    GEN_ICLINE_S *gcl;
	    for (gcl = vevent->uk_prop; gcl && gcl->next; gcl = gcl->next);
	    gcl->next = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)gcl->next, 0, sizeof(GEN_ICLINE_S));
	    gcl->next->cline = ical_parse_line(&s, ical_buf);
	  }
	}
     } /* end of if(s) */
  }

  *text = s;
  return (void *) vevent;
}

void *
ical_parse_vtimezone(char **text)
{
  char *s, *t;
  char c;
  void *v;
  VTIMEZONE_S *vtz;

  ical_debug("ical_parse_vtimezone", *text);
  vtz = fs_get(sizeof(VTIMEZONE_S));
  memset((void *)vtz, 0, sizeof(VTIMEZONE_S));

  /* s must always point the the beginning of a line */
  for(s = *text; s && *s != '\0';){
     t = s; 
     s = ical_isolate_token(&t, &c);
     if(s == NULL){
	if(t != NULL)
	  s = t;
	continue;
     }
     *t = c;	/* restore separator */

     if(s){	/* figure out the token */
	int ukn = 0;	/* unknown token */
	if(!struncmp(s, "BEGIN", 5)){
	  s += 6;		/* 6 = strlen("BEGIN:") */
	  if(!struncmp(s, "STANDARD\r\n", 10)){
	     s += 10; /* 10 = strlen("STANDARD\r\n"); */
	     v = ical_parse_timezone(&s); 
	     if(vtz->standardc == NULL)
	        vtz->standardc = (ICAL_TZPROP_S *) v;
	     else{
		ICAL_TZPROP_S *dl;
		for(dl = vtz->standardc; dl && dl->next; dl = dl->next);
		dl->next = (ICAL_TZPROP_S *) v;
	     }
	  } else if(!struncmp(s, "DAYLIGHT\r\n", 10)){
	     s += 10; /* 10 = strlen("DAYLIGHT\r\n"); */
	     v = ical_parse_timezone(&s); 
	     if(vtz->daylightc == NULL)
	        vtz->daylightc = (ICAL_TZPROP_S *) v;
	     else{
		ICAL_TZPROP_S *dl;
		for(dl = vtz->daylightc; dl && dl->next; dl = dl->next);
		dl->next = (ICAL_TZPROP_S *) v;
	     }
	  } else {
	     ICAL_S *uk_comp = ical_parse_unknown_comp(&s, 0);
	     ical_free_unknown_comp(&uk_comp);
	  }
	} else if(!struncmp(s, "END", t-s-1)){
		s += 4;	  /* 4 = strlen("END:") */
		if(!struncmp(s, "VTIMEZONE\r\n",11)){
		   *text = s + 11; /* 11 = strlen("VTIMEZONE\r\n") */
		   return (void *) vtz;
		}
	} else{ TZ_comp i;
		for(i = 0; i < TZCUnknown; i++)
		   if(!struncmp(s, tz_comp[i].prop, t-s))
		      break;
		if(tz_comp[i].parse){
		   void *v;
		   if(vtz->prop == NULL){
		     vtz->prop = fs_get(TZCUnknown*sizeof(void *));
		     memset((void *)vtz->prop, 0, TZCUnknown*sizeof(void *));
		   }
		   v = vtz->prop[tz_comp[i].pos];
		   v = (tz_comp[i].parse)(v, &s, tz_comp[i].prop);
		   vtz->prop[tz_comp[i].pos] = v;
		}
		else
		  ukn++;
	}

	if(ukn){
	  if(ical_buf_len < t - s){
	    fs_resize((void **)&ical_buf, t-s+1);
	    ical_buf_len = t-s;
	  }
	  *t = '\0';
	  strcpy(ical_buf, s);
	  *t = c;
	  if(vtz->uk_prop == NULL){
	    vtz->uk_prop = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)vtz->uk_prop, 0, sizeof(GEN_ICLINE_S));
	    vtz->uk_prop->cline = ical_parse_line(&s, ical_buf);
	  }
	  else{
	    GEN_ICLINE_S *gcl;
	    for (gcl = vtz->uk_prop; gcl && gcl->next; gcl = gcl->next);
	    gcl->next = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)gcl->next, 0, sizeof(GEN_ICLINE_S));
	    gcl->next->cline = ical_parse_line(&s, ical_buf);
	  }
	}
     } /* end of if(s) */
  }

  *text = s;
  return (void *) vtz;
}

void *
ical_parse_timezone(char **text)
{
  char *s, *t;
  char c;
  ICAL_TZPROP_S *tzprop;

  ical_debug("ical_parse_timezone", *text);
  tzprop = fs_get(sizeof(ICAL_TZPROP_S));
  memset((void *)tzprop, 0, sizeof(ICAL_TZPROP_S));

  /* s must always point the the beginning of a line */
  for(s = *text; s && *s != '\0';){
     t = s; 
     s = ical_isolate_token(&t, &c);
     if(s == NULL){
	if(t != NULL)
	  s = t;
	continue;
     }
     *t = c;	/* restore separator */

     if(s){	/* figure out the token */
	int ukn = 0;	/* unknown token */
	if(!struncmp(s, "BEGIN", 5)){
	  ICAL_S *uk_comp;
	  s += 6;		/* 6 = strlen("BEGIN:") */
	  uk_comp = ical_parse_unknown_comp(&s, 0);
	  ical_free_unknown_comp(&uk_comp);
	} else if(!struncmp(s, "END", t-s-1)){
		s += 4;	  /* 4 = strlen("END:") */
		if(!struncmp(s, "STANDARD\r\n", 10) 
		   || !struncmp(s, "DAYLIGHT\r\n", 10)){
		   *text = s + 10; /* 10 = strlen("STANDARD\r\n") */
		   return (void *) tzprop;
		}
	} else{ TZ_prop i;
		for(i = 0; i < TZPUnknown; i++)
		   if(!struncmp(s, tz_prop[i].prop, t-s))
		      break;
		if(tz_prop[i].parse){
		   void *v;
		   if(tzprop->prop == NULL){
		     tzprop->prop = fs_get(TZPUnknown*sizeof(void *));
		     memset((void *)tzprop->prop, 0, TZPUnknown*sizeof(void *));
		   }
		   v = tzprop->prop[tz_prop[i].pos];
		   v = (tz_prop[i].parse)(v, &s, tz_prop[i].prop);
		   tzprop->prop[tz_prop[i].pos] = v;
		}
		else
		  ukn++;
	}

	if(ukn){
	  if(ical_buf_len < t - s){
	    fs_resize((void **)&ical_buf, t-s+1);
	    ical_buf_len = t-s;
	  }
	  *t = '\0';
	  strcpy(ical_buf, s);
	  *t = c;
	  if(tzprop->uk_prop == NULL){
	    tzprop->uk_prop = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)tzprop->uk_prop, 0, sizeof(GEN_ICLINE_S));
	    tzprop->uk_prop->cline = ical_parse_line(&s, ical_buf);
	  }
	  else{
	    GEN_ICLINE_S *gcl;
	    for (gcl = tzprop->uk_prop; gcl && gcl->next; gcl = gcl->next);
	    gcl->next = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)gcl->next, 0, sizeof(GEN_ICLINE_S));
	    gcl->next->cline = ical_parse_line(&s, ical_buf);
	  }
	}
     } /* end of if(s) */
  }

  *text = s;
  return (void *) tzprop;
}

void *
ical_parse_valarm(char **text)
{
  char *s, *t;
  char c;
  VALARM_S *valarm;

  ical_debug("ical_parse_valarm", *text);
  valarm = fs_get(sizeof(VALARM_S));
  memset((void *)valarm, 0, sizeof(VALARM_S));

  /* s must always point the the beginning of a line */
  for(s = *text; s && *s != '\0';){
     t = s; 
     s = ical_isolate_token(&t, &c);
     if(s == NULL){
	if(t != NULL)
	  s = t;
	continue;
     }
     *t = c;	/* restore separator */

     if(s){	/* figure out the token */
	int ukn = 0;	/* unknown token */
	if(!struncmp(s, "BEGIN", 5)){
	  ICAL_S *uk_comp;
	  s += 6;		/* 6 = strlen("BEGIN:") */
	  uk_comp = ical_parse_unknown_comp(&s, 0);
	  ical_free_unknown_comp(&uk_comp);
	} else if(!struncmp(s, "END", t-s-1)){
		s += 4;	  /* 4 = strlen("END:") */
		if(!struncmp(s, "VALARM\r\n", 8)){
		   *text = s + 8; /* 8 = strlen("VALARM\r\n") */
		   return (void *) valarm;
		}
	} else{ Alarm_prop i;
		for(i = 0; i < AlUnknown; i++)
		   if(!struncmp(s, alarm_prop[i].prop, t-s))
		      break;
		if(alarm_prop[i].parse){
		   void *v;
		   if(valarm->prop == NULL){
		     valarm->prop = fs_get((AlUnknown+1)*sizeof(void *));
		     memset((void *)valarm->prop, 0, (AlUnknown+1)*sizeof(void *));
		   }
		   v = valarm->prop[alarm_prop[i].pos];
		   v = (alarm_prop[i].parse)(v, &s, alarm_prop[i].prop);
		   valarm->prop[alarm_prop[i].pos] = v;
		}
		else
		  ukn++;
	}

	if(ukn){
	  if(ical_buf_len < t - s){
	    fs_resize((void **)&ical_buf, t-s+1);
	    ical_buf_len = t-s;
	  }
	  *t = '\0';
	  strcpy(ical_buf, s);
	  *t = c;
	  if(valarm->uk_prop == NULL){
	    valarm->uk_prop = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)valarm->uk_prop, 0, sizeof(GEN_ICLINE_S));
	    valarm->uk_prop->cline = ical_parse_line(&s, ical_buf);
	  }
	  else{
	    GEN_ICLINE_S *gcl;
	    for (gcl = valarm->uk_prop; gcl && gcl->next; gcl = gcl->next);
	    gcl->next = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)gcl->next, 0, sizeof(GEN_ICLINE_S));
	    gcl->next->cline = ical_parse_line(&s, ical_buf);
	  }
	}
     } /* end of if(s) */
  }

  *text = s;
  return (void *) valarm;
}

void *
ical_parse_vtodo(char **text)
{
 return NULL;
}

void *
ical_parse_vjournal(char **text)
{
  return NULL;
}

void *
ical_parse_vfreebusy(char **text)
{
  return NULL;
}

ICAL_S *
ical_parse_generic_comp(char **text, int level)
{
  ICAL_S *ical;
  char *s, *t;
  char *token = NULL;
  GEN_ICLINE_S *gcl = NULL;
  char c;

  ical_debug("ical_parse_generic_comp", *text);
  ical = fs_get(sizeof(ICAL_S));
  memset((void *)ical, 0, sizeof(ICAL_S));

  ical->comp = ical_get_value(text);
  token = fs_get(strlen(ical->comp) + 2 + 1);
  sprintf(token, "%s\r\n", ical->comp);	/* this is allocated memory */

  /* s must always point the the beginning of a line */
  for(s = *text; s && *s != '\0';){
     t = s; 
     s = ical_isolate_token(&t, &c);
     if(s == NULL){
	if(t != NULL)
	  s = t;
	continue;
     }

     *t = c;	/* restore character */
     if(s){	/* figure out the token */
	int ukn = 0;	/* unknown token */
	switch(*s){
	   case 'B':
	   case 'b': if(!struncmp(s+1, "EGIN", 4)){
			s += 6;		/* 6 = strlen("BEGIN:") */
			if(ical->next ==  NULL)
			   ical->next = ical_parse_unknown_comp(&s, level+1);
			else{
			   ICAL_S *b;
			   int i;

			   for(i = 0, b = ical; i <= level && b && b->next; b = b->next, i++);
			   if(b->branch == NULL)
			      b->branch = ical_parse_unknown_comp(&s, level+1);
			   else {
			      for(; b && b->branch; b = b->branch);
			      b->branch = ical_parse_unknown_comp(&s, level+1);
			   }
			}
		     } else ukn++;
		     break;

	   case 'E':
	   case 'e': if(!struncmp(s+1, "ND", 2)){
			*t = c;
			s += 4;	  /* 4 = strlen("END:") */
			if(!struncmp(s, token, strlen(token))){
			   *text = s + strlen(token);
			   ical->value = (void *) gcl;
			   return ical;
			}
		     } else ukn++;
		     break;

	   default : ukn++;
		     break;
	} /* end of switch(*s) */
	if(ukn){
	  if(ical_buf_len < t - s){
	    fs_resize((void **)&ical_buf, t-s+1);
	    ical_buf_len = t-s;
	  }
	  *t = '\0';
	  strcpy(ical_buf, s);
	  *t = c;
	  if(gcl == NULL){
	    gcl = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)gcl, 0, sizeof(GEN_ICLINE_S));
	    gcl->cline = ical_parse_line(&s, ical_buf);
	  }
	  else{
	    GEN_ICLINE_S *gencl;
	    for (gencl = gcl; gencl && gencl->next; gencl = gencl->next);
	    gencl->next = fs_get(sizeof(GEN_ICLINE_S));
	    memset((void *)gencl->next, 0, sizeof(GEN_ICLINE_S));
	    gencl->next->cline = ical_parse_line(&s, ical_buf);
	  }
	}
     } /* end of if(s) */
  }

  ical->value = (void *) gcl;
  *text = s;
  return ical;
}

ICAL_S *
ical_parse_unknown_comp(char **text, int level)
{
   ICAL_S *ical;
   int i;

   ical_debug("ical_parse_unknown_comp", *text);
   for(i = 0; ical_comp[i].comp 
		&& (struncmp(*text, ical_comp[i].comp, ical_comp[i].len)
		    || struncmp(*text + ical_comp[i].len, "\r\n", 2)); i++);

   if(ical_comp[i].parse){
     *text += ical_comp[i].len + 2;
     ical = fs_get(sizeof(ICAL_S));
     memset((void *)ical, 0, sizeof(ICAL_S));
     ical->comp = cpystr(ical_comp[i].comp);
     ical->value = (ical_comp[i].parse)(text);
   } else 
      ical = ical_parse_generic_comp(text, level);

   return ical;
}

ICLINE_S *
ical_parse_line(char **text, char *name)
{
  ICLINE_S *ic;
  char *s = *text;

  ic = fs_get(sizeof(ICLINE_S));
  memset((void *)ic, 0, sizeof(ICLINE_S));

  ic->token = cpystr(name);
  s += strlen(name);
  if(*s == ';'){
     s++;
     ic->param = ical_get_parameter(&s);
  }
  if(*s == ':'){
     s++;
     ic->value = ical_get_value(&s);
  }

  *text = s;
  return ic;
}

/***
 *** PARSE PROPERTY FUNCTIONS
 ***/

void *
ical_parse_freq(void *fvalp, char *text)
{
  Freq_value *fval;

  fval = fs_get(sizeof(Freq_value));

  *fval = FUnknown;

  if(text == NULL) return fvalp;

  if(!strucmp(text, "SECONDLY")) *fval = FSecondly;
  else if(!strucmp(text, "MINUTELY")) *fval = FMinutely;
  else if(!strucmp(text, "HOURLY")) *fval = FHourly;
  else if(!strucmp(text, "DAILY")) *fval = FDaily;
  else if(!strucmp(text, "WEEKLY")) *fval = FWeekly;
  else if(!strucmp(text, "MONTHLY")) *fval = FMonthly;
  else if(!strucmp(text, "YEARLY")) *fval = FYearly;

  fvalp = (void *) fval;

  return fvalp;
}

void *
ical_parse_until(void *Tmp, char *text)
{
   struct tm *Tm;

   if(text != NULL){
     Tm = fs_get(sizeof(struct tm));
     ical_parse_date(text, Tm);
     Tmp = (void *) Tm;
   }

   return Tmp;
}

void *
ical_parse_count(void *countp, char *text)
{
  int *count;

  if(text != NULL){
    count = fs_get(sizeof(int));
    *count = atoi(text);
    countp = (void *) count;
  }

  return countp;
}

void *
ical_parse_weekday_list(void *bywkdyp, char *wklist)
{
  BYWKDY_S *bywkdy, *w;
  char *s, *t, c;
  int done;
  size_t len;

  bywkdy = NULL;
  bywkdyp = (void *) bywkdy;

  if(wklist == NULL) return bywkdyp;

  done = 0;
  for(t = s = wklist; done == 0; s++){
    if(*s != ',' && *s != '\0')
      continue;
    c = *s;
    if(c == ',')
      *s = '\0';
    else  /* c == '\0' */
      done++;
    len = strlen(t);
    if(len > 1){
      for(w = bywkdy; w && w->next; w =  w->next);
      w = fs_get(sizeof(BYWKDY_S));
      memset((void *)w, 0, sizeof(BYWKDY_S));
      if(!strucmp(t+len-2, "SU")) w->wd = Sunday;
      else if(!strucmp(t+len-2, "MO")) w->wd = Monday;
      else if(!strucmp(t+len-2, "TU")) w->wd = Tuesday;
      else if(!strucmp(t+len-2, "WE")) w->wd = Wednesday;
      else if(!strucmp(t+len-2, "TH")) w->wd = Thursday;
      else if(!strucmp(t+len-2, "FR")) w->wd = Friday;
      else if(!strucmp(t+len-2, "SA")) w->wd = Saturday;
//      t[len - 2] = '\0';
      if(*t != '\0')
	w->value = strtoul(t, &t, 10);
      if(bywkdy == NULL)
	bywkdy = w;
    }
    *s = c;
    if(*s == ',')
      t = s + 1;
  }

  if(bywkdyp)  
    ical_free_weekday_list((void **)&bywkdy);
  else
    bywkdyp = (void *) bywkdy;

  return bywkdyp;
}

void *
ical_parse_number_list(void *bynop, char *nolist)
{
  BYWKDY_S *byno, *n;
  char *s, *t, c;
  int done = 0;

  byno = NULL;
  bynop = (void *) byno;

  if(nolist == NULL) return bynop;

  for(t = s = nolist; done == 0; s++){
    if(*s != ',' && *s != '\0')
      continue;
    c = *s;
    if(c == ',')
      *s = '\0';
    else  /* c == '\0' */
      done++;

    for(n = byno; n && n->next; n = n->next);
    n = fs_get(sizeof(BYWKDY_S));
    memset((void *)n, 0, sizeof(BYWKDY_S));
    n->value = strtoul(t, &t, 10);
    if(byno == NULL)
      byno = n;
    *s = c;
    if(*s == ',')
      t = s + 1;
  }

  if(bynop)
    ical_free_weekday_list((void **)&byno);
  else
    bynop = (void *) byno;

  return bynop;
}

void *
ical_parse_rrule(void *rrulep, char **text, char *token)
{
  RRULE_S *rrule;
  ICLINE_S *icl;
  char *s;
  ICAL_PARAMETER_S *param, *p;
  int i;

  if(text == NULL || *text == NULL || struncmp(*text, "RRULE", 5))
    return rrulep;

  rrule = fs_get(sizeof(RRULE_S));
  memset((void *) rrule, 0, sizeof(RRULE_S));

  /* recurring rules are special. First, we parse the icline that contains it */
  icl = ical_parse_line(text, token);

  /* now we copy the parameters that it contains */
  rrule->param = ical_parameter_cpy(icl->param);

  /* then we parse icl->value as if it was a parameter */
  s = icl->value;
  param = ical_get_parameter(&s);

  /* now we check which values were given, and fill the prop array */
  rrule->prop = fs_get((RRUnknown+1)*sizeof(void *));
  memset((void *) rrule->prop, 0, (RRUnknown+1)*sizeof(void *));

  for(p = param; p != NULL; p = p->next){
     for(i = 0; rrule_prop[i].prop != NULL && strucmp(p->name, rrule_prop[i].prop); i++);
     if(rrule_prop[i].parse){
	void *v = rrule->prop[rrule_prop[i].pos];
	v = (rrule_prop[i].parse)(v, p->value);
        rrule->prop[rrule_prop[i].pos] = v;
     }
  }
  rrule->prop[RRUnknown] = NULL;

  ical_free_param(&param);
  ical_free_cline((void **)&icl);

  if(rrulep)
    ical_free_rrule((void **)&rrule);
  else
    rrulep = (void *) rrule;

  return rrulep;
}

/*** UTF-8 for ICAL ***/

int
ical_non_ascii_valid(unsigned char c)
{
  static unsigned char icu[6];
  static int utf8_len = 0;
  static int utf8_type = 0;
  int rv;

  if(utf8_len == 0)
    utf8_type = (c >= 0xF0 && c <= 0xF4) 
		? 4 : (c >= 0xE0 && c <= 0xEF)
			? 3 : (c >= 0xC2 && c <= 0xDF)
				? 2 : 0;

  if(utf8_type == 0)
     return 0;

  icu[utf8_len++] = c;	/* count it */

  if(utf8_type == 2){
     if(utf8_len < 2)
	rv = NEED_MORE;
     else if(utf8_len == 2){
	rv = (icu[0] >= 0xC2 && icu[0] <= 0xDF) 
		&& (icu[1] >= 0x80 && icu[1] <= 0xBF) ? UTF8_COMPLETE : 0;
	utf8_len = 0;
     }
  } else if (utf8_type == 3){
       if(utf8_len < 3)
	  rv = NEED_MORE;
       else{
	  if(icu[0] == 0xE0)
	    rv = (icu[1] >= 0xA0 && icu[1] <= 0xBF) 
		&& (icu[2] >= 0x80 && icu[2] <= 0xBF) ? UTF8_COMPLETE : 0;
	  else if(icu[0] >= 0xE1 && icu[0] <= 0xEC)
	    rv = (icu[1] >= 0x80 && icu[1] <= 0xBF) 
		&& (icu[2] >= 0x80 && icu[2] <= 0xBF) ? UTF8_COMPLETE : 0;
	  else if(icu[0] == 0xED)
	    rv = (icu[1] >= 0x80 && icu[1] <= 0x9F) 
		&& (icu[2] >= 0x80 && icu[2] <= 0xBF) ? UTF8_COMPLETE : 0;
	  else if(icu[0] >= 0xE1 && icu[0] <= 0xEC)
	    rv = (icu[1] >= 0x80 && icu[1] <= 0xBF) 
		&& (icu[2] >= 0x80 && icu[2] <= 0xBF) ? UTF8_COMPLETE : 0;
	  utf8_len = 0;
       }
  } else if (utf8_type == 4){
       if(utf8_len < 4)
	  rv = NEED_MORE;
       else{
	  if(icu[0] == 0xF0)
	    rv = (icu[1] >= 0x90 && icu[1] <= 0xBF) 
		&& (icu[2] >= 0x80 && icu[2] <= 0xBF)
		&& (icu[3] >= 0x80 && icu[3] <= 0xBF) ? UTF8_COMPLETE : 0;
	  else if(icu[0] >= 0xF1 && icu[0] <= 0xF3)
	    rv = (icu[1] >= 0x80 && icu[1] <= 0xBF) 
		&& (icu[2] >= 0x80 && icu[2] <= 0xBF)
		&& (icu[3] >= 0x80 && icu[3] <= 0xBF) ? UTF8_COMPLETE : 0;
	  else if(icu[0] == 0xF4)
	    rv = (icu[1] >= 0x80 && icu[1] <= 0x8F) 
		&& (icu[2] >= 0x80 && icu[2] <= 0xBF)
		&& (icu[3] >= 0x80 && icu[3] <= 0xBF) ? UTF8_COMPLETE : 0;
	  utf8_len = 0;
       }
  }
  return rv;
}

int
ical_get_number_value(char *value, int beg_pos, int end_pos)
{
   char c, *err;
   int rv;

   c = value[end_pos];
   value[end_pos] = '\0';
   rv = strtoul(value + beg_pos, &err, 10);
   if(err != NULL && *err != '\0') return -1;
   value[end_pos] = c;
   return rv;
}

void
ical_free_duration(ICAL_DURATION_S **ic_d)
{
  if(ic_d == NULL || *ic_d == NULL)
    return;

  if((*ic_d)->next) ical_free_duration(&(*ic_d)->next);
  fs_give((void **)ic_d);
}

/* returns 0 if no error, -1 if some error */
int
ical_parse_duration(char *value, ICAL_DURATION_S *ic_d)
{
   int i, j = 0, rv = 0;

   if(value == NULL || ic_d == NULL) return -1;

   memset((void *)ic_d, 0, sizeof(ICAL_DURATION_S));

   if(value[i = 0] == '-'){
     i++;
     ic_d->sign = 1;
   } else if(value[i] == '+')
     i++;

   if(value[i++] == 'P'){
      for(j = i; value[j] != '\0' && value[j] != ','; j++){
	if(!isdigit(value[j]))
	  switch(value[j]){
	   case 'W': ic_d->weeks = ical_get_number_value(value, i, j-1);
		     i = ++j;
		     break;
	   case 'D': ic_d->days = ical_get_number_value(value, i, j-1);
		     i = ++j;
		     break;
	   case 'H': ic_d->hours = ical_get_number_value(value, i, j-1);
		     i = ++j;
		     break;
	   case 'M': ic_d->minutes = ical_get_number_value(value, i, j-1);
		     i = ++j;
		     break;
	   case 'S': ic_d->seconds = ical_get_number_value(value, i, j-1);
		     i = ++j;
		     break;
	   case 'T': i = j + 1;
		     break;
	   default:  rv = -1;
		     break;
	  }
      }
   }
   else
     rv = -1;

   if(value[j++] == ','){
     ICAL_DURATION_S next;
     rv = ical_parse_duration(value+j, &next);
     ic_d->next = &next;
   }

   return rv;
}

/* return -1 if any error,
           0 if value has the DATE-TIME form
           1 if value has the DATE form only
	   2 if value has the DATE-TIME form and is in GMT.
 */
int
ical_parse_date(char *value, struct tm *t)
{
   int i, rv;
   struct tm Tm;

   rv = -1;
   if(t == NULL) return rv;
   memset((void *)&Tm, 0, sizeof(struct tm));

   if(value == NULL) return rv;

   rv = 0;	/* assume DATE-TIME format */
   /* a simple check for the format of the string */
   for(i = 0; isdigit(value[i]); i++);
   if (i == 8 && value[i] == '\0')
       rv = 1;	
   else
      if (i != 8 || value[i++] != 'T') return -1;
   if(rv == 0) {
     for(; isdigit(value[i]); i++);
     if(i != 15 || (value[i] != '\0' && (value[i] != 'Z' || value[i+1] != '\0')))
        return -1;
     if(i == 15 && value[i] == 'Z')
	rv = 2;
   }

   Tm.tm_year = ical_get_number_value(value, 0, 4) - 1900;
   Tm.tm_mon  = ical_get_number_value(value, 4, 6) - 1;
   Tm.tm_mday = ical_get_number_value(value, 6, 8);
   if(rv != 1){
     Tm.tm_hour = ical_get_number_value(value, 9, 11);
     Tm.tm_min  = ical_get_number_value(value, 11, 13);
     Tm.tm_sec  = ical_get_number_value(value, 13, 15);
     Tm.tm_isdst = ICAL_DST_UNKNOWN;
   }
   else
     Tm.tm_isdst = -1;
   *t = Tm;

   return (t->tm_mon > 11 || t->tm_mon < 0 
	   || t->tm_mday > 31 || t->tm_mday < 0 
	   || t->tm_hour > 23 || t->tm_hour < 0
	   || t->tm_min > 59 || t->tm_min < 0 
	   || t->tm_sec > 60 || t->tm_sec < 0) 
	    ? - 1 : rv;
}

void
ical_set_date(ICLINE_S *icl, VTIMEZONE_S *vtz)
{
   int date_form;	/* date forms from section 3.3.4 in RFC 5545 */
   ICAL_PARAMETER_S *param;
   char *tz = NULL;
   struct tm ic_date;
   time_t t;

   if(icl == NULL) return;

   for(param = icl->param; param != NULL; param = param->next)
     if(!strucmp(param->name, "TZID"))
	tz = param->value;

   if(tz != NULL) 
     date_form = 3;	/* local time with timezone */
   else if(icl->value[strlen(icl->value)-1] == 'Z')
     date_form = 2;	/* utc time */
   else date_form = 1;	/* local time */

   ical_parse_date(icl->value, &ic_date);
   ic_date.tm_wday = ical_day_of_week(ic_date);	/* find out day of the week */

   switch(date_form){
      case 1: break;
      case 2: ical_adjust_date(&ic_date, vtz);
	      break;
      case 3: break;
      default: alpine_panic ("Impossible date_form");
   }
}

ICAL_TZPROP_S *
ical_std_or_daylight(struct tm *date, VTIMEZONE_S *vtz)
{
  struct tm standard, daylight;
  ICLINE_S *tzid = (ICLINE_S *) vtz->prop[TZCid];

// standard = daylight;

  return NULL;
}



/* adjusts time to given time zone */
void
ical_adjust_date(struct tm *date, VTIMEZONE_S *vtz)
{
  char *tzname = NULL;
  ICLINE_S *icl;
  ICAL_TZPROP_S *cur_std_day;

  if(vtz == NULL)
    return;

  if(vtz->prop){
    if((icl = (ICLINE_S *)vtz->prop[TZCid]) != NULL)
	tzname = cpystr(icl->value);
  }

  cur_std_day = ical_std_or_daylight(date, vtz);
}

void
ical_set_date_vevent(void *veventv, void *vtzv)
{
   VEVENT_S *vevent = (VEVENT_S *) veventv;
   VTIMEZONE_S *vtz = (VTIMEZONE_S *) vtzv;

   if(vevent){
     ical_set_date(vevent->prop[EvDtstamp], vtz);
     ical_set_date(vevent->prop[EvDtstart], vtz);
     ical_set_date(vevent->prop[EvDtend], vtz);
   }
}

#define LEAP_YEAR(X)  ((((X) % 4 == 0) 					\
			&& (((X) % 100 != 0) || ((X) % 400 == 0)))	\
			|| (X) == 1700)

#define CAL_OFFSET(X) (((X) == 1752) ? 5 : (LEAP_YEAR((X)) ? 2 : 1))

/* given a year, after day_zero,  return the day
 * of the week of the first of january of that year. On error, 
 * return a negative number.
 * Assumption: day_zero is the date of january 1, of some year.
 */
int
ical_january_first(int year)
{
  int i, january_first;

  if(year < day_zero.tm_year) return -1;	/* not supported */

  year += 1900;
  january_first = day_zero.tm_wday;
  for(i = 1900 + day_zero.tm_year + 1; i <= year; i++)
     january_first += CAL_OFFSET(i-1);

  return january_first % 7;
}

/* given a month, week day, and year, return all days of the month
 * that have that day as the week day. For example, return all
 * sundays in november 2012.
 */
int *
ical_day_from_week(int month, Weekday day, int year)
{
  int *rv = NULL;
  int fday, nday;
  Weekday wday;
  int i;

  fday = ical_first_of_month(month, year);
  year += 1900;		/* restore year */
  if(year == 1752 && month == 8){
	fday = 9;
  } else {
     for(nday = 1, wday = (Weekday) fday; wday != day; wday = (wday+1) % 7, nday++)
	;
     rv = fs_get(6*sizeof(int));
     memset((void *) rv, 0, 6*sizeof(int));
     for(i = 0; nday <= month_len[month]; i++){
	rv[i] = nday;
	nday += 7;
     }
     if(LEAP_YEAR(year) && month == 1 && nday == 29)
	rv[i] = nday;
  }

  return rv;
}


/* given a month and a year, return the weekday of the first of the
 * month in that year.
 * return value: on error -1, otherwise the day of the week.
 */
int
ical_first_of_month(int month, int year)
{
 int i, d;

 if((d = ical_january_first(year)) < 0)
   return -1;

 year += 1900;
 for(i = 0; i < month; i++)
   d += month_len[i];

 if(LEAP_YEAR(year) && month >= 2)
   d += 1;

 if(year == 1752 && month >= 9)
   d -= 11;

 return d % 7;
}

/* given a day, month and year, return the weekday of that day
 * return value: on error -1, otherwise the day of the week.
 */
int
ical_day_of_week(struct tm date)
{
 int d;

 if((d = ical_first_of_month(date.tm_mon, date.tm_year)) < 0)
   return -1;

 d += date.tm_mday - 1;

 if(date.tm_year + 1900 == 1752){
   if(date.tm_mday > 2 && date.tm_mday < 14)
     return -1;
   if(date.tm_mday >= 14)
     d -= 11;
 }
 return d % 7;
}


/* given an initial date dtstart, and a recurring rule, rrule, 
 * adjust the date to the first date on the same year, when
 * the rule actually starts
 */
struct tm
adjust_date_rrule(struct tm *dtstart, RRULE_S *rrule)
{
  struct tm t;

  memset((void *) &t, 0, sizeof(struct tm));
  t.tm_year = dtstart->tm_year;		/* same year */
  if(rrule->prop[RRFreq]){
  }
  if(rrule->prop[RRCount]){
  }
  else if(rrule->prop[RRInterval]){
  }
  if(rrule->prop[RRBysecond]){
     BYWKDY_S *sec = (BYWKDY_S *) rrule->prop[RRBysecond], *seco;
     for (seco = sec; seco != NULL; seco = seco->next)
        if(seco == sec) t.tm_sec = seco->value;
	else if (seco->value < t.tm_sec)
	   t.tm_sec = seco->value;
  }
  if (rrule->prop[RRByminute]){
     BYWKDY_S *sec = (BYWKDY_S *) rrule->prop[RRByminute], *seco;
     for (seco = sec; seco != NULL; seco = seco->next)
        if(seco == sec) t.tm_min = seco->value;
	else if (seco->value < t.tm_sec)
	   t.tm_min = seco->value;
  }
  if (rrule->prop[RRByhour]){
     BYWKDY_S *sec = (BYWKDY_S *) rrule->prop[RRByhour], *seco;
     for (seco = sec; seco != NULL; seco = seco->next)
        if(seco == sec) t.tm_hour = seco->value;
	else if (seco->value < t.tm_sec)
	   t.tm_hour = seco->value;
  }
  if (rrule->prop[RRByday]){
  }
  if (rrule->prop[RRByweekno]){
  }
  if (rrule->prop[RRBymonthday]){
  }
  if (rrule->prop[RRByyearday]){
  }
  if (rrule->prop[RRByweekno]){
  }
  if (rrule->prop[RRBymonth]){
     BYWKDY_S *m = (BYWKDY_S *) rrule->prop[RRBymonth], *mo;
     for (mo = m; mo != NULL; mo = mo->next)
        if(mo == m) t.tm_mon = mo->value - 1;
	else if (mo->value - 1 < t.tm_mon)
	   t.tm_mon = mo->value - 1;
  }
  if (rrule->prop[RRBysetpos]){
  }
  if (rrule->prop[RRWkst]){
  }
  return t;
}

void
ical_initialize(void)
{
   static int inited = 0;

   if(inited != 0)
     return;

   ical_buf_len = 1024;
   ical_buf = fs_get(ical_buf_len+1);

   memset((void *) &day_zero, 0, sizeof(struct tm));
   day_zero.tm_year = 1601 - 1900;
   day_zero.tm_mday = 1;
   day_zero.tm_wday = 4;

   inited++;
}

/* At this time, we are going to print the date in 24 hour format
 * if there is no string for AM or PM, but we use AM or PM when available.
 * We plan to make this user configurable, but not today...
 */
void
ical_date_time (char *tmp, size_t len, struct tm *ic_datep)
{
  /* test of the AM/PM string is available */
  our_strftime(tmp, len, "%p", ic_datep);

  if(tmp[0])
    our_strftime(tmp, len, "%a %x %I:%M %p", ic_datep);
  else
    our_strftime(tmp, len, "%a %x %H:%M", ic_datep);
}

/* If the icline has a TZID parameter, return its value, otherwise, return 
 * NULL. Returned value freed by caller.
 */
char *
ical_get_tzid(ICAL_PARAMETER_S *param)
{
  char *tzid = NULL;

  if(param == NULL)
    return tzid;

  if(strucmp(param->name, "TZID") == 0)
    tzid = cpystr(param->value);
  else
    tzid = ical_get_tzid(param->next);

  return tzid;
}

/* we create a summary of the event, and pass that back as
   an ical parameter
 */
VEVENT_SUMMARY_S *
ical_vevent_summary(VCALENDAR_S *vcal)
{
  VEVENT_SUMMARY_S *rv, *vsummary= NULL;
  ICLINE_S *method;
  VEVENT_S *vevent;
  GEN_ICLINE_S *gicl;
  ICLINE_S *icl;
  char *k;

  if(vcal == NULL) return NULL;

  method = vcal->method;

  vevent = (VEVENT_S *) vcal->comp[VEvent]; 
  if(vevent == NULL || vevent->prop == NULL)
    return NULL;

  for(vevent = (VEVENT_S *) vcal->comp[VEvent]; 
	vevent != NULL && vevent->prop != NULL; 
	vevent = vevent->next, rv = rv->next){

     rv = fs_get(sizeof(VEVENT_SUMMARY_S));
     memset((void *) rv, 0, sizeof(VEVENT_SUMMARY_S));

     if(method != NULL && !strucmp(method->value, "CANCEL"))
	rv->cancel++;

     if((icl = (ICLINE_S *) vevent->prop[EvPriority]) != NULL)
	rv->priority = atoi(icl->value);
 
     if((icl = (ICLINE_S *) vevent->prop[EvSummary]) != NULL){
	rv->summary = cpystr(icl->value ? icl->value : _("No Summary"));
	ical_remove_escapes(&rv->summary);
     }

     if((icl = (ICLINE_S *) vevent->prop[EvClass]) != NULL)
	rv->class = cpystr(icl->value ? icl->value : _("PUBLIC"));
     else
	rv->class = cpystr(_("PUBLIC"));

     if((icl = (ICLINE_S *) vevent->prop[EvOrganizer]) != NULL){
        char *cn, *sender, *address;
        ICAL_PARAMETER_S *param;

        cn = sender = address = NULL;
        for(param = icl->param; param != NULL; param = param->next)
	  if(!strucmp(param->name, "CN"))
	    cn = param->value;
	  else if(!strucmp(param->name, "SENT-BY"))
	    sender = param->value;

	if(sender != NULL){
	  if(!struncmp(sender, "MAILTO:", 7))
	    sender += 7;
	  utf8_snprintf(tmp_20k_buf, SIZEOF_20KBUF, "<%s>", sender);
	  rv->sender = cpystr(tmp_20k_buf);
	}

	if((address = icl->value) != NULL){
	  if(!struncmp(address, "MAILTO:", 7))
	     address += 7;
	  utf8_snprintf(tmp_20k_buf, SIZEOF_20KBUF, "%s%s<%s>",
		cn ? cn :  "", cn ? " " : "", 
		address ? address : _("Unknown address"));
	  rv->organizer = cpystr(tmp_20k_buf);
	}
     }	/* end of if(organizer) */

     if((icl = (ICLINE_S *) vevent->prop[EvLocation]) != NULL){
	rv->location = cpystr(icl->value ? icl->value : _("Location undisclosed"));
	ical_remove_escapes(&rv->location);
     }

     if((icl = (ICLINE_S *) vevent->prop[EvDtstart]) != NULL){
	struct tm ic_date;
	char tmp[200], *tzid;
	int icd;	/* ical date return value */

	memset((void *)&ic_date, 0, sizeof(struct tm));
	icd = ical_parse_date(icl->value, &ic_date);
	tzid = ical_get_tzid(icl->param);
	if(icd >= 0){
	  ic_date.tm_wday = ical_day_of_week(ic_date);
	  switch(icd){
	    case 0: /* DATE-TIME */
		    ical_date_time(tmp, sizeof(tmp), &ic_date);
		    break;
	    case 1: /* DATE */
		    our_strftime(tmp, sizeof(tmp), "%a %x", &ic_date);
		    break;
	    case 2: /* DATE-TIME in GMT, Bug: add adjust to time zone */
		    our_strftime(tmp, sizeof(tmp), "%a %x %I:%M %p", &ic_date);
		    break;
	    default: alpine_panic("Unhandled ical date format");
		    break;
	  }
	}
	else{
	  strncpy(tmp, _("Error while parsing event date"), sizeof(tmp));
	  tmp[sizeof(tmp) - 1] = '\0';
	}

	if(icl->value == NULL)
	  rv->evstart = cpystr(_("Unknown Start Date"));
	else{
	  size_t len = strlen(tmp) + 1;

	  if(tzid != NULL)
	    len += strlen(tzid) + 3; 	/* 3 = strlen(" ()") */

	  rv->evstart = fs_get(len*sizeof(char));
	  snprintf(rv->evstart, len, "%s%s%s%s", tmp, 
			tzid != NULL ? " (" : "",
			tzid != NULL ? tzid : "",
			tzid != NULL ? ")" : "");
	  rv->evstart[len-1] = '\0';
        }
	if(tzid)
	  fs_give((void **)&tzid);
     }	/* end of if dtstart */

     if((icl = (ICLINE_S *) vevent->prop[EvDuration]) != NULL){
	int i, done = 0;
	ICAL_DURATION_S ic_d, icd2;
	if(ical_parse_duration(icl->value, &ic_d) == 0){
	  char tmp[MAILTMPLEN+1];

	  for(i = 1, icd2 = ic_d; icd2.next != NULL; icd2 = *icd2.next, i++);
	  rv->duration = fs_get((i+1)*sizeof(char *));
	  i = 0;

	  do {
	    tmp[0] = '\0';

	    if(ic_d.weeks > 0)
	      utf8_snprintf(tmp+strlen(tmp), MAILTMPLEN - strlen(tmp), 
		"%d %s ", ic_d.weeks, ic_d.weeks == 1 ? _("week") : _("weeks"));
	    if(ic_d.days > 0)
	      utf8_snprintf(tmp+strlen(tmp), MAILTMPLEN - strlen(tmp), 
		"%d %s ", ic_d.days, ic_d.days == 1 ?  _("day") : _("days"));
	    if(ic_d.hours > 0)
	      utf8_snprintf(tmp+strlen(tmp), MAILTMPLEN - strlen(tmp), 
		"%d %s ", ic_d.hours, ic_d.hours == 1 ?  _("hour") : _("hours"));
	    if(ic_d.minutes > 0)
	      utf8_snprintf(tmp+strlen(tmp), MAILTMPLEN - strlen(tmp), 
		"%d %s ", ic_d.minutes, ic_d.minutes == 1 ?  _("minute") : _("minutes"));
	    if(ic_d.seconds > 0)
	      utf8_snprintf(tmp+strlen(tmp), MAILTMPLEN - strlen(tmp), 
		"%d %s ", ic_d.seconds, ic_d.seconds == 1 ?  _("second") : _("seconds"));

	    tmp[MAILTMPLEN] = '\0';
	    rv->duration[i++] = cpystr(tmp);

	    if(ic_d.next != NULL)
	       ic_d = *ic_d.next;
	    else
	       done++;
	  } while (done == 0);
	  rv->duration[i] = NULL;
        }
     } /* end of DURATION */
     else if((icl = (ICLINE_S *) vevent->prop[EvDtend]) != NULL){
	      struct tm ic_date;
	      char tmp[200], *tzid;
	      int icd;

	      memset((void *)&ic_date, 0, sizeof(struct tm));
	      icd = ical_parse_date(icl->value, &ic_date);
	      tzid = ical_get_tzid(icl->param);
	      if(icd >= 0){
	         ic_date.tm_wday = ical_day_of_week(ic_date);
		 switch(icd){
		    case 0: /* DATE-TIME */
			    ical_date_time(tmp, sizeof(tmp), &ic_date);
			    break;
		    case 1: /* DATE */
			    our_strftime(tmp, sizeof(tmp), "%a %x", &ic_date);
			    break;
		    case 2: /* DATE-TIME in GMT, Bug: add adjust to time zone */
			    our_strftime(tmp, sizeof(tmp), "%a %x %I:%M %p", &ic_date);
			    break;
		    default: alpine_panic("Unhandled ical date format");
			    break;
	 	}
     	  }
	  else{
	     strncpy(tmp, _("Error while parsing event date"), sizeof(tmp));
	     tmp[sizeof(tmp) - 1] = '\0';
	  }

	  if(icl->value == NULL)
	    rv->evend = cpystr(_("Unknown End Date"));
	  else{
	    size_t len = strlen(tmp) + 1;

	    if(tzid != NULL)
	      len += strlen(tzid) + 3; 	/* 3 = strlen(" ()") */

	    rv->evend = fs_get(len*sizeof(char));
	    snprintf(rv->evend, len, "%s%s%s%s", tmp, 
			tzid != NULL ? " (" : "",
			tzid != NULL ? tzid : "",
			tzid != NULL ? ")" : "");
	    rv->evend[len-1] = '\0';
	  }
	  if(tzid)
	    fs_give((void **)&tzid);
     }	/* end of if dtend */

     if((icl = (ICLINE_S *) vevent->prop[EvDtstamp]) != NULL){
       struct tm ic_date;
       char tmp[200], *tzid;
       int icd;

       memset((void *)&ic_date, 0, sizeof(struct tm));
       icd = ical_parse_date(icl->value, &ic_date);
       tzid = ical_get_tzid(icl->param);
       if(icd >= 0){
         ic_date.tm_wday = ical_day_of_week(ic_date);
	 switch(icd){
	    case 0: /* DATE-TIME */
		    ical_date_time(tmp, sizeof(tmp), &ic_date);
		    break;
	    case 1: /* DATE */
		    our_strftime(tmp, sizeof(tmp), "%a %x", &ic_date);
		    break;
	    case 2: /* DATE-TIME in GMT, Bug: add adjust to time zone */
		    our_strftime(tmp, sizeof(tmp), "%a %x %I:%M %p", &ic_date);
		    break;
	    default: alpine_panic("Unhandled ical date format");
		    break;
	 }
       }
       else{
	strncpy(tmp, _("Error while parsing event date"), sizeof(tmp));
	tmp[sizeof(tmp) - 1] = '\0';
       }
       if(icl->value == NULL)
	 rv->dtstamp = cpystr(_("Unknown when event was scheduled"));
       else{
	 size_t len = strlen(tmp) + 1;

	 if(tzid != NULL)
	  len += strlen(tzid) + 3; 	/* 3 = strlen(" ()") */

	 rv->dtstamp = fs_get(len*sizeof(char));
	 snprintf(rv->dtstamp, len, "%s%s%s%s", tmp, 
			tzid != NULL ? " (" : "",
			tzid != NULL ? tzid : "",
			tzid != NULL ? ")" : "");
	 rv->dtstamp[len-1] = '\0';
       }
     } /* end of if dtstamp */

     if((gicl = (GEN_ICLINE_S *) vevent->prop[EvAttendee]) != NULL){
	int nattendees, i;

	for(nattendees = 0; gicl != NULL; gicl = gicl->next, nattendees++);
	rv->attendee = fs_get((nattendees+1)*sizeof(char *));

	gicl = (GEN_ICLINE_S *) vevent->prop[EvAttendee];
	for(i = 0; gicl != NULL; gicl = gicl->next, i++){
	   char *role, *partstat, *rsvp;
	   char *cn, *mailto;
	   ICAL_PARAMETER_S *param;

	   icl  = gicl->cline;
	   role = partstat = rsvp = cn = mailto = NULL;
	   for(param = icl->param; param != NULL; param = param->next){
	      if(!strucmp(param->name, "ROLE")){
		if(!strucmp(param->value, "REQ-PARTICIPANT"))
		   role = _("[Required]");
		else if(!strucmp(param->value, "OPT-PARTICIPANT"))
		   role = _("[Optional]");
		else if(!strucmp(param->value, "NON-PARTICIPANT"))
		   role = _("[Informed]");
		else if(!strucmp(param->value, "CHAIR"))
		   role = _("[ Chair  ]");
		else
		   role = param->value;
	      }
	      else if(!strucmp(param->name, "PARTSTAT")){
		if(!strucmp(param->value, "NEEDS-ACTION"))
		   partstat = _("[Need-Reply]");
		else if(!strucmp(param->value, "ACCEPTED"))
		   partstat = _("[ Accepted ]");
		else if(!strucmp(param->value, "DECLINED"))
		   partstat = _("[ Declined ]");
		else if(!strucmp(param->value, "TENTATIVE"))
		   partstat = _("[ Tentative]");
		else if(!strucmp(param->value, "DELEGATED"))
		   partstat = _("[ Delegated]");
		else
		   partstat = param->value;
	      }
	      else if(!strucmp(param->name, "RSVP"))
		rsvp = param->value;
	      else if(!strucmp(param->name, "CN"))
		cn = param->value;
	   }
	   if(icl->value && !struncmp(icl->value, "MAILTO:", strlen("MAILTO:")))
		mailto = icl->value + 7; /* 7 = strlen("MAILTO:") */
	   if(!strucmp(cn, mailto))
		cn = "";
	   utf8_snprintf(tmp_20k_buf, SIZEOF_20KBUF, "%s%s%s%s%s%s<%s>",
		role && *role ? role : "",
		role && *role ? " " : "",
		partstat ? partstat : _("[Unknown Reply]"),
		" ",
		cn && *cn ? cn  : "",
		cn && *cn ? " " : "",
		mailto ? mailto : _("Unknown address"));
	   rv->attendee[i] = cpystr(tmp_20k_buf);
	}
	rv->attendee[i] = NULL;
     } /* end of ATTENDEES */

     if((icl = (ICLINE_S *) vevent->prop[EvDescription]) != NULL){
	char *s, *t, *u, *v;
	int i, escaped;

	if(icl->value == NULL){
	   free_vevent_summary(&rv);
	   return vsummary;
	}

	v = cpystr(icl->value);	/* process a copy of icl->value */

	for(i = 1, escaped = 0, s = v; s && *s; s++){
	   if(*s == '\\' && escaped == 0){ escaped = 1; continue; }
	   if(escaped){
		if(!(*s == '\\' || *s == ',' || *s == 'n' || *s == 'N' || *s == ';')){
		   free_vevent_summary(&rv);
		   fs_give((void **)&v);
		   return vsummary;
		}
		escaped = 0;
		continue;
	   }
	   if(*s == ',') i++;	/* a non-scaped comma is a new value for text */
	}

	rv->description = fs_get((i+1)*sizeof(unsigned char *));
	i = 0;
	for (s = t = u = v, escaped = 0; *t != '\0'; t++){
	   if(*t == '\\' && escaped == 0){ escaped = 1; continue; }
	   if(escaped){
		switch(*t){
		   case '\\':
		   case ',':
		   case ';':
			    *u++ = *t;
			    break;
		   case 'n':
		   case 'N':
			    *u++ = '\n';
			    break;
		   default: free_vevent_summary(&rv);
			    fs_give((void **)&v);
			    return NULL;
		}
		escaped = 0;
		continue;
	   }
	   if(*t == ','){
		*u = '\0';
		rv->description[i++] = cpystr(ical_decode(s, vcal->encoding));
		s = u = t+1;
	   } else
		*u++ = *t;  
	}
	*u = '\0';
	rv->description[i++] = cpystr(ical_decode(s, vcal->encoding));
	rv->description[i] = NULL;
	fs_give((void **)&v);
     } /* end of if(description) */
     /* last instruction of the loop */
     if(vsummary == NULL)
	vsummary = rv;
     else{
	VEVENT_SUMMARY_S *vesy;
	for(vesy = vsummary; vesy && vesy->next; vesy = vesy->next);
	vesy->next = rv;
     }
  } /* end of "for" loop */
  return vsummary;
}

void
free_vevent_summary(VEVENT_SUMMARY_S **vesy)
{
  int i;
  if(vesy == NULL || *vesy == NULL) return;

  if((*vesy)->class) fs_give((void **)&(*vesy)->class);
  if((*vesy)->summary) fs_give((void **)&(*vesy)->summary);
  if((*vesy)->sender) fs_give((void **)&(*vesy)->sender);
  if((*vesy)->organizer) fs_give((void **)&(*vesy)->organizer);
  if((*vesy)->location) fs_give((void **)&(*vesy)->location);
  if((*vesy)->evstart) fs_give((void **)&(*vesy)->evstart);
  if((*vesy)->evend) fs_give((void **)&(*vesy)->evend);
  if((*vesy)->dtstamp) fs_give((void **)&(*vesy)->dtstamp);
  if((*vesy)->duration){
     for(i = 0; (*vesy)->duration[i] != NULL; i++)
	fs_give((void **) &(*vesy)->duration[i]);
     fs_give((void **) (*vesy)->duration);
  }
  if((*vesy)->attendee){
     for(i = 0; (*vesy)->attendee[i] != NULL; i++)
	fs_give((void **) &(*vesy)->attendee[i]);
     fs_give((void **) &(*vesy)->attendee);
  }
  if((*vesy)->description){
     for(i = 0; (*vesy)->description[i] != NULL; i++)
	fs_give((void **) &(*vesy)->description[i]);
     fs_give((void **) &(*vesy)->description);
  }
  if((*vesy)->next) free_vevent_summary(&(*vesy)->next);
  fs_give((void **) vesy);
}

void
ical_free_all(void)
{
  if(ical_buf)
    fs_give((void **)&ical_buf);
}
