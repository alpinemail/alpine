#ifndef ICALTYPE_INCLUDED
#define ICALTYPE_INCLUDED

/* Due to the line by line processing algorithm, not all informatio
 * is available when process some lines. In particular, when we
 * process anything that has to do with time, we do not know if
 * we are processing a date in daylight savings time or not. We
 * solve this by creating a new value for tm_isdst, called
 * ICAL_DST_UNKNOWN, which is a positive integer. We set this
 * when the date comes in GMT. Once we process it, we either
 * change it to 0, which means it is not dst, or change it
 * to a different value, ICAL_DST_SET which means we know the date
 * is DST
 */
#define ICAL_DST_UNKNOWN  (1)
#define ICAL_DST_SET 	  (ICAL_DST_UNKNOWN + 1)

/* this is the PARAMETER struct from mail.h, but with possibility of
 * extension */
typedef struct ical_param_s {
  char *name;
  char *value;
  struct ical_param_s *next;
} ICAL_PARAMETER_S;

#define ICAL_S struct ical_s

ICAL_S {
  char *comp;			/* component name */
  void *value;
  ICAL_S *branch;		/* component in same level   */
  ICAL_S *next;			/* component at next level  */
};

typedef struct icline_s {
  char *token;
  ICAL_PARAMETER_S *param;
  char *value;	/* this could need further processing, so consider this a raw value */
} ICLINE_S;

typedef struct gen_icline_s {
  ICLINE_S *cline;
  struct gen_icline_s *next;
} GEN_ICLINE_S;

typedef enum {FSecondly, FMinutely, FHourly, FDaily, FWeekly, 
	      FMonthly, FYearly, FUnknown} Freq_value;

/* believe it or not, I did not need to copy these values from
 * RFC 5545! */
typedef enum {Sunday, Monday, Tuesday, Wednesday, Thursday,
	      Friday, Saturday} Weekday;

typedef struct ical_weekday_s {
  int value;		/* number value being parsed */
  Weekday wd;
  struct ical_weekday_s *next;
} BYWKDY_S;

typedef struct ical_rrule_s {
#if 0
  Freq_value freq;		/* required, at most one */
  ICLINE_S *until;		/* optional, must not occur with count */
  ICLINE_S *count;		/* optional, must not occur with until */
  unsigned long interval;	/* optional, at most one */
  BYWKDY_S *bysecond;		/* optional, at most one */
  ICLINE_S *byminute;		/* optional, at most one */
  ICLINE_S *byhour;		/* optional, at most one */
  BYWKDY_S *byday;		/* optional, at most one */
  ICLINE_S *bymonthday;	/* optional, at most one */
  ICLINE_S *byyearday;	/* optional, at most one */
  ICLINE_S *byweekno;	/* optional, at most one */
  BYWKDY_S *bymonth;	/* optional, at most one, only use value */
  ICLINE_S *bysetpos;	/* optional, at most one */
  ICLINE_S *wkst;	/* optional, at most one */
#endif /* if 0 */
  void **prop;		/* the list of properties of a recurring rule */
  ICAL_PARAMETER_S *param;
} RRULE_S;

typedef struct valarm_s {
#if 0
  ICLINE_S  *action;		/* required, at most one */
  ICLINE_S  *trigger;		/* required, at most one */
  ICLINE_S  *duration;		/* audio,display,email.optional, at most one. Must occur with repeat */
  ICLINE_S  *repeat;		/* audio,display,email.optional, at most one. Must occur with duration */
  ICLINE_S  *description;	/* display,email.required, at most one */
  ICLINE_S  *summary;		/* email.required, at most one */
  GEN_ICLINE_S  *attach;	/* audio.optional, at most one;email.optional, may occur more than once */
  GEN_ICLINE_S  *attendee;	/* email.required, may occur more than once */
#endif /* if 0 */
  void **prop;			/* an array of all properties of an alarm */
  GEN_ICLINE_S  *uk_prop; 	/* optional, may occur more than once */
  struct valarm_s *next;
} VALARM_S;

typedef struct vevent_s {
#if 0
  ICLINE_S *dtstamp;	/* required, at most one */
  ICLINE_S *uid;	/* required, at most one */
  ICLINE_S *dtstart;	/* required if METHOD not specified, at most one */
  ICLINE_S *class;	/* optional, at most one */
  ICLINE_S *created;	/* optional, at most one */
  ICLINE_S *description;/* optional, at most one */
  ICLINE_S *geo;	/* optional, at most one */
  ICLINE_S *lastmod;	/* optional, at most one */
  ICLINE_S *location;	/* optional, at most one */
  ICLINE_S *organizer;	/* optional, at most one */
  ICLINE_S *priority;	/* optional, at most one */
  ICLINE_S *seq;	/* optional, at most one */
  ICLINE_S *status;	/* optional, at most one */
  ICLINE_S *summary;	/* optional, at most one */
  ICLINE_S *transp;	/* optional, at most one */
  ICLINE_S *url;	/* optional, at most one */
  ICLINE_S *recurid;	/* optional, at most one */
  RRULE_S *rrule;	/* optional, at most one */
  ICLINE_S *dtend;	/* optional, at most one, exclude duration */
  ICLINE_S *duration;	/* optional, at most one, exclude dtend	   */
  GEN_ICLINE_S *attach;		/* optional, may occur more than once */
  GEN_ICLINE_S *attendee;	/* optional, may occur more than once */
  GEN_ICLINE_S *categories;	/* optional, may occur more than once */
  GEN_ICLINE_S *comment;	/* optional, may occur more than once */
  GEN_ICLINE_S *contact;	/* optional, may occur more than once */
  GEN_ICLINE_S *exdate;		/* optional, may occur more than once */
  GEN_ICLINE_S *rstatus;	/* optional, may occur more than once */
  GEN_ICLINE_S *related;	/* optional, may occur more than once */
  GEN_ICLINE_S *resources;	/* optional, may occur more than once */
  GEN_ICLINE_S *rdate;		/* optional, may occur more than once */
#endif /* if 0 */
  void **prop;			/* the properties of an event component */
  GEN_ICLINE_S *uk_prop;	/* unknown values */
  VALARM_S *valarm;		/* possible valarm */
  struct vevent_s *next;	/* calendar of method publish has many events */
} VEVENT_S;

typedef struct vtodo_s {
  ICLINE_S *dtstamp;	/* required, at most one */
  ICLINE_S *uid;	/* required, at most one */
  ICLINE_S *class;	/* optional, at most one */
  ICLINE_S *completed;	/* optional, at most one */
  ICLINE_S *created;	/* optional, at most one */
  ICLINE_S *description;/* optional, at most one */
  ICLINE_S *dtstart;	/* optional, at most one */
  ICLINE_S *geo;	/* optional, at most one */
  ICLINE_S *lastmod;	/* optional, at most one */
  ICLINE_S *location;	/* optional, at most one */
  ICLINE_S *organizer;	/* optional, at most one */
  ICLINE_S *percent;	/* optional, at most one */
  ICLINE_S *priority;	/* optional, at most one */
  ICLINE_S *recurid;	/* optional, at most one */
  ICLINE_S *seq;	/* optional, at most one */
  ICLINE_S *status;	/* optional, at most one */
  ICLINE_S *summary;	/* optional, at most one */
  ICLINE_S *url;	/* optional, at most one */
  RRULE_S *rrule;	/* optional, at most one */
  ICLINE_S *due;	/* optional, at most one, but exclude duration */
  ICLINE_S *duration;	/* optional, at most one, but exclude due, and add dtstart */
  ICLINE_S *attach;	/* optional, can appear more than once */
  ICLINE_S *attendee;	/* optional, can appear more than once */
  ICLINE_S *categories;	/* optional, can appear more than once */
  ICLINE_S *comment;	/* optional, can appear more than once */
  ICLINE_S *contact;	/* optional, can appear more than once */
  ICLINE_S *exdate;	/* optional, can appear more than once */
  ICLINE_S *rstatus;	/* optional, can appear more than once */
  ICLINE_S *related;	/* optional, can appear more than once */
  ICLINE_S *resources;	/* optional, can appear more than once */
  ICLINE_S *rdate;	/* optional, can appear more than once */
  ICAL_PARAMETER_S *unknown;   /* unknown values */
  VALARM_S *valarm;	/* optional valarm */
} VTODO_S;

typedef struct journal_s {
  ICLINE_S *dtstamp;	/* required, at most one */
  ICLINE_S *uid;	/* required, at most one */
  ICLINE_S *class;	/* optional, at most one */
  ICLINE_S *created;	/* optional, at most one */
  ICLINE_S *dtstart;	/* optional, at most one */
  ICLINE_S *lastmod;	/* optional, at most one */
  ICLINE_S *organizer;	/* optional, at most one */
  ICLINE_S *recurid;	/* optional, at most one */
  ICLINE_S *seq;	/* optional, at most one */
  ICLINE_S *status;	/* optional, at most one */
  ICLINE_S *summary;	/* optional, at most one */
  ICLINE_S *url;	/* optional, at most one */
  RRULE_S *rrule;	/* optional, at most one */
  ICLINE_S *attach;	/* optional, may occur more than once */
  ICLINE_S *attendee;	/* optional, may occur more than once */
  ICLINE_S *categories;	/* optional, may occur more than once */
  ICLINE_S *comment;	/* optional, may occur more than once */
  ICLINE_S *contact;	/* optional, may occur more than once */
  ICLINE_S *description;/* optional, may occur more than once */
  ICLINE_S *exdate;	/* optional, may occur more than once */
  ICLINE_S *related;	/* optional, may occur more than once */
  ICLINE_S *rdate;	/* optional, may occur more than once */
  ICLINE_S *rstatus;	/* optional, may occur more than once */
  ICAL_PARAMETER_S *unknown;   /* unknown values */
} VJOURNAL_S;

typedef struct freebusy_s {
  ICLINE_S *dtstamp;	/* required, at most one */
  ICLINE_S *uid;	/* required, at most one */
  ICLINE_S *contact;	/* optional, at most one */
  ICLINE_S *dtstart;	/* optional, at most one */
  ICLINE_S *dtend;	/* optional, at most one */
  ICLINE_S *organizer;	/* optional, at most one */
  ICLINE_S *url;	/* optional, at most one */
  ICLINE_S *attendee;	/* optional, may appear more than oncece */
  ICLINE_S *comment;	/* optional, may appear more than oncece */
  ICLINE_S *freebusy;	/* optional, may appear more than oncece */
  ICLINE_S *rstatus;	/* optional, may appear more than once */
  ICAL_PARAMETER_S *unknown;   /* unknown values */
} VFREEBUSY_S;

typedef struct ical_tzprop_s {
#if 0
  struct tm dtstart;		/* required, at most one */
  int tzoffsetto;		/* required, at most one */
  int tzoffsetfrom;		/* required, at most one */
  RRULE_S *rrule;		/* optional, at most one */
  GEN_ICLINE_S *comment;	/* optional, may appear more than once */
  GEN_ICLINE_S *rdate;		/* optional, may appear more than once */
  GEN_ICLINE_S *tzname;		/* optional, may appear more than once */
#endif /* if 0 */
  void **prop;			/* the bunch of timezone properties */
  GEN_ICLINE_S *uk_prop;	/* optional, may appear more than once */
  struct ical_tzprop_s *next;
} ICAL_TZPROP_S;

typedef struct vtimezone_s {
#if 0
  ICLINE_S *tzid;		/* required, at most one */
  ICLINE_S *last_mod;		/* optional, at most one */
  ICLINE_S *tzurl;		/* optional, at most one */
#endif /* if 0 */
  void **prop;			/* array of timezone properties */
  ICAL_TZPROP_S *standardc;	/* optional, may appear more than once */
  ICAL_TZPROP_S *daylightc;	/* optional, may appear more than once */
  GEN_ICLINE_S *uk_prop;	/* optional, may appear more than once */
} VTIMEZONE_S;

typedef struct vcalendar_s {
  ICLINE_S *prodid;	/* required, at most one */
  ICLINE_S *version;	/* required, at most one */
  ICLINE_S *calscale;	/* optional, at most one */
  ICLINE_S *method;	/* optional, at most one */
  GEN_ICLINE_S *uk_prop;/* in case there is an unknown property */
  void   **comp;	/* an array with the components of a calendar */
  ICAL_S *uk_comp;	/* in case there is an unknown component */
  unsigned short encoding;	/* save the original encoding. */
} VCALENDAR_S;


typedef enum {Individual, Group, Resource, Room, CUUnknown} CUType;
typedef enum {EventNeedsAction, EventAccepted, EventDeclined, EventTentative, 
	      EventDelegated, EventUnknown,
	      TodoNeedsAction, TodoAccepted, TodoDeclined, TodoTentative,
              TodoDelegated, TodoCompleted, TodoInProgress, TodoUnknown,
	      JournalNeedsAction, JournalAccepted, JournalDeclined,
	      JournalUnknown} PartStat;
typedef enum  {RelBegin, RelEnd, RelUnknown} Related;
typedef enum  {Parent, Child, Sibling} RelType;
typedef enum  {ReqPart, Chair, OptPart, NonPart, RoleUnknown} Role;
typedef enum  {RSVPFalse, RSVPTrue, RSVPUnknown} RSVP;
typedef enum  {Binary, _Boolean, CalAddress, Date, DateTime, _Duration,
	       Float, Integer, Period, Recur, _Text, Time, Uri, 
	       UtcOffset, ValueUnknown} Value;

typedef struct icalpar_s {
  ICLINE_S *altrep;	/* altrep uri, inside dquote RFC 2392, RFC 2616 and RFC 2818 */
  ICLINE_S *cn;	/* common name */
  CUType   cutype; /* calendar user type: individual, group, resource, room, unknown */
  ADDRESS *delegated_from; /* person(s) who delegated their participation */
  ADDRESS *delegated_to;   /* person that was delegated participation */
  ICLINE_S *dir;   /* reference to a directory entry associated with the calendar user specified by the property. */
  unsigned short encoding; /* encoding, either 8bit or base64 */
  unsigned short type;	   /* type for FMTTYPE */
  ICLINE_S *subtype;	   /* subtype for FMTTYPE */
  ICLINE_S *fbtype;		   /* FreeBusy type */
  ICLINE_S *language;	   /* language */
  ADDRESS *member;	   /* group or list membership of the calendar user specified by the property */
  PartStat partstat;	   /* participation status for the calendar user specified by the property. */
  ICLINE_S *range;		   /* this and future */
  Related related;	   /* relationship of the alarm trigger with respect to the start or end of the calendar component. */
  RelType reltype;	   /* type of hierarchical relationship associated with the calendar component specified by the property. */
  Role    role;		   /* participation role for the calendar user specified by the property. */
  RSVP    rsvp;		   /*  whether there is an expectation of a favor of a reply from the calendar user specified by the property value. */
  ADDRESS *sentby;	   /* the calendar user that is acting on behalf of the calendar user specified by the property. */
  ICLINE_S *tzid;		   /* the identifier for the time zone definition for a time component in the property value. */
  Value value;		   /* specify the value type format for a property value. */
} ICALPAR_S;

typedef struct ical_duration_s {
   unsigned sign:1;	/* sign = 0 for positive, sign = 1 for negative */
   unsigned weeks;
   unsigned days;
   unsigned hours;
   unsigned minutes;
   unsigned seconds;
   struct ical_duration_s *next;	/* another duration */
} ICAL_DURATION_S;

/* altrepparam = "ALTREP" "=" DQUOTE uri DQUOTE 
 * cnparam    = "CN" "=" param-value
 * cutypeparam = "CUTYPE" "="
                          ("INDIVIDUAL"   ; An individual
                         / "GROUP"        ; A group of individuals
                         / "RESOURCE"     ; A physical resource
                         / "ROOM"         ; A room resource
                         / "UNKNOWN"      ; Otherwise not known
                         / x-name         ; Experimental type
                         / iana-token)    ; Other IANA-registered
                                          ; type
 * delfromparam  = "DELEGATED-FROM" "=" DQUOTE cal-address
                             DQUOTE *("," DQUOTE cal-address DQUOTE)

 * deltoparam = "DELEGATED-TO" "=" DQUOTE cal-address DQUOTE
                    *("," DQUOTE cal-address DQUOTE)

 * dirparam   = "DIR" "=" DQUOTE uri DQUOTE

 * encodingparam = "ENCODING" "="
                          ( "8BIT"
          ; "8bit" text encoding is defined in [RFC2045]
                          / "BASE64"
          ; "BASE64" binary encoding format is defined in [RFC4648]
                          )
 * fmttypeparam = "FMTTYPE" "=" type-name "/" subtype-name
                      ; Where "type-name" and "subtype-name" are
                      ; defined in Section 4.2 of [RFC4288].

 * fbtypeparam  = "FBTYPE" "=" ("FREE" / "BUSY"
                          / "BUSY-UNAVAILABLE" / "BUSY-TENTATIVE"
                          / x-name
                ; Some experimental iCalendar free/busy type.
                          / iana-token)
                ; Some other IANA-registered iCalendar free/busy type.

 * languageparam = "LANGUAGE" "=" language

   language = Language-Tag
                  ; As defined in [RFC5646].

 * memberparam  = "MEMBER" "=" DQUOTE cal-address DQUOTE
                            *("," DQUOTE cal-address DQUOTE)

 * partstatparam    = "PARTSTAT" "="
                         (partstat-event
                        / partstat-todo
                        / partstat-jour)

       partstat-event   = ("NEEDS-ACTION"    ; Event needs action
                        / "ACCEPTED"         ; Event accepted
                        / "DECLINED"         ; Event declined
                        / "TENTATIVE"        ; Event tentatively
                                             ; accepted
                        / "DELEGATED"        ; Event delegated
                        / x-name             ; Experimental status
                        / iana-token)        ; Other IANA-registered
                                             ; status
       ; These are the participation statuses for a "VEVENT".
       ; Default is NEEDS-ACTION.

       partstat-todo    = ("NEEDS-ACTION"    ; To-do needs action
                        / "ACCEPTED"         ; To-do accepted
                        / "DECLINED"         ; To-do declined
                        / "TENTATIVE"        ; To-do tentatively
                                             ; accepted
                        / "DELEGATED"        ; To-do delegated
                        / "COMPLETED"        ; To-do completed
                                             ; COMPLETED property has
                                             ; DATE-TIME completed
                        / "IN-PROCESS"       ; To-do in process of
                                             ; being completed
                        / x-name             ; Experimental status
                        / iana-token)        ; Other IANA-registered
                                             ; status
       ; These are the participation statuses for a "VTODO".
       ; Default is NEEDS-ACTION.



       partstat-jour    = ("NEEDS-ACTION"    ; Journal needs action
                        / "ACCEPTED"         ; Journal accepted
                        / "DECLINED"         ; Journal declined
                        / x-name             ; Experimental status
                        / iana-token)        ; Other IANA-registered
                                             ; status
       ; These are the participation statuses for a "VJOURNAL".
       ; Default is NEEDS-ACTION.

 * rangeparam = "RANGE" "=" "THISANDFUTURE"
       ; To specify the instance specified by the recurrence identifier
       ; and all subsequent recurrence instances.

 * trigrelparam = "RELATED" "="
                           ("START"       ; Trigger off of start
                          / "END")        ; Trigger off of end

 * reltypeparam = "RELTYPE" "="
                           ("PARENT"    ; Parent relationship - Default
                          / "CHILD"     ; Child relationship
                          / "SIBLING"   ; Sibling relationship
                          / iana-token  ; Some other IANA-registered
                                        ; iCalendar relationship type
                          / x-name)     ; A non-standard, experimental
                                        ; relationship type

 * roleparam  = "ROLE" "="
                 ("CHAIR"             ; Indicates chair of the
                                        ; calendar entity
                  / "REQ-PARTICIPANT"   ; Indicates a participant whose
                                        ; participation is required
                  / "OPT-PARTICIPANT"   ; Indicates a participant whose
                                        ; participation is optional
                  / "NON-PARTICIPANT"   ; Indicates a participant who
                                        ; is copied for information
                                        ; purposes only
                  / x-name              ; Experimental role
                  / iana-token)         ; Other IANA role
       ; Default is REQ-PARTICIPANT

  * rsvpparam = "RSVP" "=" ("TRUE" / "FALSE")
       ; Default is FALSE

  * sentbyparam        = "SENT-BY" "=" DQUOTE cal-address DQUOTE

  * tzidparam  = "TZID" "=" [tzidprefix] paramtext

    tzidprefix = "/"

 */

typedef struct vevent_summary_s {
  int cancel:1;
  int priority;
  char *class;
  char *summary;
  char *sender;
  char *organizer;
  char *location;
  char *evstart;
  char *evend;
  char *dtstamp;
  char **duration;
  char **attendee;
  unsigned char **description;
  struct vevent_summary_s *next;
} VEVENT_SUMMARY_S;

typedef enum {VCalendar = 0, VTimeZone, VEvent, VTodo, VJournal,
              VAlarm, VFreeBusy, VUnknown} Cal_comp;

typedef enum {EvDtstamp = 0, EvUid, EvDtstart, EvClass, EvCreated,
              EvDescription, EvGeo, EvLastMod, EvLocation,
              EvOrganizer, EvPriority, EvSequence, EvStatus,
              EvSummary, EvTransp, EvUrl, EvRecurrence, EvRrule,
              EvDtend, EvDuration, EvAttach, EvAttendee, EvCategories,
              EvComment, EvContact, EvExdate, EvRstatus, EvRelated,
              EvResources, EvRdate,
              EvUnknown} Event_prop;

typedef enum {TZCid = 0, TZCLastMod, TZCUrl, TZCUnknown} TZ_comp;

typedef enum {TZPDtstart = 0, TZPOffsetto, TZPOffsetfrom,
	     TZPRrule, TZPComment, TZPRdate, TZPTzname, TZPUnknown} TZ_prop;

typedef enum {AlAction = 0, AlTrigger, AlDuration, AlRepeat,
              AlDescription, AlSummary, AlAttach, AlAttendee,
              AlUnknown} Alarm_prop;

typedef enum {RRFreq, RRUntil, RRCount, RRInterval,
	      RRBysecond, RRByminute, RRByhour, RRByday,
	      RRByweekno, RRBymonth, RRBysetpos, RRWkst,
	      RRBymonthday, RRByyearday, 
	      RRUnknown} RRule_prop;

#endif /* ifndef ICALTYPE_INCLUDED */
