#ifndef PITH_ICAL_INCLUDED
#define PITH_ICAL_INCLUDED

#include "../pith/icaltype.h"

void ical_free_vcalendar(void **);
void ical_free_duration(ICAL_DURATION_S **ic_d);
int  ical_first_of_month(int, int);      /* args: month, year - in that order */
int  ical_day_of_week(struct tm);        /* args: a time structure */
int  ical_parse_date(char *, struct tm *);
int  ical_parse_duration(char *, ICAL_DURATION_S *);
int  ical_remove_escapes(char **);
VEVENT_SUMMARY_S *ical_vevent_summary(VCALENDAR_S *);
void free_vevent_summary(VEVENT_SUMMARY_S **);

VCALENDAR_S *ical_parse_text(char *);           /* this is the entry point */
void ical_free_all(void);

#endif /* ifndef PITH_ICAL_INCLUDED */
