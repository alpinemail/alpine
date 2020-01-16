/* ========================================================================
 * Copyright 1988-2006 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * 
 * ========================================================================
 */

/*
 * Program:	Unix compatibility routines
 *
 * Author:	Mark Crispin
 *		Networks and Distributed Computing
 *		Computing & Communications
 *		University of Washington
 *		Administration Building, AG-44
 *		Seattle, WA  98195
 *		Internet: MRC@CAC.Washington.EDU
 *
 * Date:	14 September 1996
 * Last Edited:	November 7, 2015.
 *		Eduardo Chappa <chappa@gmx.com>
 */


/*				DEDICATION
 *
 *  This file is dedicated to my dog, Unix, also known as Yun-chan and
 * Unix J. Terwilliker Jehosophat Aloysius Monstrosity Animal Beast.  Unix
 * passed away at the age of 11 1/2 on September 14, 1996, 12:18 PM PDT, after
 * a two-month bout with cirrhosis of the liver.
 *
 *  He was a dear friend, and I miss him terribly.
 *
 *  Lift a leg, Yunie.  Luv ya forever!!!!
 */
 
/* Emulator for BSD flock() call
 * Accepts: file descriptor
 *	    operation bitmask
 * Returns: 0 if successful, -1 if failure
 */

/*  Our friends in Redmond have decided that you can not write to any segment
 * which has a shared lock.  This screws up the shared-write mailbox drivers
 * (mbx, mtx, and tenex).  As a workaround, we'll only lock the first byte of
 * the file, meaning that you can't write that byte shared.
 *  This behavior seems to be new as of NT 4.0.
 */

int flock (int fd,int op)
{
  HANDLE hdl = (HANDLE) _get_osfhandle (fd);
  DWORD flags = (op & LOCK_NB) ? LOCKFILE_FAIL_IMMEDIATELY : 0;
  OVERLAPPED offset = {NIL,NIL,0,0,NIL};
  int ret = -1;
  blocknotify_t bn = (blocknotify_t) 
    ((op & LOCK_NB) ? NIL : mail_parameters (NIL,GET_BLOCKNOTIFY,NIL));
  if (hdl < 0) errno = EBADF;	/* error in file descriptor */
  else switch (op & ~LOCK_NB) {	/* translate to LockFileEx() op */
  case LOCK_EX:			/* exclusive */
    flags |= LOCKFILE_EXCLUSIVE_LOCK;
  case LOCK_SH:			/* shared */
    if (!check_nt ()) return 0;	/* always succeeds if not NT */
    if (bn) (*bn) (BLOCK_FILELOCK,NIL);
				/* bug for bug compatible with Unix */
    UnlockFileEx (hdl,NIL,1,0,&offset);
				/* lock the file as requested */
    if (LockFileEx (hdl,flags,NIL,1,0,&offset)) ret = 0;
    if (bn) (*bn) (BLOCK_NONE,NIL);
				/* if failed */
    if (ret) errno = (op & LOCK_NB) ? EAGAIN : EBADF;
    break;
  case LOCK_UN:			/* unlock */
    if (check_nt ()) UnlockFileEx (hdl,NIL,1,0,&offset);
    ret = 0;			/* always succeeds */
  default:			/* default */
    errno = EINVAL;		/* bad call */
    break;
  }
  return ret;
}

/* Local storage */

static char *loghdr;		/* log file header string */
static HANDLE loghdl = NIL;	/* handle of event source */

/* Emulator for BSD syslog() routine
 * Accepts: priority
 *	    message
 *	    parameters
 */

void syslog (int priority,const char *message,...)
{
  va_list args;
  LPTSTR strs[2];
  char tmp[MAILTMPLEN];		/* callers must be careful not to pop this */
  unsigned short etype;
  if (!check_nt ()) return;	/* no-op on non-NT system */
				/* default event source */
  if (!loghdl) openlog ("c-client",LOG_PID,LOG_MAIL);
  switch (priority) {		/* translate UNIX type into NT type */
  case LOG_ALERT:
    etype = EVENTLOG_ERROR_TYPE;
    break;
  case LOG_INFO:
    etype = EVENTLOG_INFORMATION_TYPE;
    break;
  default:
    etype = EVENTLOG_WARNING_TYPE;
  }
  va_start (args,message);	/* initialize vararg mechanism */
  vsprintf (tmp,message,args);	/* build message */
  strs[0] = loghdr;		/* write header */
  strs[1] = tmp;		/* then the message */
				/* report the event */
  ReportEvent (loghdl,etype,(unsigned short) priority,2000,NIL,2,0,strs,NIL);
  va_end (args);
}


/* Emulator for BSD openlog() routine
 * Accepts: identity
 *	    options
 *	    facility
 */

void openlog (const char *ident,int logopt,int facility)
{
  char tmp[MAILTMPLEN];
  if (!check_nt ()) return;	/* no-op on non-NT system */
  if (loghdl) fatal ("Duplicate openlog()!");
  loghdl = RegisterEventSource (NIL,ident);
  sprintf (tmp,(logopt & LOG_PID) ? "%s[%d]" : "%s",ident,getpid ());
  loghdr = cpystr (tmp);	/* save header for later */
}

/* Copy Unix string with CRLF newlines
 * Accepts: destination string
 *	    pointer to size of destination string buffer
 *	    source string
 *	    length of source string
 * Returns: length of copied string
 */

unsigned long unix_crlfcpy (char **dst,unsigned long *dstl,char *src,
			    unsigned long srcl)
{
  unsigned long i,j;
  char *d = src;
				/* count number of LF's in source string(s) */
  for (i = srcl,j = 0; j < srcl; j++) if (*d++ == '\012') i++;
				/* flush destination buffer if too small */
  if (*dst && (i > *dstl)) fs_give ((void **) dst);
  if (!*dst) {			/* make a new buffer if needed */
    *dst = (char *) fs_get ((*dstl = i) + 1);
    if (dstl) *dstl = i;	/* return new buffer length to main program */
  }
  d = *dst;			/* destination string */
				/* copy strings, inserting CR's before LF's */
  while (srcl--) switch (*src) {
  case '\015':			/* unlikely carriage return */
    *d++ = *src++;		/* copy it and any succeeding linefeed */
    if (srcl && *src == '\012') {
      *d++ = *src++;
      srcl--;
    }
    break;
  case '\012':			/* line feed? */
    *d++ ='\015';		/* yes, prepend a CR, drop into default case */
  default:			/* ordinary character */
    *d++ = *src++;		/* just copy character */
    break;
  }
  *d = '\0';			/* tie off destination */
  return d - *dst;		/* return length */
}

/* Length of Unix string after unix_crlfcpy applied
 * Accepts: source string
 * Returns: length of string
 */

unsigned long unix_crlflen (STRING *s)
{
  unsigned long pos = GETPOS (s);
  unsigned long i = SIZE (s);
  unsigned long j = i;
  while (j--) switch (SNX (s)) {/* search for newlines */
  case '\015':			/* unlikely carriage return */
    if (j && (CHR (s) == '\012')) {
      SNX (s);			/* eat the line feed */
      j--;
    }
    break;
  case '\012':			/* line feed? */
    i++;
  default:			/* ordinary character */
    break;
  }
  SETPOS (s,pos);		/* restore old position */
  return i;
}

/* Undoubtably, I'm going to regret these two routines in the future.  I
 * regret them now.  Their purpose is to work around two problems in the
 * VC++ 6.0 C library:
 *  (1) tmpfile() creates the file in the current directory instead of a
 *	temporary directory
 *  (2) tmpfile() and fclose() think that on NT systems, it works to unlink
 *	the file while it's still open, so there's no need for the _tmpfname
 *	hook at fclose().  Unfortunately, that doesn't work in Win2K.
 * I would be delighted to have a better alternative.
 */
/* So Visual Studio 2015 came along and it made a change to the FILE structure
 * so it is not possible to use _tmpfname to store the name of the temporary
 * file name, so we will introduce an internal management system to keep track
 * of temporary files. E.Ch.
 */

typedef struct win_file {
   FILE *f;
   char *name;
} WIN_FILE_S;

typedef struct wintmpfile {
  WIN_FILE_S *wf;		/* where memory is saved		*/
  int size;			/* size of array of allocated memory	*/
  int total;			/* total number of allocated members	*/
} TMP_WINFILE;

#define TMPFILE_NUM 5		/* increase every 5 files, if we need to */
TMP_WINFILE win_tmp;
int inited = 0;

void add_tmpfile(TMP_WINFILE *wtmp, FILE *f, char *name)
{
  if(wtmp == NULL)
     return;

   if(wtmp->total % TMPFILE_NUM == 0){
      wtmp->size += TMPFILE_NUM;
      fs_resize((void **)&wtmp->wf, wtmp->size*sizeof(WIN_FILE_S));
   }

   wtmp->wf[wtmp->total].f = f;
   wtmp->wf[wtmp->total++].name = name;
}

int get_pos_tmpfile(TMP_WINFILE *wtmp, FILE *f)
{
  int i;

  if(wtmp == NULL || wtmp->total == 0)
    return -1;

  for(i = 0; i < wtmp->total && wtmp->wf[i].f != f; i++);

  return i == wtmp->total ? -1 : i;
}

/* remove the element in position pos from wtmp, all memory is freed before
 * calling this function */
void  remove_pos_tmpfile(TMP_WINFILE *wtmp, int pos)
{
   int i;

   if(wtmp == NULL || pos < 0 || pos >= wtmp->total)
      return;

   wtmp->total--;
   for(i = pos; i < wtmp->total; i++){
	wtmp->wf[i].f = wtmp->wf[i+1].f;
	wtmp->wf[i].name = wtmp->wf[i+1].name;
   }
   wtmp->wf[wtmp->total].f = NIL;
   wtmp->wf[wtmp->total].name = NIL;

   if(wtmp->total % TMPFILE_NUM == 0){
      wtmp->size -= TMPFILE_NUM;
      fs_resize((void **)&wtmp->wf, wtmp->size*sizeof(WIN_FILE_S));
   }
   if(wtmp->size == 0)
     inited = 0;		/* restart */
}

#undef fclose			/* use the real fclose() in close_file() */

/* Substitute for Microsoft's tmpfile() that uses the real temporary directory
 * Returns: FILE structure if success, NIL if failure
 */

FILE *create_tempfile (void)
{
  FILE *ret = NIL;
  char *s = _tempnam (getenv ("TEMP"),"msg");

  if(inited == 0){		/* initialize, just in case */
    memset((void *)&win_tmp, 0, sizeof(TMP_WINFILE));
    inited++;
  }
  if (s) {			/* if got temporary name... */
				/* open file, and stash name on record of temp files */
    if (ret = fopen (s,"w+b")) add_tmpfile(&win_tmp, ret, s);
    else fs_give ((void **) &s);/* flush temporary string */
  }
  return ret;
}


/* Substitute for Microsoft's fclose() that always flushes _tmpfname
 * Returns: FILE structure if success, NIL if failure
 */

int close_file (FILE *stream)
{
  int ret;
  int pos = get_pos_tmpfile(&win_tmp, stream);
  ret = fclose (stream);		/* close the file */
  if (pos >= 0) {			/* was this a temporary file? */
    unlink (win_tmp.wf[pos].name);	/* if so, delete it */
    fs_give ((void **) &win_tmp.wf[pos].name);	/* and flush the name */
    remove_pos_tmpfile(&win_tmp, pos);
  }
  return ret;
}

/* Get password from console
 * Accepts: prompt
 * Returns: password
 */

#define PWDLEN 128		/* used by Linux */

char *getpass (const char *prompt)
{
  static char pwd[PWDLEN];
  int ch,i,done;
  fputs (prompt,stderr);	/* output prompt */
  for (i = done = 0; !done; ) switch (ch = _getch()) {
  case 0x03:			/* CTRL/C stops program */
    _exit (1);
  case '\b':			/* BACKSPACE erase previous character */
    if (i) pwd[--i] = '\0';
    break;
  case '\n': case '\r':		/* CR or LF terminates string */
    done = 1;
    break;
  default:			/* any other character is a pwd char */
    if (i < (PWDLEN - 1)) pwd[i++] = ch;
    break;
  }
  pwd[i] = '\0';		/* tie off string with null */
  putchar ('\n');		/* echo newline */
  return pwd;
}
