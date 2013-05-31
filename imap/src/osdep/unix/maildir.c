/*
 * Maildir driver for Alpine 2.11
 * 
 * Written by Eduardo Chappa <chappa@gmx.com>
 * Last Update: May 29, 2011.
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
extern int errno;		/* just in case */
#include "mail.h"
#include <pwd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "osdep.h"
#include "rfc822.h"
#include "fdstring.h"
#include "misc.h"
#include "dummy.h"
#include "maildir.h"

/* Driver dispatch used by MAIL */
DRIVER maildirdriver = {
  "md",				/* driver name, yes it's md, not maildir */
  DR_MAIL|DR_LOCAL|DR_NAMESPACE|DR_DIRFMT,		/* driver flags */
  (DRIVER *) NIL,		/* next driver 				*/
  maildir_valid,		/* mailbox is valid for us 		*/
  maildir_parameters,		/* manipulate parameters		*/
  NIL,				/* scan mailboxes 			*/
  maildir_list,			/* find mailboxes 			*/
  maildir_lsub,			/* find subscribed mailboxes 		*/
  maildir_sub,			/* subscribe to mailbox 		*/
  maildir_unsub,		/* unsubscribe from mailbox 		*/
  maildir_create,		/* create mailbox 			*/
  maildir_delete,		/* delete mailbox 			*/
  maildir_rename,		/* rename mailbox 			*/
  mail_status_default,		/* status of mailbox 			*/
  maildir_open,			/* open mailbox				*/
  maildir_close,		/* close mailbox 			*/
  maildir_fast,			/* fetch message "fast" attributes	*/
  NIL,				/* fetch message flags 			*/
  NIL,				/* fetch overview 			*/
  NIL,				/* fetch message structure 		*/
  maildir_header,		/* fetch message header 		*/
  maildir_text,			/* fetch message body 			*/
  NIL,				/* fetch partial message text 		*/
  NIL,				/* unique identifier 			*/
  NIL,				/* message number 			*/
  NIL,				/* modify flags 			*/
  maildir_flagmsg,		/* per-message modify flags 		*/
  NIL,				/* search for message based on criteria */
  NIL,				/* sort messages 			*/
  NIL,				/* thread messages 			*/
  maildir_ping,			/* ping mailbox to see if still alive 	*/
  maildir_check,		/* check for new messages		*/
  maildir_expunge,		/* expunge deleted messages 		*/
  maildir_copy,			/* copy messages to another mailbox 	*/
  maildir_append,		/* append string message to mailbox 	*/
  NIL				/* garbage collect stream 		*/
};


DRIVER courierdriver = {
  "mc",	/* Why a separate driver? So that createproto will work		*/
  DR_MAIL|DR_LOCAL|DR_NAMESPACE|DR_DIRFMT,		/* driver flags */
  (DRIVER *) NIL,		/* next driver 				*/
  maildir_valid,		/* mailbox is valid for us 		*/
  maildir_parameters,		/* manipulate parameters		*/
  NIL,				/* scan mailboxes 			*/
  courier_list,			/* find mailboxes 			*/
  maildir_lsub,			/* find subscribed mailboxes 		*/
  maildir_sub,			/* subscribe to mailbox 		*/
  maildir_unsub,		/* unsubscribe from mailbox 		*/
  maildir_create,		/* create mailbox 			*/
  maildir_delete,		/* delete mailbox 			*/
  maildir_rename,		/* rename mailbox 			*/
  mail_status_default,		/* status of mailbox 			*/
  maildir_open,			/* open mailbox				*/
  maildir_close,		/* close mailbox 			*/
  maildir_fast,			/* fetch message "fast" attributes	*/
  NIL,				/* fetch message flags 			*/
  NIL,				/* fetch overview 			*/
  NIL,				/* fetch message structure 		*/
  maildir_header,		/* fetch message header 		*/
  maildir_text,			/* fetch message body 			*/
  NIL,				/* fetch partial message text 		*/
  NIL,				/* unique identifier 			*/
  NIL,				/* message number 			*/
  NIL,				/* modify flags 			*/
  maildir_flagmsg,		/* per-message modify flags 		*/
  NIL,				/* search for message based on criteria */
  NIL,				/* sort messages 			*/
  NIL,				/* thread messages 			*/
  maildir_ping,			/* ping mailbox to see if still alive 	*/
  maildir_check,		/* check for new messages		*/
  maildir_expunge,		/* expunge deleted messages 		*/
  maildir_copy,			/* copy messages to another mailbox 	*/
  maildir_append,		/* append string message to mailbox 	*/
  NIL				/* garbage collect stream 		*/
};

MAILSTREAM maildirproto = {&maildirdriver};	/* prototype stream */
MAILSTREAM courierproto = {&courierdriver};	/* prototype stream */

long maildir_dirfmttest (char *name)
{
  int i;
  for (i = 0; mdstruct[i] && strcmp(name, mdstruct[i]); i++);
  return (i < EndDir) || !strcmp(name, MDDIR) 
	|| !strncmp(name, MDUIDLAST, strlen(MDUIDLAST))
	|| !strncmp(name, MDUIDTEMP, strlen(MDUIDTEMP)) ? LONGT : NIL;
}

void 
md_domain_name(void)
{
   int i, j;

   strcpy(mdlocaldomain, mylocalhost ());
   for (i = 0; mdlocaldomain[i] != '\0' ;)
      if(mdlocaldomain[i] == '/' || mdlocaldomain[i] == ':'){
	 for(j = strlen(mdlocaldomain); j >= i; j--)
	    mdlocaldomain[j+4] = mdlocaldomain[j];
	 mdlocaldomain[i++] = '\\';
	 mdlocaldomain[i++] = '0';
	 if(mdlocaldomain[i] == '/'){
	    mdlocaldomain[i++] = '5';
	    mdlocaldomain[i++] = '7';
	 } else {
	    mdlocaldomain[i++] = '7';
	    mdlocaldomain[i++] = '2';
	 }
      }
      else
	i++;
}

char *
myrootdir(char *name)
{
return myhomedir();
}

char *
mdirpath(void)
{
  char *path = maildir_parameters(GET_MDINBOXPATH, NIL);
  return path ? (path[0] ? path : ".") : "Maildir";
}

/* remove the "#md/" or "#mc/" part from a folder name
 * memory freed by caller
 */
char *
maildir_remove_root (char *name)
{
  int courier = IS_COURIER(name), offset;
  char realname[MAILTMPLEN];

  offset = maildir_valid_name(name) ? (name[3] == '/' ? 4 : 3) : 0;
  if(courier)
     courier_realname(name+offset, realname);
  else
     strcpy(realname, name+offset);
  return cpystr(realname);
}


/* Check validity of the name, we accept:
 *	a) #md/directory/folder
 *	b) #md/inbox
 * A few considerations: We can only accept as valid
 *  a) names that start with #md/ and the directory exists or
 *  b) names that do not start with #md/ but are maildir directories (have
 *     the /cur, /tmp and /new structure)
 */
int maildir_valid_name (char *name)
{
  char tmpname[MAILTMPLEN] = {'\0'};

   if (mdfpath)
      fs_give((void **)&mdfpath);
   if (name && (name[0] != '#'))
	snprintf(tmpname, sizeof(tmpname), "%s%s",MDPREFIX(CCLIENT), name);
   mdfpath = cpystr(tmpname[0] ? tmpname : name);

  return IS_CCLIENT(name) || IS_COURIER(name);
}

/* Check if the directory whose path is given by name is a valid maildir
 *  directory (contains /cur, /tmp and /new)
 */
int maildir_valid_dir (char *name)
{
 int len;
 DirNamesType i;
 struct stat sbuf;
 char tmp[MAILTMPLEN];

   if(name[strlen(name) - 1] == '/')
      name[strlen(name) - 1] = '\0';
   len = strlen(name);
   for (i = Cur; i != EndDir; i++){
      MDFLD(tmp, name, i);
      if (stat(tmp, &sbuf) < 0 || !S_ISDIR(sbuf.st_mode))
	  break;
   }
   name[len] = '\0';
   return (i == EndDir) ? T : NIL;
}

void courier_realname(char *name, char *realname)
{
  int i,j;

  if(!name)
    return;

  for (i = 0, j = 0; i < MAILTMPLEN && j < strlen(name); j++, i++){
      realname[i] = name[j];
      if(name[j] == '/' && name[j+1] != '.' && name[j+1] != '%' 
		&& name[j+1] != '*') 
	realname[++i] = '.';
  }
  if(realname[i-1] == '.')
    i--; 
  realname[i] = '\0';
}


/* given a maildir folder, return its path. Memory freed by caller. Directory
 * does not contain the trailing slash "/". On error NULL is returned.
 */
int maildir_file_path (char *name, char *tmp, size_t sizeoftmp)
{
   char *maildirpath = mdirpath(), *rname;
   int courier = IS_COURIER(name);

   /* There are several ways in which the path can come, so we will handle 
      them here. First we deal with #mc/ or #md/ prefix by removing the 
      prefix, if any */

    if(strlen(name) >= MAILTMPLEN)
      name[MAILTMPLEN] = '\0';
    strcpy(tmp, name);
    rname = maildir_remove_root(tmp);
    tmp[0] = '\0';	/* just in case something fails */

    if (strlen(myrootdir(rname)) + 
		max(strlen(rname), strlen(maildirpath)) > sizeoftmp){
	errno = ENAMETOOLONG;
	snprintf(tmp, sizeoftmp, "Error opening \"%s\": %s", rname, strerror (errno));
	mm_log(tmp,ERROR);
	if(rname) fs_give((void **)&rname);
	return NIL;
    }

    /* There are two ways in which the name can come here, either as a 
       full path or not. If it is not a full path it can come in two ways, 
       either as a file system path (Maildir/.Drafts) or as a maildir path 
       (INBOX.Drafts)
     */

     if(*rname == '/'){	/* full path */
	strncpy(tmp, rname, sizeoftmp); /* do nothing */
	tmp[sizeoftmp-1] = '\0';
     }
     else
	snprintf (tmp, sizeoftmp, "%s/%s%s%s", myrootdir (rname),
	    strncmp (ucase (strcpy (tmp, rname)), "INBOX", 5) 
		? rname : maildirpath,
	    strncmp (ucase (strcpy (tmp, rname)), "INBOX", 5) 
		? "" : (courier ? "/" : ""),
	    strncmp (ucase (strcpy (tmp, rname)), "INBOX", 5) 
		? "" : (*(rname+5) == MDSEPARATOR(courier) ? rname+5 : ""));
    if(rname) fs_give((void **)&rname);
    return tmp[0] ? T : NIL;
}

/* This function is given a full path for a mailbox and returns
 * if it is a valid maildir transformed to canonical notation
 */
int
is_valid_maildir (char **name)
{
  if (!strncmp(*name, myrootdir (*name), strlen(myrootdir(*name)))){
     (*name) += strlen(myrootdir(*name));
     if (**name == '/') (*name)++;
  }
  return maildir_valid(*name) ? T :  NIL;
}

/* Check validity of mailbox. This routine does not send errors to log, other
 *  routines calling this one may do so, though
 */ 

DRIVER *maildir_valid (char *name)
{
   char tmpname[MAILTMPLEN];

   maildir_file_path(name, tmpname, sizeof(tmpname));
   
   return maildir_valid_dir(tmpname) 
		? (IS_COURIER(name) ? &courierdriver : &maildirdriver) : NIL;
}

void maildir_fast (MAILSTREAM *stream,char *sequence,long flags)
{
  unsigned long i;
  MESSAGECACHE *elt;
                                /* get sequence */
  if (stream && LOCAL && ((flags & FT_UID) ?
                          mail_uid_sequence (stream,sequence) :
                          mail_sequence (stream,sequence)))
    for (i = 1L; i <= stream->nmsgs; i++) {
      if ((elt = mail_elt (stream,i))->sequence && (elt->valid = T) &&
          !(elt->day && elt->rfc822_size)) {
        ENVELOPE **env = NIL;
        ENVELOPE *e = NIL;
        if (!stream->scache) env = &elt->private.msg.env;
        else if (stream->msgno == i) env = &stream->env;
        else env = &e;
        if (!*env || !elt->rfc822_size) {
          STRING bs;
          unsigned long hs;
          char *ht = (*stream->dtb->header) (stream,i,&hs,NIL);

          if (!*env) rfc822_parse_msg (env,NIL,ht,hs,NIL,BADHOST,
                                       stream->dtb->flags);
          if (!elt->rfc822_size) {
            (*stream->dtb->text) (stream,i,&bs,FT_PEEK);
            elt->rfc822_size = hs + SIZE (&bs) - GETPOS (&bs);
          }
        }

        if (!elt->day && *env && (*env)->date)
          mail_parse_date (elt,(*env)->date);

        if (!elt->day) elt->day = elt->month = 1;
        mail_free_envelope (&e);
      }
    }
}

int
maildir_eliminate_duplicate (char *name, struct direct ***flist, unsigned long *nfiles)
{
   int i, j, k, error = 0, scanr;
   char new[MAILTMPLEN], old[MAILTMPLEN], tmp[MAILTMPLEN], *str;
   struct direct **names = NIL;

   if((scanr = maildir_doscandir(name, &names, CCLIENT)) < 0)
     return -1;

   if(nfiles) *nfiles = scanr;
   for(i = 0, j = 1, k = 0;  j < scanr; i++, j++){
      if(k)
	names[i] = names[i+k];
      if(same_maildir_file(names[i]->d_name, names[j]->d_name)){
	int d, f, r, s;
	maildir_getflag(names[i]->d_name, &d, &f, &r, &s, NIL);
	snprintf(old, sizeof(old), "%s/%s", name, names[i]->d_name);
	snprintf(new, sizeof(new), "%s/.%s", name, names[i]->d_name);
	if(rename(old, new) < 0 && errno != EEXIST)
	  error++;
	if(!error){
	  for(; j < scanr
		&& same_maildir_file(names[i]->d_name, names[j]->d_name)
	      ; j++, k++){
	      maildir_getflag(names[j]->d_name, (d ? NIL : &d), 
			(f ? NIL : &f), (r ? NIL : &r), (s ? NIL : &s), NIL);
	      snprintf(tmp, sizeof(tmp), "%s/%s", name, names[j]->d_name);
	      if(unlink(tmp) < 0){	/* Hmmm... a problem, let's see */
		struct stat sbuf;
		if (stat(tmp, &sbuf) == 0 && (sbuf.st_mode & S_IFMT) == S_IFREG)
		   error++;
	      }
	  }
	  if((str = strrchr(names[i]->d_name,FLAGSEP)) != NULL) *str = '\0';
	  snprintf (old, sizeof(old), "%s/%s%s%s%s%s%s", name, names[i]->d_name, MDSEP(2),
		MDFLAG(Draft, d), MDFLAG(Flagged, f), MDFLAG(Replied, r), 
		MDFLAG(Seen, s));
	  if(rename(new, old) < 0)
	     error++;
	}
      }

   }
   if(k > 0)
     fs_give((void **)&names);
   else
     *flist = names;
   return error ? -1 : k;
}

int
maildir_doscandir(char *name, struct direct ***flist, int flag)
{
return scandir(name, flist, 
		flag == CCLIENT ? maildir_select : courier_dir_select, 
		flag == CCLIENT ? maildir_namesort : courier_dir_sort);
}

/* 
 * return all files in a given directory. This is a separate call
 * so that if there are warnings during compilation this only appears once.
 */
unsigned long
maildir_scandir (char *name, struct direct ***flist, 
			unsigned long *nfiles, int *scand, int flag)
{
  struct stat sbuf;
  int rv = -2;	/* impossible value */

  if (scand)
     *scand = -1;	/* assume error for safety */
  *nfiles = 0;
  if((stat(name,&sbuf) < 0) 
	|| (flag == CCLIENT
	 && ((rv = maildir_eliminate_duplicate(name, flist, nfiles)) < 0)))
     return 0L;

  if (scand && (rv > 0 || rv == -2))
     *nfiles = maildir_doscandir(name, flist, flag);

  if(scand) *scand = *nfiles;

  return (unsigned long) sbuf.st_ctime;
}

/* Does a message with given name exists (or was it removed)?
 * Returns: 1 - yes, such message exist,
 *	    0 - No, that message does not exist anymore
 *
 * Parameters: stream, name of mailbox, new name if his message does not
 *		exist.
 */

int maildir_message_exists(MAILSTREAM *stream, char *name, char *newfile)
{
  char tmp[MAILTMPLEN];
  int gotit = NIL;
  DIR *dir;
  struct direct *d;
  struct stat sbuf;

  /* First check directly if it exists, if not there, look for it */
  snprintf(tmp, sizeof(tmp), "%s/%s", LOCAL->path[Cur], name);
  if ((stat(tmp, &sbuf) == 0) && ((sbuf.st_mode & S_IFMT) == S_IFREG))
    return T;

  if (!(dir = opendir (LOCAL->path[Cur])))
     return NIL;

  while ((d = readdir(dir)) && gotit == NIL){
    if (d->d_name[0] == '.')
      continue;
    if (same_maildir_file(d->d_name, name)){
	  gotit = T;
	  strcpy(newfile, d->d_name);
    }
  }
  closedir(dir);
  return gotit;
}

/* Maildir open */
 
MAILSTREAM *maildir_open (MAILSTREAM *stream)
{
  char tmp[MAILTMPLEN];
  struct stat sbuf;

  if (!stream) return &maildirproto;
  if (stream->local) fatal ("maildir recycle stream");
  md_domain_name();    /* get domain name for maildir files in mdlocaldomain */
  if(mypid == (pid_t) 0)
    mypid = getpid();
  if (!stream->rdonly){
     stream->perm_seen = stream->perm_deleted = stream->perm_flagged = 
	stream->perm_answered = stream->perm_draft = T;
  }
  stream->local = (MAILDIRLOCAL *) fs_get (sizeof (MAILDIRLOCAL));
  memset(LOCAL, 0, sizeof(MAILDIRLOCAL));
  LOCAL->fd = -1;

  LOCAL->courier = IS_COURIER(stream->mailbox);
  strcpy(tmp, stream->mailbox);
  if (maildir_file_path (stream->mailbox, tmp, sizeof(tmp)))
     LOCAL->dir = cpystr (tmp);
  LOCAL->candouid = maildir_can_assign_uid(stream);
  maildir_read_uid(stream, &stream->uid_last, &stream->uid_validity);
  if (LOCAL->dir){
     LOCAL->path = (char **) fs_get(EndDir*sizeof(char *));
     MDFLD(tmp, LOCAL->dir, Cur); LOCAL->path[Cur] = cpystr (tmp);
     MDFLD(tmp, LOCAL->dir, New); LOCAL->path[New] = cpystr (tmp);
     MDFLD(tmp, LOCAL->dir, Tmp); LOCAL->path[Tmp] = cpystr (tmp);
     if (stat (LOCAL->path[Cur],&sbuf) < 0) {
         snprintf (tmp, sizeof(tmp), "Can't open folder %s: %s",
				stream->mailbox,strerror (errno));
         mm_log (tmp,ERROR);
	 maildir_close(stream, 0);
        return NIL;
     }
  }

  if(maildir_file_path (stream->mailbox, tmp, sizeof(tmp))){
    fs_give ((void **) &stream->mailbox);
    stream->mailbox = cpystr(tmp);
  }

  LOCAL->buf = (char *) fs_get (CHUNKSIZE);
  LOCAL->buflen = CHUNKSIZE - 1;
  stream->sequence++;
  stream->nmsgs = stream->recent = 0L;

  maildir_parse_folder(stream, 1);

  return stream;
}

/* Maildir initial parsing of the folder */
void
maildir_parse_folder (MAILSTREAM *stream, int full)
{
   char tmp[MAILTMPLEN];
   struct direct **namescur = NIL, **namesnew = NIL;
   unsigned long i, nfilescur = 0L, nfilesnew = 0L, oldpos, newpos, total;
   int scan_err, rescan, loop = 0;

   if (!stream)		/* what??? */
      return;

   MM_CRITICAL(stream);

   maildir_scandir (LOCAL->path[New], &namesnew, &nfilesnew, &scan_err, CCLIENT);
   if (scan_err < 0)
      maildir_abort(stream);

   /* Scan old messages first, escoba! */
   if(stream->rdonly ||
      (LOCAL && ((maildir_initial_check(stream, Cur) == 0)
							|| nfilesnew > 0L))){
      LOCAL->scantime =  maildir_scandir (LOCAL->path[Cur], &namescur, &nfilescur, 
					&scan_err, CCLIENT);
      if (scan_err < 0){
	if(namesnew){
	  for(i = 0L; i < nfilesnew; i++)
	    fs_give((void **)&namesnew[i]);
	  fs_give((void **) &namesnew);
	}
	maildir_abort(stream);
      }
   }
   if(LOCAL && (maildir_initial_check(stream, New) == 0)
	&& (nfilescur > 0L)){
      while(LOCAL && loop < 10){
	 if(nfilesnew == 0L)
	   maildir_scandir (LOCAL->path[New], &namesnew, &nfilesnew, &scan_err, CCLIENT);
         if (scan_err < 0){
	    if(namesnew){
	      for(i = 0L; i < nfilesnew; i++)
		fs_give((void **)&namesnew[i]);
	      fs_give((void **) &namesnew);
	    }
	    maildir_abort(stream);
	    break;
	 }
	 for(i = 0L, rescan = 0, newpos = oldpos = 0L; 
		newpos < nfilescur && i < nfilesnew; i++){
	    if(maildir_message_in_list(namesnew[i]->d_name, namescur, oldpos, 
						nfilescur - 1L, &newpos)){
	       oldpos = newpos;
	       snprintf(tmp, sizeof(tmp), "%s/%s", LOCAL->path[New], namesnew[i]->d_name);
	       if(unlink(tmp) < 0)
		 scan_err = -1;
	       rescan++;
	    }
	    else
	      newpos = oldpos;
	 }
	 if(scan_err < 0)
	    maildir_abort(stream);
	 if(rescan == 0)
	   break;
	 else{ /* restart */
	   if(namesnew){
	     for(i = 0L; i < nfilesnew; i++)
		fs_give((void **)&namesnew[i]);
	     fs_give((void **) &namesnew);
	   }
	   nfilesnew = 0L;
	   loop++;
	 }
      }
   }
   if(loop == 10)
     maildir_abort(stream);
   if(LOCAL){
     if(stream->rdonly)
	stream->recent = 0L;
     total = namescur || stream->rdonly 
		? maildir_parse_dir(stream, 0L, Cur, namescur, 
					      nfilescur, full) : stream->nmsgs;
     stream->nmsgs = maildir_parse_dir(stream, total, New, namesnew, 
						nfilesnew, full);
   }
   if(namesnew){
     for(i = 0L; i < nfilesnew; i++)
	fs_give((void **)&namesnew[i]);
     fs_give((void **) &namesnew);
   }
   if(namescur){
     for(i = 0L; i < nfilescur; i++)
	fs_give((void **)&namescur[i]);
     fs_give((void **) &namescur);
   }
   MM_NOCRITICAL(stream);
}

int
maildir_initial_check (MAILSTREAM *stream, DirNamesType dirtype)
{
   char *tmp;
   struct stat sbuf;

   if (access (LOCAL->path[dirtype], R_OK|W_OK|X_OK) != 0){
      maildir_abort(stream);
      return -1;
   }

   if (dirtype != New && 
	(stat(LOCAL->path[Cur], &sbuf) < 0 || sbuf.st_ctime == LOCAL->scantime))
      return -1;
   return 0;
}


/* Return the number of messages in the directory, while filling the
 * elt structure.
 */

unsigned long
maildir_parse_dir(MAILSTREAM *stream, unsigned long nmsgs,
		  DirNamesType dirtype, struct direct **names, 
		  unsigned long nfiles, int full)
{
   char tmp[MAILTMPLEN], file[MAILTMPLEN], newfile[MAILTMPLEN], *mdstr;
   struct stat sbuf;
   unsigned long i, new = 0L, l, uid_last;
   unsigned long recent = stream ? stream->recent : 0L;
   int d = 0, f = 0, r = 0, s = 0, t = 0;
   int we_compute, in_list;
   int silent = stream ? stream->silent : NIL;
   MESSAGECACHE *elt;

   if (dirtype == Cur && !stream->rdonly)
      for (i = 1L; i <= stream->nmsgs;){
	elt = mail_elt(stream,  i);
	in_list = elt && elt->private.spare.ptr && nfiles > 0L
		  ? (MDPOS(elt) < nfiles 
		    ? same_maildir_file(MDFILE(elt), names[MDPOS(elt)]->d_name)
		    : NIL)
		    || maildir_message_in_list(MDFILE(elt), names, 0L, 
						nfiles - 1L, &MDPOS(elt))
		  : NIL;
	if (!in_list){
	   if (elt->private.spare.ptr)
	      maildir_free_file ((void **) &elt->private.spare.ptr);

	   if (elt->recent) --recent;
	   mail_expunged(stream,i);
	}
	else i++;
      }

   stream->silent = T;
   uid_last = 0L;
   for (we_compute = 0, i = l = 1L; l <= nfiles; l++){
      unsigned long pos, uid;
      if (dirtype == New && !stream->rdonly){ /* move new messages to cur */
	pos = l - 1L;
	snprintf (file, sizeof(file), "%s/%s", LOCAL->path[New], names[pos]->d_name);
	if(lstat(file,&sbuf) == 0)
	   switch(sbuf.st_mode & S_IFMT){
	    case S_IFREG:
		strcpy(tmp, names[pos]->d_name);
		if((mdstr = strstr(tmp,MDSEP(3))) 
		   || (mdstr = strstr(tmp,MDSEP(2))))
		   *(mdstr+1) = '2';
		else
		   strcat(tmp, MDSEP(2));
		snprintf(newfile, sizeof(newfile), "%s/%s", LOCAL->path[Cur], tmp);
		if(rename (file, newfile) != 0){
		   mm_log("Unable to read new mail!", WARN);
		   continue;
		}
		unlink (file);
		new++;
	        break;
	    case S_IFLNK:  /* clean up, clean up, everybody, everywhere */
		if(unlink(file) < 0){
		   if(LOCAL->link == NIL){ 
		      mm_log("Unable to remove symbolic link", WARN);
		      LOCAL->link = T;
		   }
		}
		continue;
		break;
	    default: 
		if(LOCAL && LOCAL->link == NIL){
		  mm_log("Unrecognized file or link in folder", WARN);
		  LOCAL->link = T;
		}
		continue;
		break;
	   }
      }
      mail_exists(stream, i + nmsgs);
      elt = mail_elt(stream, i + nmsgs);
      pos = (elt && elt->private.spare.ptr) ? MDPOS(elt) : l - 1L;
      if (dirtype == New) elt->recent = T;
      maildir_getflag(names[pos]->d_name, &d, &f, &r ,&s, &t);
      if (elt->private.spare.ptr)
	 maildir_free_file_only ((void **)&elt->private.spare.ptr);
      else{
	 maildir_get_file((MAILDIRFILE **)&elt->private.spare.ptr);
	 we_compute++;
      }
      MDFILE(elt) = cpystr(names[pos]->d_name);
      MDPOS(elt)  = pos;
      MDLOC(elt)  = dirtype;
      if (dirtype == Cur){	/* deal with UIDs */
	if(elt->private.uid == 0L)
	  elt->private.uid = maildir_get_uid(MDFILE(elt));
	if(elt->private.uid <= uid_last){
	  uid = (we_compute ? uid_last : stream->uid_last) + 1L;
	  if(LOCAL->candouid)
	    maildir_assign_uid(stream, i + nmsgs, uid);
	  else
	    elt->private.uid = uid;
	}
	else
	  uid = elt->private.uid;
	uid_last = uid;
	if(uid_last > stream->uid_last)
	  stream->uid_last = uid_last;
      }
      if(dirtype == New && !stream->rdonly){
	maildir_free_file_only((void **)&elt->private.spare.ptr);
	MDFILE(elt)  = cpystr(tmp);
	MDSIZE(elt)  = sbuf.st_size;
	MDMTIME(elt) = sbuf.st_mtime;
	MDLOC(elt)   = Cur;
      }
      if (elt->draft != d || elt->flagged != f || 
	elt->answered != r || elt->seen != s || elt->deleted != t){
	   elt->draft = d; elt->flagged = f; elt->answered = r;
	   elt->seen  = s; elt->deleted = t;
	   if (!we_compute && !stream->rdonly)
	      MM_FLAGS(stream, i+nmsgs);
      }
      maildir_get_date(stream, i+nmsgs);
      elt->valid = T;
      i++;
   }
   stream->silent = silent;
   if(LOCAL->candouid && dirtype == Cur)
      maildir_read_uid(stream, NULL, &stream->uid_validity);
   if (dirtype == New && stream->rdonly)
      new = nfiles;
   mail_exists(stream, nmsgs  + ((dirtype == New) ? new : nfiles));
   mail_recent(stream, recent + ((dirtype == New) ? new : 0L));

   return (nmsgs  + (dirtype == New ? new : nfiles));
}

long maildir_ping (MAILSTREAM *stream)
{
  maildir_parse_folder(stream, 0);
  if(stream && LOCAL){
     if(LOCAL->candouid < 0)
	LOCAL->candouid++;
     else if(LOCAL->candouid)
        maildir_uid_renew_tempfile(stream);
     else	 /* try again to get uids */
	LOCAL->candouid = maildir_can_assign_uid(stream);
  }
  return stream && LOCAL ? LONGT : NIL;
}

int maildir_select (const struct direct *name)
{
 return (name->d_name[0] != '.');
}

/*
 * Unfortunately, there is no way to sort by arrival in this driver, this
 * means that opening a folder in this driver using the scandir function
 * will always make this driver slower than any driver that has a natural
 * way of sorting by arrival (like a flat file format, "mbox", "mbx", etc).
 */
int maildir_namesort (const struct direct **d1, const struct direct **d2)
{
  const struct direct *e1 = *(const struct direct **) d1;
  const struct direct *e2 = *(const struct direct **) d2; 

  return comp_maildir_file((char *) e1->d_name, (char *) e2->d_name);
}

/* Maildir close */

void maildir_close (MAILSTREAM *stream, long options)
{
  MESSAGECACHE *elt;
  unsigned long i;
  int silent = stream ? stream->silent : 0;
  mailcache_t mc = (mailcache_t) mail_parameters (NIL,GET_CACHE,NIL);

  if (!stream) return;

  for (i = 1L; i <= stream->nmsgs; i++)
    if((elt = (MESSAGECACHE *) (*mc)(stream,i,CH_ELT)) && elt->private.spare.ptr)
      maildir_free_file ((void **) &elt->private.spare.ptr);
  stream->silent = T;
  if (options & CL_EXPUNGE) maildir_expunge (stream, NIL, NIL);
  maildir_abort(stream);
  if (mdfpath) fs_give((void **)&mdfpath);
  if (mypid) mypid = (pid_t) 0;
  stream->silent = silent;
}

void maildir_check (MAILSTREAM *stream)
{
  if (maildir_ping (stream)) mm_log ("Check completed",(long) NIL);   
}

long maildir_text (MAILSTREAM *stream,unsigned long msgno,STRING *bs, long flags)
{
  char tmp[MAILTMPLEN];
  unsigned long i;
  MESSAGECACHE *elt;
  char *s;
                                /* UID call "impossible" */
  if (flags & FT_UID || !LOCAL) return NIL;
  elt = mail_elt (stream, msgno);

  if (!(flags & FT_PEEK) && !elt->seen){
    elt->seen = T;
    maildir_flagmsg (stream, elt);
    MM_FLAGS(stream, elt->msgno);
  }

  MSGPATH(tmp, LOCAL->dir, MDFILE(elt), MDLOC(elt));
  if (LOCAL->fd < 0)	/* if file closed ? */
     LOCAL->fd = open(tmp,O_RDONLY,NIL);

  if (LOCAL->fd < 0 && (errno == EACCES || errno == ENOENT)){
     INIT (bs, mail_string, "", 0);
     elt->rfc822_size = 0L;
     return NIL;
  }

  s = maildir_text_work(stream, elt, &i, flags);
  INIT (bs, mail_string, s, i);
  return LONGT;
}

char *maildir_text_work (MAILSTREAM *stream,MESSAGECACHE *elt,
                      unsigned long *length,long flags)
{
  FDDATA d;
  STRING bs;
  char *s,tmp[CHUNK];
  unsigned long msgno = elt->msgno;
  static int try = 0;

  if (length)
     *length = 0L;
  LOCAL->buf[0] = '\0';

  MSGPATH(tmp, LOCAL->dir, MDFILE(elt), MDLOC(elt));
  if (LOCAL->fd < 0)	/* if file closed ? */
     LOCAL->fd = open(tmp,O_RDONLY,NIL);

  if (LOCAL->fd < 0){		/* flag change? */
      if (try < 5){
	try++;
	if (maildir_update_elt_maildirp(stream, msgno) > 0)
	  try = 0;
	return maildir_text_work(stream, mail_elt(stream, msgno),length, flags);
      }
      try = 0;
      return NULL;
  }

  lseek (LOCAL->fd, elt->private.msg.text.offset,L_SET);

  if (flags & FT_INTERNAL) {    /* initial data OK? */
    if (elt->private.msg.text.text.size > LOCAL->buflen) {
      fs_give ((void **) &LOCAL->buf);
      LOCAL->buf = (char *) fs_get ((LOCAL->buflen =
                                     elt->private.msg.text.text.size) + 1);
    }
    read (LOCAL->fd,LOCAL->buf,elt->private.msg.text.text.size);
    LOCAL->buf[*length = elt->private.msg.text.text.size] = '\0';
  }
  else {
    if (elt->rfc822_size > LOCAL->buflen) {
      fs_give ((void **) &LOCAL->buf);
      LOCAL->buf = (char *) fs_get ((LOCAL->buflen = elt->rfc822_size) + 1);
    }
    d.fd = LOCAL->fd;           /* yes, set up file descriptor */
    d.pos = elt->private.msg.text.offset;
    d.chunk = tmp;              /* initial buffer chunk */
    d.chunksize = CHUNK;
    INIT (&bs,fd_string,&d,elt->private.msg.text.text.size);
    for (s = LOCAL->buf; SIZE (&bs);) switch (CHR (&bs)) {
    case '\r':                  /* carriage return seen */
      *s++ = SNX (&bs);         /* copy it and any succeeding LF */
      if (SIZE (&bs) && (CHR (&bs) == '\n')) *s++ = SNX (&bs);
      break;
    case '\n':
      *s++ = '\r';              /* insert a CR */
    default:
      *s++ = SNX (&bs);         /* copy characters */
    }
    *s = '\0';                  /* tie off buffer */
    *length = s - (char *) LOCAL->buf;   /* calculate length */
  }
  close(LOCAL->fd); LOCAL->fd = -1;
  return LOCAL->buf;
}

/* maildir parse, fill the elt structure... well not all of it... */
unsigned long maildir_parse_message(MAILSTREAM *stream, unsigned long msgno,
				    DirNamesType dirtype)
{
  char *b, *s, *t, c;
  char tmp[MAILTMPLEN];
  struct stat sbuf;
  unsigned long i, len;
  int d, f, r, se, dt;
  MESSAGECACHE *elt;

  elt = mail_elt (stream,msgno);
  MSGPATH(tmp, LOCAL->dir, MDFILE(elt), dirtype);
  if(stat(tmp, &sbuf) == 0)
     MDSIZE(elt) = sbuf.st_size;

  maildir_get_date(stream, msgno);
  maildir_getflag(MDFILE(elt), &d, &f, &r ,&se, &dt);
  elt->draft = d; elt->flagged = f; elt->answered = r; elt->seen = se;
  elt->deleted = dt; elt->valid  = T;
  if (LOCAL->fd < 0)	/* if file closed ? */
     LOCAL->fd = open(tmp,O_RDONLY,NIL);

  if (LOCAL->fd >= 0){
	s = (char *) fs_get (MDSIZE(elt) + 1);
	read (LOCAL->fd,s,MDSIZE(elt));
	s[MDSIZE(elt)] = '\0';
	t = s + strlen(s);	/* make t point to the end of s */
	for (i = 0L, b = s; b < t && !(i && (*b == '\n')); i = (*b++ == '\n'));
	len = (*b ? ++b : b) - s;
	elt->private.msg.header.text.size = 
		elt->private.msg.text.offset = len;
	elt->private.msg.text.text.size = MDSIZE(elt) - len;
	for (i = 0L, b = s, c = *b; b &&
	    ((c < '\016' && ((c == '\012' && ++i) 
			 ||(c == '\015' && *(b+1) == '\012' && ++b && (i +=2))))
	    || b < t); i++, c= *++b);
	elt->rfc822_size = i;
	fs_give ((void **) &s);
	close(LOCAL->fd); LOCAL->fd = -1;
  }
  return elt->rfc822_size;
}

int
maildir_update_elt_maildirp(MAILSTREAM *stream, unsigned long msgno)
{
     struct direct **names = NIL;
     unsigned long i, nfiles, pos;
     int d = 0, f = 0 , r = 0, s = 0, t = 0, in_list, scan_err;
     MESSAGECACHE *elt;

     maildir_scandir (LOCAL->path[Cur], &names, &nfiles, &scan_err, CCLIENT);

     elt = mail_elt (stream,msgno);

     in_list = nfiles > 0L
	    ? maildir_message_in_list(MDFILE(elt), names, 0L, nfiles - 1L, &pos)
	    : NIL;

     if (in_list && pos >= 0L && pos < nfiles
	 && !strcmp(MDFILE(elt), names[pos]->d_name)){
	in_list = NIL;
	maildir_abort(stream);
     }

     if (in_list && pos >= 0L && pos < nfiles){
	maildir_free_file_only((void **)&elt->private.spare.ptr);
	MDFILE(elt) = cpystr(names[pos]->d_name);
	maildir_getflag(MDFILE(elt), &d, &f, &r ,&s, &t);
	if (elt->draft != d || elt->flagged != f || 
	   elt->answered != r || elt->seen != s || elt->deleted != t){
	   elt->draft = d; elt->flagged = f; elt->answered = r;
	   elt->seen  = s; elt->deleted = t;
	   MM_FLAGS(stream, msgno);
        }
     }
     for (i = 0L; i < nfiles; i++)
	fs_give((void **) &names[i]);
     if (names)
	fs_give((void **) &names);
     return in_list ? 1 : -1;
}

/* Maildir fetch message header */

char *maildir_header (MAILSTREAM *stream,unsigned long msgno,
		unsigned long *length, long flags)
{
  char tmp[MAILTMPLEN], *s;
  MESSAGECACHE *elt;
  static int try = 0;

  if (length) *length = 0;
  if (flags & FT_UID || !LOCAL) return "";	/* UID call "impossible" */
  elt = mail_elt (stream,msgno);
  if(elt->private.msg.header.text.size == 0)
     maildir_parse_message(stream, msgno, MDLOC(elt));

  MSGPATH(tmp, LOCAL->dir, MDFILE(elt), MDLOC(elt));
  if (LOCAL->fd < 0)
     LOCAL->fd = open (tmp,O_RDONLY,NIL);

  if (LOCAL->fd < 0 && errno == EACCES){
     mm_log ("Message exists but can not be read. Envelope and body lost!",ERROR);
     return NULL;
  }

  if (LOCAL->fd < 0){			/* flag change? */
      if (try < 5){
	try++;
	if (maildir_update_elt_maildirp(stream, msgno) > 0)
	  try = 0;
	return maildir_header(stream, msgno, length, flags);
      }
      try = 0;
      return NULL;
  }

  if (flags & FT_INTERNAL){
     if(elt->private.msg.header.text.size > LOCAL->buflen){
         fs_give ((void **) &LOCAL->buf);
         LOCAL->buf = (char *) fs_get ((LOCAL->buflen =
                                 elt->private.msg.header.text.size) + 1);
     }
     read (LOCAL->fd, (void *)LOCAL->buf, elt->private.msg.header.text.size);
     LOCAL->buf[*length = elt->private.msg.header.text.size] = '\0';
  }
  else{
      s = (char *) fs_get(elt->private.msg.header.text.size+1);
      read (LOCAL->fd, (void *)s, elt->private.msg.header.text.size);
      s[elt->private.msg.header.text.size] = '\0';
      *length = strcrlfcpy (&LOCAL->buf,&LOCAL->buflen,s,
                       elt->private.msg.header.text.size);
      fs_give ((void **) &s);
  }
  elt->private.msg.text.offset = elt->private.msg.header.text.size;
  elt->private.msg.text.text.size = MDSIZE(elt) - elt->private.msg.text.offset;
  close(LOCAL->fd); LOCAL->fd = -1;
  return LOCAL->buf;
}

/* Maildir find list of subscribed mailboxes
 * Accepts: mail stream
 *	    pattern to search
 */

void maildir_list (MAILSTREAM *stream,char *ref, char *pat)
{
  char *s,test[MAILTMPLEN],file[MAILTMPLEN];
  long i = 0L;

  if((!pat || !*pat) && maildir_canonicalize (test,ref,"*")
	&& maildir_valid_name(test)){	/* there is a #md/ leading here */
    for (i = 3L; test[i] && test[i] != '/'; i++);
    if ((s = strchr (test+i+1,'/')) != NULL) *++s = '\0';
    else test[0] = '\0';
    mm_list (stream,'/',test, LATT_NOSELECT);
  }
  else if (maildir_canonicalize (test,ref,pat)) {
    if (test[3] == '/') {       /* looking down levels? */
                                /* yes, found any wildcards? */
      if ((s = strpbrk (test,"%*")) != NULL){
                                /* yes, copy name up to that point */
        strncpy (file,test+4,i = s - (test+4));
        file[i] = '\0';         /* tie off */
      }
      else strcpy (file,test+4);/* use just that name then */
                                /* find directory name */
      if ((s = strrchr (file, '/')) != NULL){
        *s = '\0';              /* found, tie off at that point */
        s = file;
      }
                                /* do the work */
      if(IS_COURIER(test))
	courier_list_work (stream,s,test,0);
      else
	maildir_list_work (stream,s,test,0);
    }
                                /* always an INBOX */
    if (!compare_cstring (test,"#MD/INBOX"))
      mm_list (stream,NIL,"#MD/INBOX",LATT_NOINFERIORS);
    if (!compare_cstring (test,"#MC/INBOX"))
      mm_list (stream,NIL,"#MC/INBOX",LATT_NOINFERIORS);
  }
}

void courier_list (MAILSTREAM *stream,char *ref, char *pat)
{
/* I am too lazy to do anything. Do you care to ask maildir list, please?
   The real reason why this is a dummy function is because we do not want to
   see the same folder listed twice. 
*/
}

/* For those that want to hide things, we give them a chance to do so */
void *maildir_parameters (long function, void *value)
{
  void *ret = NIL;
  switch ((int) function) {
  case SET_MDINBOXPATH:
    if(strlen((char *) value ) > 49)
       strcpy(myMdInboxDir, "Maildir");
    else
       strcpy(myMdInboxDir, (char *) value);
  case GET_MDINBOXPATH:
    if (myMdInboxDir[0] == '\0') strcpy(myMdInboxDir,"Maildir");
    ret = (void *) myMdInboxDir;
    break;
  case SET_COURIERSTYLE:
    CourierStyle = (long) value;
  case GET_COURIERSTYLE:
    ret = (void *) CourierStyle;
    break;
  case GET_DIRFMTTEST:
    ret = (void *) maildir_dirfmttest;
    break;
  default:
    break;
  }
  return ret;
}

int maildir_create_folder(char *mailbox)
{
  char tmp[MAILTMPLEN], err[MAILTMPLEN];
  DirNamesType i;

  for (i = Cur; i != EndDir; i++){
	MDFLD(tmp, mailbox, i);
	if (mkdir(tmp, 0700) && errno != EEXIST){ /* try to make new dir */
	    snprintf (err, sizeof(err), "Can't create %s: %s", tmp, strerror(errno));
	    mm_log (err,ERROR);
	    return NIL;
	}
  }
  return T;
}

int maildir_create_work(char *mailbox, int loop)
{
  char *s, c, err[MAILTMPLEN], tmp[MAILTMPLEN], tmp2[MAILTMPLEN], mbx[MAILTMPLEN];
  int fnlen, create_dir = 0, courier, mv;
  struct stat sbuf;
  long style = (long) maildir_parameters(GET_COURIERSTYLE, NIL);

  courier = IS_COURIER(mailbox);
  strcpy(mbx, mailbox);
  mv = maildir_valid(mbx) ? 1 : 0;
  maildir_file_path(mailbox, tmp, sizeof(tmp));
  if (mailbox[strlen(mailbox) - 1] == MDSEPARATOR(courier)){
      create_dir++;
      mailbox[strlen(mailbox) - 1] = '\0';
  }

  if(!loop && courier){
    if(mv){
       if(create_dir){
	  if(style == CCLIENT)
	   strcpy (err,"Can not create directory: folder exists. Create subfolder");
	  else
	   strcpy(err,"Folder and Directory already exist");
       }
       else
          strcpy (err, "Can't create mailbox: mailbox already exists");
    }
    else{
	if(create_dir)
	   strcpy(err, "Can not create directory. Cread folder instead");
	else
	  err[0] = '\0';
    }
    if(err[0]){
       mm_log (err,ERROR);
       return NIL;
    }
  }

  fnlen = strlen(tmp);
  if ((s = strrchr(mailbox,MDSEPARATOR(courier))) != NULL){
     c = *++s;
    *s = '\0';
    if ((stat(tmp,&sbuf) || ((sbuf.st_mode & S_IFMT) != S_IFDIR)) &&
        !maildir_create_work (mailbox, ++loop))
      return NIL;
    *s = c;
  }
  tmp[fnlen] = '\0';

  if (mkdir(tmp,0700) && errno != EEXIST)
     return NIL;

  if (create_dir)
     mailbox[fnlen] = '/';

  if (create_dir){
     if(style == CCLIENT){
	if(!courier){
	   FILE *fp = NULL;
	   snprintf(tmp2, sizeof(tmp2), "%s%s", tmp, MDDIR);
	   if ((fp = fopen(tmp2,"w")) == NULL){
	      snprintf (err, sizeof(err), "Problem creating %s: %s", tmp2, strerror(errno));
              mm_log (err,ERROR);
              return NIL;
	   }
	   fclose(fp);
	}
     }
     return T;
  }
  else
     return maildir_create_folder(tmp);
}

long maildir_create (MAILSTREAM *stream,char *mailbox)
{
  char tmp[MAILTMPLEN], err[MAILTMPLEN];
  int rv, create_dir;

  create_dir = mailbox ? 
		(mailbox[strlen(mailbox) - 1] == 
					MDSEPARATOR(IS_COURIER(mailbox))) : 0;
  maildir_file_path(mailbox, tmp, sizeof(tmp));
  strcpy(tmp, mailbox);
  rv = maildir_create_work(mailbox, 0);
  strcpy(mailbox, tmp);
  if (rv == 0){
     snprintf (err, sizeof(err), "Can't create %s %s",
		   (create_dir ? "directory" : "mailbox"), mailbox);
     mm_log (err,ERROR);
  }
  return rv ? LONGT : NIL;
}

#define MAXTRY 10000
void maildir_flagmsg (MAILSTREAM *stream,MESSAGECACHE *elt)
{
  char oldfile[MAILTMPLEN],newfile[MAILTMPLEN],fn[MAILTMPLEN];
  char *s;
  int ren, try = 0;

  if (elt->valid){
     for (try = 1; try > 0 && try < MAXTRY; try++){
                                /* build the new filename */
	snprintf (oldfile, sizeof(oldfile), "%s/%s",LOCAL->path[Cur], MDFILE(elt));
	fn[0] = '\0';
	if ((ren = maildir_message_exists(stream, MDFILE(elt), fn)) == 0){
	    errno = ENOENT;
	    try = MAXTRY;
	}
	if (*fn)	/* new oldfile! */
	   snprintf (oldfile,sizeof(oldfile),"%s/%s", LOCAL->path[Cur], fn);
        if ((s = strrchr (MDFILE(elt), FLAGSEP))) *s = '\0';
	snprintf (fn, sizeof(fn), "%s%s%s%s%s%s%s", MDFILE(elt), MDSEP(2),
		MDFLAG(Draft, elt->draft), MDFLAG(Flagged, elt->flagged),
		MDFLAG(Replied, elt->answered), MDFLAG(Seen, elt->seen),
		MDFLAG(Trashed, elt->deleted));
	snprintf (newfile, sizeof(newfile), "%s/%s",LOCAL->path[Cur],fn);
        if (ren != 0 && rename (oldfile,newfile) >= 0)
	    try = -1;
     }

     if (try > 0){
       snprintf(oldfile, sizeof(oldfile), "Unable to write flags to disk: %s",
		(errno == ENOENT) ? "message is gone!" : strerror (errno));
       mm_log(oldfile,ERROR);
       return;
     }
#ifdef __CYGWIN__
     utime(LOCAL->path[Cur], NIL);	/* make sure next scan will catch the change */
#endif
     maildir_free_file_only ((void **) &elt->private.spare.ptr);
     MDFILE(elt) = cpystr (fn);
  }
}

long maildir_expunge (MAILSTREAM *stream, char *sequence, long options)
{
  long ret;
  MESSAGECACHE *elt;
  unsigned long i, n = 0L;
  unsigned long recent = stream->recent;
  char tmp[MAILTMPLEN];

  mm_critical (stream);               /* go critical */
  ret = sequence ? ((options & EX_UID) ?
                         mail_uid_sequence (stream,sequence) :
                         mail_sequence (stream,sequence)) : LONGT;
  if(ret == 0L)
     return 0L;
  for (i = 1L; i <= stream->nmsgs;){
    elt = mail_elt (stream,i);
    if (elt->deleted && (sequence ? elt->sequence : T)){
      snprintf (tmp, sizeof(tmp), "%s/%s", LOCAL->path[Cur], MDFILE(elt));
      if (unlink (tmp) < 0) {/* try to delete the message */
      snprintf (tmp, sizeof(tmp), "Expunge of message %ld failed, aborted: %s",i,
              strerror (errno));
      if (!stream->silent)
         mm_log (tmp,WARN);
      break;
      }
      if (elt->private.spare.ptr)
       maildir_free_file ((void **) &elt->private.spare.ptr);
      if (elt->recent) --recent;/* if recent, note one less recent message */
      mail_expunged (stream,i);       /* notify upper levels */
       n++;                    /* count up one more expunged message */
    }
    else i++;
  }
  if(n){                      /* output the news if any expunged */
    snprintf (tmp, sizeof(tmp), "Expunged %ld messages", n);
    if (!stream->silent)
       mm_log (tmp,(long) NIL);
  }
  else
    if (!stream->silent)
      mm_log ("No messages deleted, so no update needed",(long) NIL);
  mm_nocritical (stream);     /* release critical */
                            /* notify upper level of new mailbox size */
  mail_exists (stream, stream->nmsgs);
  mail_recent (stream, recent);
  return ret;
}

long maildir_copy (MAILSTREAM *stream,char *sequence,char *mailbox,long options)
{
  STRING st;
  MESSAGECACHE *elt;
  unsigned long len;
  int fd;
  unsigned long i;
  struct stat sbuf;
  char tmp[MAILTMPLEN], flags[MAILTMPLEN], path[MAILTMPLEN], *s;
				/* copy the messages */
  if ((options & CP_UID) ? mail_uid_sequence (stream, sequence) : 
  	mail_sequence (stream,sequence)) 
  for (i = 1L; i <= stream->nmsgs; i++)
    if ((elt = mail_elt (stream,i))->sequence){
      MSGPATH(path, LOCAL->dir, MDFILE(elt), MDLOC(elt));
      if (((fd = open (path,O_RDONLY,NIL)) < 0)	 
	  ||((!elt->rfc822_size && 
		((stat(path, &sbuf) < 0) || !S_ISREG (sbuf.st_mode)))))
	return NIL;
	if(!elt->rfc822_size)
	  MDSIZE(elt) = sbuf.st_size;
        s = (char *) fs_get(MDSIZE(elt) + 1);
        read (fd,s,MDSIZE(elt));
        s[MDSIZE(elt)] = '\0';
        close (fd);
	len = strcrlfcpy (&LOCAL->buf,&LOCAL->buflen, s, MDSIZE(elt));
        INIT (&st,mail_string, LOCAL->buf, len);
	elt->rfc822_size = len;
	fs_give ((void **)&s);

      flags[0] = flags[1] = '\0';
      if (elt->seen) strcat (flags," \\Seen");
      if (elt->draft) strcat (flags," \\Draft");
      if (elt->deleted) strcat (flags," \\Deleted");
      if (elt->flagged) strcat (flags," \\Flagged");
      if (elt->answered) strcat (flags," \\Answered");
      flags[0] = '(';		/* open list */
      strcat (flags,")");	/* close list */
      mail_date (tmp,elt);	/* generate internal date */
      if (!mail_append_full (NIL, mailbox, flags, tmp, &st))
        return NIL;
      if (options & CP_MOVE) elt->deleted = T;
    }
  return LONGT;			/* return success */
}

long maildir_append (MAILSTREAM *stream,char *mailbox,append_t af,void *data)
{
  int fd, k;
  STRING *message;
  char c,*s, *flags, *date;
  char tmp[MAILTMPLEN],file[MAILTMPLEN],path1[MAILTMPLEN],path2[MAILTMPLEN];
  MESSAGECACHE elt;
  long i, size = 0L, ret = LONGT, f;
  unsigned long uf, ti;
  static unsigned int transact = 0;

  if (!maildir_valid(mailbox)) {
    snprintf (tmp, sizeof(tmp), "Not a valid Maildir mailbox: %s", mailbox);
    mm_log (tmp,ERROR);
    return NIL;
  }

 if (!*mdlocaldomain)
     md_domain_name();    /* get domain name for maildir files in mdlocaldomain now! */

 if (mypid == (pid_t) 0)
    mypid = getpid();

 if (!stream){
    stream = &maildirproto;
  
    for (k = 0; k < NUSERFLAGS && stream->user_flags[k]; ++k)
       fs_give ((void **) &stream->user_flags[k]);
 }

  if (!(*af)(stream, data, &flags, &date, &message)) return NIL;

  mm_critical (stream);		/* go critical */
  /* call time(0) only once, use transact to distinguish instead */
  ti = time(0);
  do {
    if (!SIZE (message)) {      /* guard against zero-length */
      mm_log ("Append of zero-length message",ERROR);
      ret = NIL;
      break;
    }
    if (date && !mail_parse_date(&elt,date)){
        snprintf (tmp, sizeof(tmp), "Bad date in append: %.80s",date);
        mm_log (tmp,ERROR);
        ret = NIL;
        break;
    }
    f = mail_parse_flags (stream,flags,&uf);
				/* build file name we will use */
    snprintf (file, sizeof(file), "%lu.%d_%09u.%s%s%s%s%s%s",
		ti, mypid, transact++, mdlocaldomain, (f ? MDSEP(2) : ""),
		MDFLAG(Draft, f&fDRAFT), MDFLAG(Flagged, f&fFLAGGED),
		MDFLAG(Replied, f&fANSWERED), MDFLAG(Seen, f&fSEEN));
				/* build tmp file name */
    if (maildir_file_path(mailbox, tmp, sizeof(tmp)))
       MSGPATH(path1, tmp, file, Tmp);

    if ((fd = open (path1,O_WRONLY|O_CREAT|O_EXCL,S_IREAD|S_IWRITE)) < 0) {
       snprintf (tmp, sizeof(tmp), "Can't open append mailbox: %s", strerror (errno));
       mm_log (tmp, ERROR);
       return NIL;
    }
    for (size = 0,i = SIZE (message),s = (char *) fs_get (i + 1); i; --i)
      if ((c = SNX (message)) != '\015') s[size++] = c;
    if ((write (fd, s, size) < 0) || fsync (fd)) {
	unlink (path1);		/* delete message */
	snprintf (tmp, sizeof(tmp), "Message append failed: %s", strerror (errno));
	mm_log (tmp, ERROR);
	ret = NIL;
    }
    fs_give ((void **) &s);	/* flush the buffer */
    close (fd);			/* close the file */
				/* build final filename to use */
    if (maildir_file_path(mailbox, tmp, sizeof(tmp)))
	MSGPATH(path2, tmp, file, New);
    if (rename (path1,path2) < 0) {
       snprintf (tmp, sizeof(tmp), "Message append failed: %s", strerror (errno));
       mm_log (tmp, ERROR);
       ret = NIL;
    }
    unlink (path1);

    if (ret)
     if (!(*af) (stream,data,&flags,&date,&message)) ret = NIL;

  } while (ret && message);	/* write the data */
  mm_nocritical (stream);	/* release critical */
  return ret;
}

long maildir_delete (MAILSTREAM *stream,char *mailbox)
{
  DIR *dirp;
  struct direct *d;
  int i, remove_dir = 0, mddir = 0, rv, error = 0;
  char tmp[MAILTMPLEN],tmp2[MAILTMPLEN], realname[MAILTMPLEN];
  struct stat sbuf;
  int courier = IS_COURIER(mailbox);

  if (mailbox[strlen(mailbox) - 1] == MDSEPARATOR(courier)){
      remove_dir++;
      mailbox[strlen(mailbox) -1] = '\0';
  }

  if (!maildir_valid(mailbox)){
      maildir_file_path(mailbox, tmp, sizeof(tmp));
      if (stat(tmp, &sbuf) < 0 || !S_ISDIR(sbuf.st_mode)){
        snprintf(tmp, sizeof(tmp), "Can not remove %s", mailbox);
	error++;
      }
  }

  if (!error && remove_dir && !maildir_dir_is_empty(mailbox)){
     snprintf(tmp, sizeof(tmp), "Can not remove directory %s/: directory not empty", mailbox);
     error++;
  }

  if(error){
     mm_log (tmp,ERROR);
     return NIL;
  }

  maildir_close(stream,0);	/* even if stream was NULL */

  maildir_file_path(mailbox, realname, sizeof(realname));

  if (remove_dir){
     snprintf(tmp, sizeof(tmp), "%s/%s", realname, MDDIR);
     if ((rv = stat (tmp,&sbuf)) == 0 && S_ISREG(sbuf.st_mode))
	rv = unlink(tmp);
     else if (errno == ENOENT)
	rv = 0;
     if (rv != 0){
	snprintf(tmp, sizeof(tmp), "Can not remove %s/%s: %s", tmp2, MDDIR, strerror(errno));
	mm_log (tmp,ERROR);
	return NIL;
     }
     if (!maildir_valid(realname) && rmdir(realname) != 0){
	snprintf(tmp, sizeof(tmp), "Can not remove %s/: %s", mailbox, strerror(errno));
	mm_log (tmp, ERROR);
	return NIL;
     }
     return LONGT;
  }
  /* else remove just the folder. Remove all hidden files, except MDDIR */
  for (i = Cur; i != EndDir; i++){
      MDFLD(tmp, realname, i);

      if (!(dirp = opendir (tmp))){
	  snprintf(tmp, sizeof(tmp), "Can not read %s/: %s", mailbox, strerror(errno));
	  mm_log (tmp, ERROR);
	  return NIL;
      }

      while ((d = readdir(dirp)) != NULL){
	 if (strcmp(d->d_name, ".") && strcmp(d->d_name,"..")){
	    snprintf(tmp2, sizeof(tmp2), "%s/%s", tmp, d->d_name);
	    if (unlink(tmp2) != 0){
	       snprintf(tmp2, sizeof(tmp2), "Can not remove %s: %s", mailbox, strerror(errno));
	       mm_log (tmp2, ERROR);
	       return NIL;
	    }
	 }
      }
      closedir(dirp);
      if (rmdir(tmp) != 0){
	 snprintf(tmp, sizeof(tmp), "Can not remove %s: %s", mailbox, strerror(errno));
	 mm_log (tmp, ERROR);
	 return NIL;
      }
  }
  /* 
   * ok we have removed all subdirectories of the folder mailbox, Remove the
   * hidden files.
   */

  if(!(dirp = opendir (realname))){
    snprintf(tmp, sizeof(tmp), "Can not read %s/: %s", realname, strerror(errno));
    mm_log (tmp, ERROR);
    return NIL;
  }

  while ((d = readdir(dirp)) != NULL){
	if (strcmp(d->d_name, ".") && strcmp(d->d_name,"..")
		&& (!strcmp(d->d_name, MDDIR)
			|| !strncmp(d->d_name, MDUIDLAST, strlen(MDUIDLAST))
			|| !strncmp(d->d_name, MDUIDTEMP, strlen(MDUIDTEMP)))){
	   if(strcmp(d->d_name, MDDIR) == 0)
	      mddir++;
	   snprintf(tmp, sizeof(tmp), "%s/%s", realname, d->d_name);
	   if (unlink(tmp) != 0)
	      error++;
	}
  }
  closedir(dirp);
  if (error || 
	 (maildir_dir_is_empty(mailbox) && mddir == 0 && rmdir(realname) < 0)){
        snprintf(tmp, sizeof(tmp), "Can not remove folder %s: %s", mailbox, strerror(errno));
        mm_log (tmp, ERROR);
        return NIL;
  }
  return LONGT;
}

long maildir_rename (MAILSTREAM *stream, char *old, char *new)
{
  char tmp[MAILTMPLEN], tmpnew[MAILTMPLEN], realold[MAILTMPLEN];
  char realnew[MAILTMPLEN];
  int courier = IS_COURIER(old) && IS_COURIER(new);
  int i;
  long rv = LONGT;
  COURIER_S *cdir;

  if((IS_COURIER(old) || IS_COURIER(new)) && !courier){
    snprintf (tmp, sizeof(tmp), "Can't rename mailbox %s to %s", old, new);
    mm_log (tmp, ERROR);
    return NIL;
  }

  if (!maildir_valid(old)){
    snprintf (tmp, sizeof(tmp), "Can't rename mailbox %s: folder not in maildir format",old);
    mm_log (tmp, ERROR);
    return NIL;
  }
  maildir_file_path(old, realold, sizeof(realold));
  if (!maildir_valid_name(new) && new[0] == '#'){
    snprintf (tmp, sizeof(tmp), "Cannot rename mailbox %s: folder not in maildir format", new);
    mm_log (tmp, ERROR);
    return NIL;
  }
  maildir_file_path(new, realnew, sizeof(realnew));
  if (access(tmpnew,F_OK) == 0){ 	/* new mailbox name must not exist */
    snprintf (tmp, sizeof(tmp), "Cannot rename to mailbox %s: destination already exists", new);
    mm_log (tmp, ERROR);
    return NIL;
  }

  if(!courier){
    if (rename(realold, realnew)){	/* try to rename the directory */
       snprintf(tmp, sizeof(tmp), "Can't rename mailbox %s to %s: %s", old, new,
							strerror(errno));
       mm_log(tmp,ERROR);
       return NIL;
    }
    return LONGT;	/* return success */
  }

  cdir = courier_list_dir(old);
  for (i = 0; cdir && i < cdir->total; i++){
      if(strstr(cdir->data[i]->name, old)){
	snprintf(tmp, sizeof(tmp), "%s%s", new, cdir->data[i]->name+strlen(old));
	maildir_file_path(cdir->data[i]->name, realold, sizeof(realold));
	maildir_file_path(tmp, realnew, sizeof(realnew));
	if (rename(realold, realnew)){
	   snprintf (tmp, sizeof(tmp), "Can't rename mailbox %s to %s: %s", old, new,
							strerror(errno));
	   mm_log(tmp,ERROR);
	   rv = NIL;
	}
    }
  }
  courier_free_cdir(&cdir);
  return rv;
}

long maildir_sub(MAILSTREAM *stream,char *mailbox)
{
  return sm_subscribe(mailbox);
}

long maildir_unsub(MAILSTREAM *stream,char *mailbox)
{
  return sm_unsubscribe(mailbox);
}

void maildir_lsub (MAILSTREAM *stream,char *ref,char *pat)
{
  void *sdb = NIL;
  char *s, test[MAILTMPLEN];
                                /* get canonical form of name */
  if (maildir_canonicalize (test, ref, pat) && (s = sm_read (&sdb))) {
    do if (pmatch_full (s, test, '/')) mm_lsub (stream, '/', s, NIL);
    while ((s = sm_read (&sdb)) != NULL); /* until no more subscriptions */
  }
}

long maildir_canonicalize (char *pattern,char *ref,char *pat)
{
  if (ref && *ref) {            /* have a reference */
    strcpy (pattern,ref);       /* copy reference to pattern */
                                /* # overrides mailbox field in reference */
    if (*pat == '#') strcpy (pattern,pat);
                                /* pattern starts, reference ends, with / */
    else if ((*pat == '/') && (pattern[strlen (pattern) - 1] == '/'))
      strcat (pattern,pat + 1); /* append, omitting one of the period */
                                                                                
    else strcat (pattern,pat);  /* anything else is just appended */
  }
  else strcpy (pattern,pat);    /* just have basic name */
  return maildir_valid_name(pattern) ? LONGT : NIL;
}

void maildir_list_work (MAILSTREAM *stream,char *dir,char *pat,long level)
{
  DIR *dp;
  struct direct *d;
  struct stat sbuf;
  char curdir[MAILTMPLEN],name[MAILTMPLEN], tmp[MAILTMPLEN];
  char realpat[MAILTMPLEN];
  long i;
  char *maildirpath = mdirpath();

  snprintf(curdir, sizeof(curdir), "%s/%s/", myrootdir(pat), dir ? dir : maildirpath);
  if ((dp = opendir (curdir)) != NULL){ 
     if (dir) snprintf (name, sizeof(name), "%s%s/",MDPREFIX(CCLIENT),dir);
     else strcpy (name, pat);

     if (level == 0 && !strpbrk(pat,"%*")){
	if(maildir_valid(pat)){
	  i =  maildir_contains_folder(pat, NULL)
		? LATT_HASCHILDREN
		: (maildir_is_dir(pat, NULL)
			     ? LATT_HASNOCHILDREN : LATT_NOINFERIORS);
	  maildir_file_path(pat, realpat, sizeof(realpat));
	  i +=  maildir_any_new_msgs(realpat) 
			? LATT_MARKED : LATT_UNMARKED;
	  mm_list (stream,'/', pat, i);
	}
	else
	   if(pat[strlen(pat) - 1] == '/')
	     mm_list (stream,'/', pat, LATT_NOSELECT);
     }

     while ((d = readdir (dp)) != NULL)
	if(strcmp(d->d_name, ".") && strcmp(d->d_name,"..")
		&& strcmp(d->d_name, MDNAME(Cur)) 
		&& strcmp(d->d_name, MDNAME(Tmp)) 
		&& strcmp(d->d_name, MDNAME(New))){

	  if (dir) snprintf (tmp, sizeof(tmp), "%s%s", name,d->d_name);
	  else strcpy(tmp, d->d_name);

	  if(pmatch_full (tmp, pat,'/')){
	     snprintf(tmp, sizeof(tmp), "%s/%s/%s", myrootdir(d->d_name), 
				(dir ? dir : maildirpath), d->d_name);
	     if(stat (tmp,&sbuf) == 0 
		   && ((sbuf.st_mode & S_IFMT) == S_IFDIR)){
	       if (dir) snprintf (tmp, sizeof(tmp), "%s%s", name,d->d_name);
	       else strcpy(tmp, d->d_name);
               i = maildir_valid(tmp)
			? (maildir_contains_folder(dir, d->d_name)
			  ? LATT_HASCHILDREN
			  : (maildir_is_dir(dir, d->d_name)
			     ? LATT_HASNOCHILDREN : LATT_NOINFERIORS))
			: LATT_NOSELECT;
	       i +=  maildir_any_new_msgs(tmp)
			    ? LATT_MARKED : LATT_UNMARKED;
	       mm_list (stream,'/',tmp, i);
	       strcat (tmp, "/");
	       if(dmatch (tmp, pat,'/') &&
                 (level < (long) mail_parameters (NIL,GET_LISTMAXLEVEL,NIL))){
		   snprintf(tmp, sizeof(tmp), "%s/%s",dir,d->d_name);
 		   maildir_list_work (stream,tmp,pat,level+1);
	       }
	     }
	  }
       }
     closedir (dp);
  }
}

void courier_list_work (MAILSTREAM *stream, char *dir, char *pat, long level)
{
  char c, curdir[MAILTMPLEN], tmp[MAILTMPLEN];
  char realname[MAILTMPLEN], realpat[MAILTMPLEN] = {'\0'};
  int i, found;
  long style = (long) maildir_parameters(GET_COURIERSTYLE, NIL), j;
  char *maildirpath = mdirpath();
  COURIER_S *cdir;

  if(!strpbrk(pat,"%*")){	/* a mailbox */
     maildir_file_path(pat, curdir, sizeof(curdir));
     i = strlen(curdir) - 1;
     if(curdir[i] == '/')
       curdir[i] = '\0';
     cdir = courier_list_dir(curdir);
     if(cdir){
	found = 0; j = 0L;
	if(maildir_valid_name(pat)){
	  for(i = 0; !found && i < cdir->total; i++)
	     if(strstr(curdir, cdir->data[i]->name)){
		if(strlen(curdir) < strlen(cdir->data[i]->name))
		  found += 2;
		else if(strlen(curdir) == strlen(cdir->data[i]->name))
		  found -= 1;
	     }
	  if(found > 0)
            j = LATT_HASCHILDREN;
          else if(found == 0)
	    j = (style == COURIER) ? LATT_HASNOCHILDREN : LATT_NOINFERIORS;
	}
	else
	   j = LATT_NOSELECT;
        j += maildir_any_new_msgs(curdir) ? LATT_MARKED : LATT_UNMARKED;
	if (found)
	   mm_list (stream, '.', pat, j);
        courier_free_cdir(&cdir);
     }
     return;
  }

  strcpy(tmp,pat + 4);	/* a directory */
  j = strlen(pat) - 1;
  maildir_file_path(pat, realpat, sizeof(realpat));
  c = pat[j];
  pat[j] = '\0';
  realname[0] = '\0';
  if(dir)
    maildir_file_path(dir, realname, sizeof(realname));
  snprintf(curdir, sizeof(curdir), "%s%s%s/%s", (dir ? "" : myrootdir(pat)), (dir ? "" : "/"),
		(dir ? realname : maildirpath),	(dir ? "" : "."));
  snprintf(tmp, sizeof(tmp), "%s%s/.", MDPREFIX(COURIER), dir ? dir : maildirpath);
  if (level == 0 && tmp && pmatch_full (tmp, realpat, '.'))
     mm_list (stream,'.', tmp, LATT_NOSELECT);

  cdir = courier_list_dir(pat);
  pat[j] = c;
  for (i = 0; cdir && i < cdir->total; i++)
   if(pmatch_full (cdir->data[i]->name, pat, '.')){
      snprintf(tmp, sizeof(tmp), "%s.", cdir->data[i]->name);
      courier_list_info(&cdir, tmp, i);
      mm_list (stream,'.',cdir->data[i]->name, cdir->data[i]->attribute);
   }
  courier_free_cdir(&cdir);
}

int 
same_maildir_file(char *name1, char *name2)
{
 char tmp1[MAILTMPLEN], tmp2[MAILTMPLEN];
 char *s;

 strcpy(tmp1, name1 ? name1 : "");
 strcpy(tmp2, name2 ? name2 : "");
 if ((s = strrchr(tmp1, FLAGSEP)) != NULL)
   *s = '\0';
 if (((s = strrchr(tmp1, SIZESEP)) != NULL) && (strchr(s,'.') == NULL))
   *s = '\0';
 if ((s = strrchr(tmp2, FLAGSEP)) != NULL)
   *s = '\0';
 if (((s = strrchr(tmp2, SIZESEP)) != NULL) && (strchr(s,'.') == NULL))
   *s = '\0';

 return !strcmp(tmp1, tmp2);
}

unsigned long antoul(char *seed)
{
  int i, error = 0;
  unsigned long val = 0L, rv1 = 0L, t;
  char c, *p;
 if(!seed)
   return 0L;
 t = strtoul(seed, &p, 10);
 if(p && (*p == '.' || *p == '_'))
   return t;
 /* else */
 if((p = strchr(seed,'.')) != NULL)
   *p = '\0';
 error = (strlen(seed) > 6); /* too long */
 for(i= strlen(seed)-1; error == 0 && i >= 0; i--){
    c = seed[i];
    if (c >= 'A' && c <= 'Z') val = c - 'A';
    else if (c >= 'a' && c <= 'z') val = c - 'a' + 26;
    else if (c >= '0' && c <= '9') val = c - '0' + 26 + 26; 
    else if (c == '-') val = c - '-' + 26 + 26 + 10;
    else if (c == '_') val = c - '_' + 26 + 26 + 10 + 1;
    else error++;
    rv1 = val + (rv1 << 6);
 }
 if(p)
   *p = '.';
  return error ? 0L : rv1;
}

unsigned long mdfntoul (char *name)
{
  unsigned long t;
  char *r, last;

  if((*name == '_') && ((r = strpbrk(name,".,%+")) != NULL)){ /* Grrr!!! */
    last = *r;
    *r = '\0';
     t = antoul(r+1);
    *r = last;
  }
  else
    t = antoul(name);
  return t;
}

int comp_maildir_file(char *name1, char *name2)
{
  int uset1 = 1, uset2 = 1, i, j, cmp;
  unsigned long t1, t2;
  char *s1, *s2;

  if (!(name1 && *name1))
     return (name2 && *name2) ? (*name2 == FLAGSEP ? 0 : -1) : 0;

  if (!(name2 && *name2))
     return (name1 && *name1) ? (*name1 == FLAGSEP ? 0 : 1) : 0;

   if((cmp = strcmp(name1,name2)) == 0)
      return 0;

  t1 = strtoul(name1, &s1, 10);
  t2 = strtoul(name2, &s2, 10);

  if(!s1 || *s1 != '.')
    uset1 = 0;

  if(!s2 || *s2 != '.')
    uset2 = 0;

  if(uset1 && uset2)	/* normal sort order */
    return (t1 < t2) ? -1 : (t1 > t2 ? 1 : (cmp < 0 ? -1 : 1));

  /* If we make it here we say Grrrr.... first, then we try to figure out
   * how to sort this mess.
   * These are the rules.
   * If there is a number at the beginning it is bigger than anything else.
   * If there are digits, then the number of digits decides which one is bigger.
   */

  for(i = 0; isdigit(name1[i]); i++);
  for(j = 0; isdigit(name2[j]); j++);

  return(uset1 ? 1 
	       : (uset2 ? -1 
			: (i < j ? -1 : (i > j ? 1 : (cmp < 0 ? -1 : 1)))));
}

void
maildir_getflag(char *name, int *d, int *f, int *r ,int *s, int *t)
{
  char tmp[MAILTMPLEN], *b;
  int offset = 0;
  int tmpd, tmpf, tmpr, tmps, tmpt;

  if(d) *d = 0;
  if(f) *f = 0;
  if(r) *r = 0;
  if(s) *s = 0;
  if(t) *t = 0;

  tmpd = tmpf = tmpr = tmps = tmpt = NIL; /* no flags set by default */
  strcpy(tmp,name);
  while ((b = strrchr(tmp+offset, FLAGSEP)) != NULL){
    char flag,last;
    int  k;
    if (!++b) break;
    switch (*b){
	case '1':
	case '2':
	case '3': flag = *b; b += 2;
		  for (k = 0; b[k] && b[k] != FLAGSEP && b[k] != ','; k++);
		  last = b[k];
		  b[k] = '\0';
		  if (flag == '2' || flag == '3'){
		     tmpd = strchr (b, MDFLAGC(Draft))   ? T : NIL;
		     tmpf = strchr (b, MDFLAGC(Flagged)) ? T : NIL;
		     tmpr = strchr (b, MDFLAGC(Replied)) ? T : NIL;
		     tmps = strchr (b, MDFLAGC(Seen))    ? T : NIL;
		     tmpt = strchr (b, MDFLAGC(Trashed)) ? T : NIL;
		  }
		  b[k] = last;
		  b += k;
		  for (; tmp[offset] && tmp[offset] != FLAGSEP; offset++);
		  offset++;
		break;
	default: break;	/* Should we crash?... Nahhh */
    }
  }
  if(d) *d = tmpd;
  if(f) *f = tmpf;
  if(r) *r = tmpr;
  if(s) *s = tmps;
  if(t) *t = tmpt;
}

int
maildir_message_in_list(char *msgname, struct direct **names, 
		unsigned long bottom, unsigned long top, unsigned long *pos)
{
  unsigned long middle = (bottom + top)/2;
  int test;

  if (!msgname)
     return NIL;

  if (pos) *pos = middle;

  if (same_maildir_file(msgname, names[middle]->d_name))
     return T;

  if (middle == bottom){	 /* 0 <= 0 < 1 */
     int rv = NIL;
     if (same_maildir_file(msgname, names[middle]->d_name)){
	rv = T;
	if (pos) *pos = middle;
     }
     else
       if (same_maildir_file(msgname, names[top]->d_name)){
	rv = T;
	if (pos) *pos = top;
       }
     return rv;
  }

  test = comp_maildir_file(msgname, names[middle]->d_name);

  if (top <= bottom)
      return test ? NIL : T;

  if (test < 0 ) /* bottom <  msgname < middle */
     return maildir_message_in_list(msgname, names, bottom, middle, pos);
  else if (test > 0)  /* middle < msgname < top */
     return maildir_message_in_list(msgname, names, middle, top, pos);
  else return T;
}

void
maildir_abort(MAILSTREAM *stream)
{
  if (LOCAL){
    DirNamesType i;

    if(LOCAL->candouid)
      maildir_read_uid(stream, NULL, &stream->uid_validity);
    if (LOCAL->dir) fs_give ((void **) &LOCAL->dir);
    for (i = Cur; i < EndDir; i++)
      if(LOCAL->path[i]) fs_give ((void **) &LOCAL->path[i]);
    fs_give ((void **) &LOCAL->path);
    if (LOCAL->buf) fs_give ((void **) &LOCAL->buf);
    if(LOCAL->uidtempfile){
      unlink(LOCAL->uidtempfile);
      fs_give ((void **) &LOCAL->uidtempfile);
    }
    fs_give ((void **) &stream->local);
  }
  if (mdfpath) fs_give((void **)&mdfpath);
  stream->dtb = NIL;
}

int
maildir_contains_folder(char *dirname, char *name)
{
  char tmp[MAILTMPLEN], tmp2[MAILTMPLEN];
  int rv = 0;
  DIR *dir;
  struct direct *d;

  maildir_file_path(dirname, tmp2, sizeof(tmp2));
  if(name){
    strcat(tmp2,"/");
    strcat(tmp2, name);
  }

  if (!(dir = opendir (tmp2)))
     return NIL;

  while ((d = readdir(dir)) != NULL){
    if (strcmp(d->d_name, ".") && strcmp(d->d_name,"..")
	&& strcmp(d->d_name, MDNAME(Cur)) 
	&& strcmp(d->d_name, MDNAME(Tmp)) 
	&& strcmp(d->d_name, MDNAME(New))){

       snprintf(tmp, sizeof(tmp), "%s/%s", tmp2, d->d_name);
       if(maildir_valid(tmp)){
	  rv++;
	  break;
       }
    }
  }
  closedir(dir);
  return rv;
}

int
maildir_is_dir(char *dirname, char *name)
{
  char tmp[MAILTMPLEN];
  struct stat sbuf;

  maildir_file_path(dirname, tmp, sizeof(tmp));
  if(name){
    strcat(tmp, "/");
    strcat(tmp, name);
  }
  strcat(tmp, "/");
  strcat(tmp, MDDIR);

  return ((stat(tmp, &sbuf) == 0) && S_ISREG (sbuf.st_mode)) ? 1 : 0;
}

int
maildir_dir_is_empty(char *mailbox)
{
  char tmp[MAILTMPLEN], tmp2[MAILTMPLEN], tmp3[MAILTMPLEN],*s;
  int rv = 1, courier = IS_COURIER(mailbox);
  DIR *dir;
  struct direct *d;
  struct stat sbuf;

  maildir_file_path(mailbox, tmp2, sizeof(tmp2));

  if(courier){
     strcpy(tmp3, tmp2);
     if(s = strrchr(tmp2, '/'))
	*s = '\0';
  }

  if (!(dir = opendir (tmp2)))
     return rv;

  if(courier){
     while((d = readdir(dir)) != NULL){
        snprintf(tmp, sizeof(tmp), "%s/%s", tmp2, d->d_name);
	if(!strncmp(tmp, tmp3, strlen(tmp3)) 
	   && tmp[strlen(tmp3)] == '.'){
	   rv = 0;
	   break;
	}
     }
  }
  else
    while ((d = readdir(dir)) != NULL){
      snprintf(tmp, sizeof(tmp), "%s/%s", tmp2, d->d_name);
      if (strcmp(d->d_name, ".") 
	&& strcmp(d->d_name,"..")
	&& strcmp(d->d_name, MDNAME(Cur)) 
	&& strcmp(d->d_name, MDNAME(Tmp)) 
	&& strcmp(d->d_name, MDNAME(New))
	&& strcmp(d->d_name, MDDIR)
	&& strcmp(d->d_name, MDUIDVALIDITY)
	&& !(d->d_name[0] == '.' 
		&& stat (tmp,&sbuf) == 0 
		&& S_ISREG(sbuf.st_mode))){
	   rv = 0;
	   break;
       }
    }
  closedir(dir);
  return rv;
}

void
maildir_get_file (MAILDIRFILE **mdfile)
{
  MAILDIRFILE *md;

  md = (MAILDIRFILE *) fs_get(sizeof(MAILDIRFILE));
  memset(md, 0, sizeof(MAILDIRFILE));
  *mdfile = md;
}

void
maildir_free_file (void **mdfile)
{
  MAILDIRFILE *md = (mdfile && *mdfile) ? (MAILDIRFILE *) *mdfile : NULL;

  if (md){
     if (md->name) fs_give((void **)&md->name);
     fs_give((void **)&md);
  }
}

void
maildir_free_file_only (void **mdfile)
{
  MAILDIRFILE *md = (mdfile && *mdfile) ? (MAILDIRFILE *) *mdfile : NULL;

  if (md && md->name) 
     fs_give((void **)&md->name);
}

int
maildir_any_new_msgs(char *mailbox)
{
  char tmp[MAILTMPLEN];
  int rv = NIL;
  DIR *dir;
  struct direct *d;

  MDFLD(tmp, mailbox, New);

  if (!(dir = opendir (tmp)))
     return rv;

  while ((d = readdir(dir)) != NULL){
    if (d->d_name[0] == '.')
	continue;
    rv = T;
    break;
  }
  closedir(dir);
  return rv;
}


void
maildir_get_date(MAILSTREAM *stream, unsigned long msgno)
{
  MESSAGECACHE *elt;
  struct tm *t;
  time_t ti;
  int i,k;

  elt = mail_elt (stream,msgno);
  if(elt && elt->year != 0)
    return;
  if ((ti = mdfntoul(MDFILE(elt))) > 0L && (t = gmtime(&ti))){
     i = t->tm_hour * 60 + t->tm_min;
     k = t->tm_yday;
     t = localtime(&ti);
     i = t->tm_hour * 60 + t->tm_min - i;
     if((k = t->tm_yday - k) != 0) 
	i += ((k < 0) == (abs (k) == 1)) ? -24*60 : 24*60;
     k = abs (i);
     elt->hours = t->tm_hour; 
     elt->minutes = t->tm_min; 
     elt->seconds = t->tm_sec;
     elt->day = t->tm_mday; elt->month = t->tm_mon + 1;
     elt->year = t->tm_year - (BASEYEAR - 1900);
     elt->zoccident = (k == i) ? 0 : 1;
     elt->zhours = k/60;
     elt->zminutes = k % 60;
  }
}

/* Support for Courier Style directories 
   When this code is complete there will be two types of support, which 
   will be configurable. The problem is the following: In Courier style 
   folder structure, a "folder" may have a subfolder called 
   "folder.subfolder", which is not natural in the file system in the 
   sense that I can not stat for "folder.subfolder" wihtout knowing what 
   "subfolder" is. It needs to be guessed. Because of this I need to look 
   in the list of folders if there is a folder with a name 
   "folder.subfolder", before I can say if the folder is dual or not. One 
   can avoid this annoyance if one ignores the problem by declaring that 
   every folder is dual. I will however code as the default the more 
   complicated idea of scaning the containing directory each time it is 
   modified and search for subfolders, and list the entries it found.
 */

int courier_dir_select (const struct direct *name)
{
 return name->d_name[0] == '.' && (strlen(name->d_name) > 2
	|| (strlen(name->d_name) == 2 &&  name->d_name[1] != '.'));
}

int courier_dir_sort (const struct direct **d1, const struct direct **d2)
{
  const struct direct *e1 = *(const struct direct **) d1;
  const struct direct *e2 = *(const struct direct **) d2;

  return strcmp((char *) e1->d_name, (char *) e2->d_name);
}

void courier_free_cdir (COURIER_S **cdir)
{
  int i;

  if (!*cdir)
     return;

  if ((*cdir)->path) fs_give((void **)&((*cdir)->path));
  for (i = 0; i < (*cdir)->total; i++)
    if((*cdir)->data[i]->name) fs_give((void **)&((*cdir)->data[i]->name));
  fs_give((void **)&((*cdir)->data));
  fs_give((void **)&(*cdir));
}

COURIER_S *courier_get_cdir (int total)
{
 COURIER_S *cdir;

 cdir = (COURIER_S *)fs_get(sizeof(COURIER_S));
 memset(cdir, 0, sizeof(COURIER_S));
 cdir->data = (COURIERLOCAL **) fs_get(total*sizeof(COURIERLOCAL *));
 memset(cdir->data, 0, sizeof(COURIERLOCAL *));
 cdir->total = total;
 return cdir;
}

int courier_search_list(COURIERLOCAL **data, char *name, int first, int last)
{
  int try = (first + last)/2;

  if(!strstr(data[try]->name, name)){
     if(first == try) /* first == last || first + 1 == last */
	return strstr(data[last]->name, name) ? 1 : 0;
     if(strcmp(data[try]->name, name) < 0) /*data[try] < name < data[end] */
	return courier_search_list(data, name, try, last);
     else	/* data[begin] < name < data[try] */
	return courier_search_list(data, name, first, try);
  }
  return 1;
}

/* Lists all directories that are subdirectories of a given directory */

COURIER_S *courier_list_dir(char *curdir)
{
  struct direct **names = NIL;
  struct stat sbuf;
  unsigned long ndir;
  COURIER_S *cdir = NULL;
  char tmp[MAILTMPLEN], tmp2[MAILTMPLEN], pathname[MAILTMPLEN], 
	realname[MAILTMPLEN];
  int i, j, scand, td;

  /* There are two cases, either curdir is 
 	 #mc/INBOX.	 #mc/INBOX.foo
	or
	 #mc/Maildir/. 	 #mc/Maildir/.foo
   */
  strcpy(tmp,curdir + 4);
  if(!strncmp(ucase(tmp), "INBOX", 5))
    strcpy(tmp, "#mc/INBOX.");
  else{
   strcpy(tmp, curdir);
   for (i = strlen(tmp) - 1; tmp[i] && tmp[i] != '/'; i--);
   tmp[i+2] = '\0'; 	/* keep the last "." intact */
  }
  maildir_file_path(tmp, realname, sizeof(realname));
  maildir_scandir (realname, &names, &ndir, &scand, COURIER);

  if (scand > 0){
     cdir = courier_get_cdir(ndir);
     cdir->path = cpystr(realname);
     for(i = 0, j = 0; i < ndir; i++){
        td = realname[strlen(realname) - 1] == '.'
		&& *names[i]->d_name == '.';
	snprintf(tmp2, sizeof(tmp2), "%s%s", tmp, names[i]->d_name+1);
	snprintf(pathname, sizeof(pathname), "%s%s", realname, names[i]->d_name + td);
	if(stat(pathname, &sbuf) == 0 && S_ISDIR(sbuf.st_mode)){
	   cdir->data[j] = (COURIERLOCAL *) fs_get(sizeof(COURIERLOCAL));
	   cdir->data[j++]->name = cpystr(tmp2);
	}
	fs_give((void **)&names[i]);
     }
     cdir->total = j;
     if(cdir->total == 0)
        courier_free_cdir(&cdir);
  }
  if(names)
    fs_give((void **) &names);
  return cdir;
}

void
courier_list_info(COURIER_S **cdirp, char *data, int i)
{
   long style = (long) maildir_parameters(GET_COURIERSTYLE, NIL);
   COURIER_S *cdir = *cdirp;

   if(maildir_valid(cdir->data[i]->name)){
      if(courier_search_list(cdir->data, data, 0, cdir->total - 1))
	 cdir->data[i]->attribute = LATT_HASCHILDREN;
      else
	 cdir->data[i]->attribute = (style == COURIER)
				? LATT_HASNOCHILDREN : LATT_NOINFERIORS;
   }
   else
      cdir->data[i]->attribute = LATT_NOSELECT;
      cdir->data[i]->attribute += maildir_any_new_msgs(cdir->data[i]->name) 
					? LATT_MARKED : LATT_UNMARKED;
}

/* UID Support */
/* Yes, I know I procastinated a lot about this, but here it is finally */

/* return code:
   bigger than zero: this session can assign uids
   zero: this session will not assign uid
   smaller than zero: this session temporarily suspends assigning uids 
 */
int
maildir_can_assign_uid (MAILSTREAM *stream)
{
  unsigned int rv = 0;
  int ownuid, existuid;
  unsigned long t;
  char tmp[MAILTMPLEN], tmp2[MAILTMPLEN], *p, *s;
  DIR *dir;
  struct direct *d;

  if(!stream || stream->rdonly 
	|| !LOCAL || !LOCAL->dir || !(dir = opendir(LOCAL->dir)))
    return 0;

  if(mypid == (pid_t) 0)
    mypid = getpid();

  snprintf(tmp, sizeof(tmp), "%s.%d", MDUIDTEMP, mypid);

  ownuid = existuid = 0;
  s = NULL;
  while ((d = readdir(dir)) != NULL){
    if(strncmp(d->d_name, tmp, strlen(tmp)) == 0){
	existuid++; ownuid++;
	if(ownuid > 1){
	  snprintf(tmp2, sizeof(tmp), "%s/%s", LOCAL->dir, d->d_name);
	  unlink(tmp2);
	  if(s){
	     snprintf(tmp2, sizeof(tmp2), "%s/%s", LOCAL->dir, s);
	     unlink(tmp2);
	     fs_give((void **)&s);
	  }
	}
	else
	  s = cpystr(d->d_name);
    }
    else if(strncmp(d->d_name, MDUIDTEMP, strlen(MDUIDTEMP)) == 0)
        existuid++;
  }

  closedir(dir);
  if(s)
    fs_give((void **)&s);

  if(ownuid == 1 && existuid == 1)
     rv = 1;

  if(ownuid == 0 && existuid == 0){ /* nobody owns the uid? */
    FILE *fp;
    snprintf(tmp, sizeof(tmp), "%s/%s.%d.%lu", LOCAL->dir, MDUIDTEMP, mypid, time(0));
    if(fp = fopen(tmp, "w")){
      fclose(fp);
      if(LOCAL->uidtempfile)
	 fs_give((void **)&LOCAL->uidtempfile);
      LOCAL->uidtempfile = cpystr(tmp);
    }
    rv = 1;
  }

  if(ownuid == 0 && existuid > 0) /* someone else owns uid assignment */
    return 0;

  /* if we own the uid, check that we do not own it more than once
   * or that we share ownership. If any of these situations happens,
   * give up the ownership until we can recover it
   */

  if(ownuid > 0){
    if(ownuid > 1)	/* impossible, two lock files for the same session */
       return (-1)*ownuid;

    if(ownuid != existuid){	/* lock files for different sessions */
      if(LOCAL->uidtempfile){
	 unlink(LOCAL->uidtempfile);
	 fs_give((void **)&LOCAL->uidtempfile);
      }
      return (-1)*ownuid;
    }
  }

  return rv;
}

void
maildir_read_uid(MAILSTREAM *stream, unsigned long *uid_last, 
			unsigned long *uid_validity)
{
  int createuid, deleteuid = 0;
  char tmp[MAILTMPLEN], *s = NULL;
  DIR *dir;
  struct direct *d;

  if(uid_last) *uid_last = 0L;
  if(uid_last && uid_validity) *uid_validity = time(0);
  if(!stream || !LOCAL || !LOCAL->dir || !(dir = opendir(LOCAL->dir)))
    return;

  while ((d = readdir(dir)) != NULL){
      if(!strncmp(d->d_name, MDUIDLAST, strlen(MDUIDLAST)))
       break;
  }
  createuid = d == NULL ? 1 : 0;
  if(uid_last == NULL)
    deleteuid++;
  if(d){
     if(uid_last){
	s = d->d_name + strlen(MDUIDLAST) + 1;
	*uid_last = strtoul(s, &s, 10);
	if(!s || *s != '.'){
	  deleteuid++;
	  createuid++;
	  *uid_last = 0L;
	}
     }
     if(s && *s == '.'){
        if(uid_validity){
	  s++;
	  *uid_validity = strtoul(s, &s, 10);
	  if(s && *s != '\0'){
	    *uid_validity = time(0);
	    deleteuid++;
	    createuid++;
	  }
	}
     }
     else{
	deleteuid++;
	createuid++;
     }
  }
  if(deleteuid){
     snprintf(tmp, sizeof(tmp), "%s/%s", LOCAL->dir, d->d_name);
     unlink(tmp);
  }
  if(createuid)
     maildir_write_uid(stream, (uid_last ? *uid_last : stream->uid_last), 
		uid_validity ? *uid_validity : time(0));
  closedir(dir);
}

void
maildir_write_uid(MAILSTREAM *stream, unsigned long uid_last, 
			unsigned long uid_validity)
{
  char tmp[MAILTMPLEN];
  FILE *fp;

  if(!stream || stream->rdonly || !LOCAL || !LOCAL->dir)
    return;

  snprintf(tmp, sizeof(tmp), "%s/%s.%010lu.%010lu", LOCAL->dir, MDUIDLAST, 
			uid_last, uid_validity);
  if(fp = fopen(tmp, "w"))
     fclose(fp);
}

unsigned long 
maildir_get_uid(char *name)
{
  char *s;
  unsigned long rv = 0L;

  if(!name || (s = strstr(name,MDUIDSEP)) == NULL)
    return rv;

  s += strlen(MDUIDSEP);
  rv = strtoul(s, NULL, 10);
  return rv;
}


void
maildir_delete_uid(MAILSTREAM *stream, unsigned long msgno)
{
  char old[MAILTMPLEN], new[MAILTMPLEN], *s, *t;
  MESSAGECACHE *elt;

  elt = mail_elt(stream, msgno);
  if(!stream || !elt || !elt->private.spare.ptr || !LOCAL || !LOCAL->dir)
    return;

  snprintf(old, sizeof(old), "%s/%s/%s", LOCAL->dir, MDNAME(Cur), MDFILE(elt));
  t = MDFILE(elt);
  if(s = strstr(MDFILE(elt), MDUIDSEP)){
     *s = '\0';
     s += strlen(MDUIDSEP);
     strtoul(s, &s, 10);
     snprintf(new, sizeof(new), "%s/%s/%s%s", LOCAL->dir, MDNAME(Cur), t, s);
     if(rename(old, new) == 0){
	maildir_free_file_only ((void **)&elt->private.spare.ptr);
	s = strrchr(new, '/');
	MDFILE(elt) = cpystr(s+1);
     }
     elt->private.uid = 0L;
  }
}

void
maildir_assign_uid(MAILSTREAM *stream, unsigned long msgno, unsigned long uid)
{
  int createuid, deleteuid = 0;
  char old[MAILTMPLEN], new[MAILTMPLEN], *s, *t;
  MESSAGECACHE *elt;

  elt = mail_elt(stream, msgno);
  if(!stream || !elt || !elt->private.spare.ptr || !LOCAL || !LOCAL->dir)
    return;

  maildir_delete_uid(stream, msgno);
  snprintf(old, sizeof(old), "%s/%s/%s", LOCAL->dir, MDNAME(Cur), MDFILE(elt));
  t = MDFILE(elt);
  if((s = strrchr(MDFILE(elt),FLAGSEP)) != NULL){
     *s++ = '\0';
     snprintf(new, sizeof(new), "%s/%s/%s%s%lu%c%s", 
		LOCAL->dir, MDNAME(Cur), t, MDUIDSEP, uid, FLAGSEP, s);
     if(rename(old, new) == 0){
	maildir_free_file_only ((void **)&elt->private.spare.ptr);
	s = strrchr(new, '/');
	MDFILE(elt) = cpystr(s+1);
	stream->uid_validity = time(0);
     }
     elt->private.uid = uid;
  }
}

void
maildir_uid_renew_tempfile(MAILSTREAM *stream)
{
  char tmp[MAILTMPLEN];

  if(!stream || stream->rdonly 
	|| !LOCAL || !LOCAL->candouid || !LOCAL->dir || !LOCAL->uidtempfile)
    return;

  if(mypid == (pid_t) 0)
    mypid = getpid();

  snprintf(tmp, sizeof(tmp), "%s/%s.%d.%lu", LOCAL->dir, MDUIDTEMP, mypid, time(0));
  if(rename(LOCAL->uidtempfile, tmp) == 0){
      fs_give((void **)&LOCAL->uidtempfile);
      LOCAL->uidtempfile = cpystr(tmp);
  }
}
