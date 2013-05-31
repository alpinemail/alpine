/* 
 * A few definitions that try to make this module portable to other
 * platforms (e.g. Cygwin). This module is based on the information from
 * http://cr.yp.to/proto/maildir.html
 */

/* First we deal with the separator character */
#ifndef FLAGSEP
#define FLAGSEP ':'
#endif
#define SIZESEP ','

const char sep1[] = {FLAGSEP, '1', ',', '\0'}; /* experimental semantics*/
const char sep2[] = {FLAGSEP, '2', ',', '\0'}; /* Flags Information	*/
const char sep3[] = {FLAGSEP, '3', ',', '\0'}; /* Grrrr....		*/

const char *sep[] = { sep1, sep2, sep3, NULL};

#define MDSEP(i)  sep[((i) - 1)]

/* Now we deal with flags. Woohoo! */
typedef enum  {Draft, Flagged, Passed, Replied, Seen, Trashed, 
	       EmptyFlag, EndFlags} MdFlagNamesType;
const int mdimapflags[] = {Draft, Flagged, Replied, Seen, Trashed, EmptyFlag, EndFlags};
const int mdkwdflags[]  = {Passed, EmptyFlag, EndFlags};

/* this array lists the codes for mdflgnms (maildir flag names) above */
const char *mdflags[] = { "D", "F", "P", "R", "S", "T", "", NULL};
/* and as characters too */
const char cmdflags[] = { 'D', 'F', 'P', 'R', 'S', 'T', '0', '\0'};

/* MDFLAG(Seen, elt->seen) */
#define MDFLAG(i,j) mdflags[j ? (i) : EmptyFlag]
/* MDFLAGC(Seen) */
#define MDFLAGC(i) cmdflags[(i)]

/* Now we deal with the directory structure */
typedef enum {Cur, Tmp, New, EndDir} DirNamesType;
char *mdstruct[] = {"cur", "tmp", "new", NULL};
#define MDNAME(i) mdstruct[(i)]
#define MDFLD(tmp, dir, i) sprintf((tmp),"%s/%s", (dir), mdstruct[(i)])
#define MSGPATH(tmp, dir, msg,i) sprintf((tmp),"%s/%s/%s", (dir), mdstruct[(i)],(msg))

/* Files associated to a maildir directory */

#define MDUIDVALIDITY	".uidvalidity"	/* support for old maildirs    */
#define MDDIR		".mdir"		/* this folder is a directory  */
#define MDUIDLAST	".uidlast"	/* last assigned uid	       */
#define MDUIDTEMP	".uidtemp"	/* We assign uid's no one else */



/* Support of Courier Structure */
#define CCLIENT 0
#define COURIER 1
#define IS_CCLIENT(t) \
		(((t) && (t)[0] == '#' && ((t)[1] == 'm' || (t)[1] == 'M')\
		&& ((t)[2] == 'd' || (t)[2] == 'D')\
		&& (t)[3] == '/'  && (t)[4] != '\0') ? 1 : 0)

#define IS_COURIER(t) \
		(((t) && (t)[0] == '#' && ((t)[1] == 'm' || (t)[1] == 'M')\
		&& ((t)[2] == 'c' || (t)[2] == 'C')\
		&& (t)[3] == '/'  && (t)[4] != '\0') ? 1 : 0)
#define MDPREFIX(s) ((s) ? "#mc/" : "#md/")
#define MDSEPARATOR(s) ((s) ? '.' : '/')

/* UID Support */

#define MAXTEMPUID (unsigned long) 180L
const char mduid[] = {',','u','=','\0'};
#define MDUIDSEP mduid


/* Now we deal with messages filenames */
char mdlocaldomain[MAILTMPLEN+1] = {'\0'};
pid_t mypid = (pid_t) 0;
static char *mdfpath = NULL;
static char myMdInboxDir[50] = { '\0' };/* Location of the Maildir INBOX */
static long CourierStyle = CCLIENT;

#define CHUNK	16384	/* from unix.h */

typedef struct courier_local {
  char *name;		/* name of directory/folder */
  int attribute;	/* attributes (children/marked/etc) */
} COURIERLOCAL;

typedef struct courier {
  char *path;			/* Path to collection */
  time_t scantime;		/* time at which information was generated */
  int total;			/* total number of elements in data */
  COURIERLOCAL **data;
} COURIER_S;

/* In gdb this is the  *(struct maildir_local *)stream->local structure */
typedef struct maildir_local {
  unsigned int dirty : 1;	/* diskcopy needs updating 		*/
  unsigned int courier : 1;	/* It is Courier style file system	*/
  unsigned int link : 1;	/* There is a symbolic link		*/
  int candouid;			/* we can assign uids and no one else	*/
  char *uidtempfile;		/* path to uid temp file		*/
  int fd;			/* fd of open message			*/
  char *dir;			/* mail directory name			*/
  char **path;			/* path to directories cur, new and tmp	*/
  unsigned char *buf;		/* temporary buffer 			*/
  unsigned long buflen;		/* current size of temporary buffer 	*/
  time_t scantime;		/* last time directory scanned 		*/
} MAILDIRLOCAL;

/* Convenient access to local data */
#define LOCAL ((MAILDIRLOCAL *) stream->local)

typedef struct maildir_file_info {
   char *name;		/* name of the file			   */
   DirNamesType loc;	/* location of this file		   */
   unsigned long pos;	/* place in list where this file is listed */
   off_t size;		/* size in bytes, on disk */
   time_t atime;	/* last access time */
   time_t mtime;	/* last modified time */
   time_t ctime;	/* last changed time */
} MAILDIRFILE;

#define MDFILE(F) (((MAILDIRFILE *)((F)->private.spare.ptr))->name)
#define MDLOC(F)  (((MAILDIRFILE *)((F)->private.spare.ptr))->loc)
#define MDPOS(F)  (((MAILDIRFILE *)((F)->private.spare.ptr))->pos)
#define MDSIZE(F)  (((MAILDIRFILE *)((F)->private.spare.ptr))->size)
#define MDATIME(F)  (((MAILDIRFILE *)((F)->private.spare.ptr))->atime)
#define MDMTIME(F)  (((MAILDIRFILE *)((F)->private.spare.ptr))->mtime)
#define MDCTIME(F)  (((MAILDIRFILE *)((F)->private.spare.ptr))->ctime)

/* Function prototypes */

DRIVER *maildir_valid (char *name);
MAILSTREAM *maildir_open (MAILSTREAM *stream);
void maildir_close (MAILSTREAM *stream, long options);
long maildir_ping (MAILSTREAM *stream);
void maildir_check (MAILSTREAM *stream);
long maildir_text (MAILSTREAM *stream,unsigned long msgno,STRING *bs,long flags);
char *maildir_header (MAILSTREAM *stream,unsigned long msgno,
		unsigned long *length, long flags);
void maildir_list (MAILSTREAM *stream,char *ref,char *pat);
void *maildir_parameters (long function,void *value);
int maildir_create_folder (char *mailbox);
long maildir_create (MAILSTREAM *stream,char *mailbox);
void maildir_flagmsg (MAILSTREAM *stream,MESSAGECACHE *elt); /*check */
long maildir_expunge (MAILSTREAM *stream, char *sequence, long options);
long maildir_copy (MAILSTREAM *stream,char *sequence,char *mailbox,long options);
long maildir_append (MAILSTREAM *stream,char *mailbox, append_t af, void *data);
long maildir_delete (MAILSTREAM *stream,char *mailbox);
long maildir_rename (MAILSTREAM *stream,char *old,char *new);
long maildir_sub (MAILSTREAM *stream,char *mailbox);
long maildir_unsub (MAILSTREAM *stream,char *mailbox);
void maildir_lsub (MAILSTREAM *stream,char *ref,char *pat);
void courier_list (MAILSTREAM *stream,char *ref, char *pat);

/* utility functions */
void courier_realname (char *name, char *realname);
long maildir_dirfmttest (char *name);
char *maildir_file (char *dst,char *name);
int maildir_select (const struct direct *name);
int maildir_namesort (const struct direct **d1, const struct direct **d2);
unsigned long antoul (char *seed);
unsigned long mdfntoul (char *name);
int courier_dir_select (const struct direct *name);
int courier_dir_sort (const struct direct **d1, const struct direct **d2);
long maildir_canonicalize (char *pattern,char *ref,char *pat);
void maildir_list_work (MAILSTREAM *stream,char *subdir,char *pat,long level);
void courier_list_work (MAILSTREAM *stream,char *subdir,char *pat,long level);
int maildir_file_path(char *name, char *tmp, size_t sizeoftmp);
int maildir_valid_name (char *name);
int maildir_valid_dir (char *name);
int is_valid_maildir (char **name);
int maildir_message_exists(MAILSTREAM *stream,char *name, char *tmp);
char *maildir_remove_root(char *name);
char *maildir_text_work (MAILSTREAM *stream,MESSAGECACHE *elt, unsigned long *length,long flags);
unsigned long  maildir_parse_message(MAILSTREAM *stream, unsigned long msgno, 
						DirNamesType dirtype);
int maildir_eliminate_duplicate (char *name, struct direct ***flist, 
					unsigned long *nfiles);
int maildir_doscandir (char *name, struct direct ***flist, int flag);
unsigned long maildir_scandir (char *name, struct direct ***flist,
			unsigned long *nfiles, int *scand, int flag);
void maildir_parse_folder (MAILSTREAM *stream, int full);
void  md_domain_name (void);
char  *myrootdir (char *name);
char  *mdirpath (void);
int   maildir_initial_check (MAILSTREAM *stream, DirNamesType dirtype);
unsigned long  maildir_parse_dir(MAILSTREAM *stream, unsigned long nmsgs, 
   DirNamesType dirtype, struct direct **names, unsigned long nfiles, int full);
int same_maildir_file(char *name1, char *name2);
int comp_maildir_file(char *name1, char *name2);
int maildir_message_in_list(char *msgname, struct direct **names,
		unsigned long bottom, unsigned long top, unsigned long *pos);
void maildir_getflag(char *name, int *d, int *f, int *r ,int *s, int *t);
int maildir_update_elt_maildirp(MAILSTREAM *stream, unsigned long msgno);
void maildir_abort (MAILSTREAM *stream);
int maildir_contains_folder(char *dirname, char *name);
int maildir_is_dir(char *dirname, char *name);
int maildir_dir_is_empty(char *mailbox);
int maildir_create_work (char *mailbox, int loop);
void maildir_get_file (MAILDIRFILE **mdfile);
void maildir_free_file (void **mdfile);
void maildir_free_file_only (void **mdfile);
int maildir_any_new_msgs(char *mailbox);
void maildir_get_date(MAILSTREAM *stream, unsigned long msgno);
void maildir_fast (MAILSTREAM *stream,char *sequence,long flags);

/* Courier server support */
void courier_free_cdir (COURIER_S **cdir);
COURIER_S *courier_get_cdir (int total);
int courier_search_list(COURIERLOCAL **data, char *name, int first, int last);
COURIER_S *courier_list_dir(char *curdir);
void courier_list_info(COURIER_S **cdirp, char *data, int i);

/* UID Support */
int maildir_can_assign_uid (MAILSTREAM *stream);
void maildir_read_uid(MAILSTREAM *stream, unsigned long *uid_last, 
     			                   unsigned long *uid_validity);
void maildir_write_uid(MAILSTREAM *stream, unsigned long uid_last, 
     			                   unsigned long uid_validity);
unsigned long maildir_get_uid(char *name);
void maildir_delete_uid(MAILSTREAM *stream, unsigned long msgno);
void maildir_assign_uid(MAILSTREAM *stream, unsigned long msgno, unsigned long uid);
void maildir_uid_renew_tempfile(MAILSTREAM *stream);

