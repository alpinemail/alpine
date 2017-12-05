/* include/config.h.  Generated from config.h.in by configure.  */
/* include/config.h.in.  Generated from configure.ac by autoheader.  */

/* Default configuration value */
#define ANSI_PRINTER "attached-to-ansi"

/* Use Apple OS X key chain for credential caching */
/* #undef APPLEKEYCHAIN */

/* Enable background posting support */
#define BACKGROUND_POST /**/

/* Default configuration value */
#define CHECK_POINT_FREQ 12

/* Default configuration value */
#define CHECK_POINT_TIME 420

/* File name separator as character constant */
#define C_FILESEP '/'

/* Default configuration value */
#define DEADLETTER "dead.letter"

/* Compile in debugging */
#define DEBUG 1

/* Default configuration value */
#define DEBUGFILE ".pine-debug"

/* Display debug messages in journal */
#define DEBUGJOURNAL 1

/* Default configuration value */
#define DEFAULT_COLUMNS_ON_TERMINAL 80

/* Default configuration value */
#define DEFAULT_DEBUG 2

/* Default configuration value */
#define DEFAULT_LINES_ON_TERMINAL 24

/* Default configuration value */
#define DEFAULT_SAVE "saved-messages"

/* Default configuration value */
#define DF_AB_SORT_RULE "fullname-with-lists-last"

/* Default configuration value */
#define DF_ADDRESSBOOK ".addressbook"

/* Default configuration value */
#define DF_CACERT_DIR ".alpine-smime/ca"

/* Name of default certificate authority container */
#define DF_CA_CONTAINER "CAContainer"

/* Default configuration value */
#define DF_DEFAULT_FCC "sent-mail"

/* Default configuration value */
#define DF_DEFAULT_PRINTER ANSI_PRINTER

/* Default configuration value */
#define DF_ELM_STYLE_SAVE "no"

/* Default configuration value */
#define DF_FCC_RULE "default-fcc"

/* Default configuration value */
#define DF_FILLCOL "74"

/* Default configuration value */
#define DF_FLD_SORT_RULE "alphabetical"

/* Default configuration value */
#define DF_HEADER_IN_REPLY "no"

/* Default configuration value */
#define DF_KBLOCK_PASSWD_COUNT "1"

/* Default configuration value */
#define DF_LOCAL_ADDRESS "postmaster"

/* Default configuration value */
#define DF_LOCAL_FULLNAME "Local Support"

/* Default configuration value */
#define DF_MAILCHECK "150"

/* Default configuration value */
#define DF_MAIL_DIRECTORY "mail"

/* Default configuration value */
#define DF_MARGIN "0"

/* Default configuration value */
#define DF_OLD_STYLE_REPLY "no"

/* Default configuration value */
#define DF_OVERLAP "2"

/* Default configuration value */
#define DF_PRIVATEKEY_DIR ".alpine-smime/private"

/* Name of default private container */
#define DF_PRIVATE_CONTAINER "PrivateContainer"

/* Default configuration value */
#define DF_PUBLICCERT_DIR ".alpine-smime/public"

/* Name of default public container */
#define DF_PUBLIC_CONTAINER "PublicContainer"

/* Default configuration value */
#define DF_REMOTE_ABOOK_HISTORY "3"

/* Default configuration value */
#define DF_SAVED_MSG_NAME_RULE "default-folder"

/* Default configuration value */
#define DF_SAVE_BY_SENDER "no"

/* Default configuration value */
#define DF_SIGNATURE_FILE ".signature"

/* Default configuration value */
#define DF_SORT_KEY "arrival"

/* set default value of ssh command string (usually "%s %s -l %s exec
   /etc/r%sd") */
/* #undef DF_SSHCMD */

/* set default value of ssh command path (defining should cause ssh to be
   preferred to rsh) */
/* #undef DF_SSHPATH */

/* Default configuration value */
#define DF_STANDARD_PRINTER "lpr"

/* Default configuration value */
#define DF_USE_ONLY_DOMAIN_NAME "no"

/* Interactive, filewise spell checker */
#define DF_VAR_SPELLER "/usr/bin/hunspell"

/* Define enable dmalloc debugging */
/* #undef ENABLE_DMALLOC */

/* Enable LDAP query support */
#define ENABLE_LDAP /**/

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#define ENABLE_NLS 1

/* Enable From address encoding in sent messages */
/* #undef ENCODE_FROMS */

/* Default configuration value */
#define FORWARDED_FLAG "$Forwarded"

/* Define to 1 if `TIOCGWINSZ' requires <sys/ioctl.h>. */
#define GWINSZ_IN_SYS_IOCTL 1

/* Define if systems uses old BSD-style terminal control */
/* #undef HAS_SGTTY */

/* Define if systems uses termcap terminal database */
/* #undef HAS_TERMCAP */

/* Define if systems uses terminfo terminal database */
#define HAS_TERMINFO 1

/* Define if systems uses termio terminal control */
/* #undef HAS_TERMIO */

/* Define if systems uses termios terminal control */
#define HAS_TERMIOS 1

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the MacOS X function CFLocaleCopyCurrent in the
   CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYCURRENT */

/* Define to 1 if you have the MacOS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
/* #undef HAVE_CFPREFERENCESCOPYAPPVALUE */

/* Define to 1 if you have the `chown' function. */
#define HAVE_CHOWN 1

/* Define to 1 if you have the <ctype.h> header file. */
#define HAVE_CTYPE_H 1

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
#define HAVE_DCGETTEXT 1

/* Define to 1 if you have the <dirent.h> header file, and it defines `DIR'.
   */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `fsync' function. */
#define HAVE_FSYNC 1

/* Define to 1 if you have the `getpwnam' function. */
#define HAVE_GETPWNAM 1

/* Define to 1 if you have the `getpwuid' function. */
#define HAVE_GETPWUID 1

/* Define if the GNU gettext() function is already present or preinstalled. */
#define HAVE_GETTEXT 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the `getuid' function. */
#define HAVE_GETUID 1

/* Define if you have the iconv() function. */
/* #undef HAVE_ICONV */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <langinfo.h> header file. */
#define HAVE_LANGINFO_H 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the `listen' function. */
#define HAVE_LISTEN 1

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if you have the `mbstowcs' function. */
#define HAVE_MBSTOWCS 1

/* Define to 1 if you have the `memcpy' function. */
#define HAVE_MEMCPY 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define if system supports subsecond, non-alarm sleep */
#define HAVE_NANOSLEEP 1

/* Define to 1 if you have the <ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the `pclose' function. */
#define HAVE_PCLOSE 1

/* Define to 1 if you have the `poll' function. */
#define HAVE_POLL 1

/* Define to 1 if you have the `popen' function. */
#define HAVE_POPEN 1

/* System has pthread support */
#define HAVE_PTHREAD 1

/* Define to 1 if you have the <pthread.h> header file. */
#define HAVE_PTHREAD_H 1

/* Define to 1 if you have the `putenv' function. */
#define HAVE_PUTENV 1

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you have the `qsort' function. */
#define HAVE_QSORT 1

/* Define to 1 if you have the `read' function. */
#define HAVE_READ 1

/* Regular expression header file exists */
#define HAVE_REGEX_H 1

/* Define to 1 if you have the `rename' function. */
#define HAVE_RENAME 1

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `setenv' function. */
#define HAVE_SETENV 1

/* Define to 1 if you have the `setjmp' function. */
#define HAVE_SETJMP 1

/* Define to 1 if you have the <setjmp.h> header file. */
#define HAVE_SETJMP_H 1

/* Define to 1 if you have the `sigaction' function. */
#define HAVE_SIGACTION 1

/* Define to 1 if you have the `sigaddset' function. */
#define HAVE_SIGADDSET 1

/* Define to 1 if you have the `sigemptyset' function. */
#define HAVE_SIGEMPTYSET 1

/* Define to 1 if you have the `signal' function. */
#define HAVE_SIGNAL 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the `sigprocmask' function. */
#define HAVE_SIGPROCMASK 1

/* Define to 1 if you have the `sigrelse' function. */
/* #undef HAVE_SIGRELSE */

/* Define to 1 if you have the `sigset' function. */
/* #undef HAVE_SIGSET */

/* Define to 1 if you have the `srandom' function. */
#define HAVE_SRANDOM 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strcoll' function and it is properly defined.
   */
#define HAVE_STRCOLL 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <stropts.h> header file. */
#define HAVE_STROPTS_H 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if you have the `strtoul' function. */
#define HAVE_STRTOUL 1

/* Define if system supplies syslog() logging */
#define HAVE_SYSLOG 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/poll.h> header file. */
#define HAVE_SYS_POLL_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/syslog.h> header file. */
#define HAVE_SYS_SYSLOG_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
#define HAVE_SYS_UIO_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the <sys/utime.h> header file. */
/* #undef HAVE_SYS_UTIME_H */

/* Define to 1 if you have <sys/wait.h> that is POSIX.1 compatible. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the `tmpfile' function. */
#define HAVE_TMPFILE 1

/* Define to 1 if you have the `truncate' function. */
#define HAVE_TRUNCATE 1

/* Define to 1 if you have the `uname' function. */
#define HAVE_UNAME 1

/* Define to 1 if the system has the type `union wait'. */
#define HAVE_UNION_WAIT 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <utime.h> header file. */
#define HAVE_UTIME_H 1

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if you have the `wait' function. */
#define HAVE_WAIT 1

/* Define to 1 if you have the `wait4' function. */
#define HAVE_WAIT4 1

/* Define to 1 if you have the `waitpid' function. */
#define HAVE_WAITPID 1

/* Define to 1 if you have the <wchar.h> header file. */
#define HAVE_WCHAR_H 1

/* Define to 1 if you have the `wcrtomb' function. */
#define HAVE_WCRTOMB 1

/* Define to 1 if you have the `wcwidth' function. */
#define HAVE_WCWIDTH 1

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Default configuration value */
#define INBOX_NAME "INBOX"

/* Default configuration value */
#define INTERRUPTED_MAIL ".pine-interrupted-mail"

/* Enable keyboard lock support */
#define KEYBOARD_LOCK /**/

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Path to local inboxes for pico newmail check */
#define MAILDIR "/var/spool/mail"

/* Default configuration value */
#define MAX_FILLCOL 80

/* Default configuration value */
#define MAX_SCREEN_COLS 500

/* Default configuration value */
#define MAX_SCREEN_ROWS 200

/* File mode used to set readonly access */
#define MODE_READONLY (0600)

/* Compile in mouse support */
#define MOUSE /**/

/* Disallow users changing their From address */
/* #undef NEVER_ALLOW_CHANGING_FROM */

/* Default configuration value */
#define NUMDEBUGFILES 4

/* OSX TARGET */
/* #undef OSX_TARGET */

/* Name of package */
#define PACKAGE "alpine"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "chappa@washington.edu"

/* Define to the full name of this package. */
#define PACKAGE_NAME "alpine"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "alpine 2.21.9"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "alpine"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.21.9"

/* Password cache file (recommended if S/MIME is enabled and configured) */
#define PASSFILE "ALPINE.PWD"

/* Program users use to change their password */
#define PASSWD_PROG "/usr/bin/passwd"

/* Define if system supports POSIX signal interface */
#define POSIX_SIGNALS /**/

/* Default configuration value */
#define POSTPONED_MAIL "postponed-mail"

/* Default configuration value */
#define POSTPONED_MSGS "postponed-msgs"

/* ps command which outputs list of running commands */
#define PSEFCMD "/bin/ps auxww"

/* Define to necessary symbol if this constant uses a non-standard name on
   your system. */
/* #undef PTHREAD_CREATE_JOINABLE */

/* Include support for UW Pubcookie Web Authentication */
/* #undef PUBCOOKIE */

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to the type of arg 1 for `select'. */
#define SELECT_TYPE_ARG1 int

/* Define to the type of args 2, 3 and 4 for `select'. */
#define SELECT_TYPE_ARG234 (fd_set *)

/* Define to the type of arg 5 for `select'. */
#define SELECT_TYPE_ARG5 (struct timeval *)

/* Local mail submission agent */
#define SENDMAIL "/usr/sbin/sendmail"

/* Local MSA flags for SMTP on stdin/stdout */
#define SENDMAILFLAGS "-bs -odb -oem"

/* Posting agent to use when no nntp-servers defined */
/* #undef SENDNEWS */

/* The size of `unsigned int', as computed by sizeof. */
/* #undef SIZEOF_UNSIGNED_INT */

/* The size of `unsigned long', as computed by sizeof. */
/* #undef SIZEOF_UNSIGNED_LONG */

/* The size of `unsigned short', as computed by sizeof. */
/* #undef SIZEOF_UNSIGNED_SHORT */

/* Enable S/MIME code */
#define SMIME /**/

/* Directory where S/MIME CACerts are located */
#define SMIME_SSLCERTS "/etc/ssl/certs"

/* Simple spell checker: reads stdin, emits misspellings on stdout */
#define SPELLER "/usr/bin/hunspell -l"

/* SSL Supports TLSV1.2 */
#define SSL_SUPPORTS_TLSV1_2 1

/* Define to 1 if the `S_IS*' macros in <sys/stat.h> do not work properly. */
/* #undef STAT_MACROS_BROKEN */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* System pinerc */
#define SYSTEM_PINERC "/usr/local/lib/pine.conf"

/* System fixed pinerc */
#define SYSTEM_PINERC_FIXED "/usr/local/lib/pine.conf.fixed"

/* Local Support Info File */
#define SYSTEM_PINE_INFO_PATH "/usr/local/lib/pine.info"

/* Pine-Centric Host Specifier */
#define SYSTYPE "LSU"

/* Define if system supports SYSV signal interface */
/* #undef SYSV_SIGNALS */

/* File name separator as string constant */
#define S_FILESEP "/"

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Default configuration value */
#define TRASH_FOLDER "Trash"

/* System defined unsigned 16 bit integer */
#define UINT16 uint16_t

/* System defined unsigned 32 bit integer */
#define UINT32 uint32_t

/* Compile in quota check on startup */
/* #undef USE_QUOTAS */

/* Version number of package */
#define VERSION "2.21.9"

/* Windows is just too different */
/* #undef _WINDOWS */

/* Enable extended pthread features on Solaris */
/* #undef __EXTENSIONS__ */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef mode_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* qsort compare function argument type */
#define qsort_t void

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */
