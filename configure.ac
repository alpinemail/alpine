dbl Process this file with autoconf to produce a configure script.

dnl /* ========================================================================
dnl  * Copyright 2013-2020 Eduardo Chappa
dnl  * Copyright 2006-2008 University of Washington
dnl  *
dnl  * Licensed under the Apache License, Version 2.0 (the "License");
dnl  * you may not use this file except in compliance with the License.
dnl  * You may obtain a copy of the License at
dnl  *
dnl  *     http://www.apache.org/licenses/LICENSE-2.0
dnl  *
dnl  * ========================================================================
dnl  */

AC_PREREQ([2.69])

AC_REVISION([Rev:29 by chappa@washington.edu])

dnl Alpine Version Number is in $srcdir/VERSION
AC_INIT([alpine],[m4_esyscmd(tr -d \\n < VERSION)],[chappa@washington.edu])

AC_CONFIG_SRCDIR([include/system.h])
AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign nostdinc])

AM_MAINTAINER_MODE

AC_CANONICAL_HOST

AC_LANG(C)

AC_MSG_NOTICE([Configuring for $PACKAGE_STRING ($host)])

# start out with intent to build Web Alpine
WEB_BUILD=web/src/alpined.d

dnl CHECK PROGRAMS

AC_PROG_CC
AX_PROG_CC_FOR_BUILD
AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LN_S
AC_PROG_AWK
LT_INIT
AC_SUBST([LIBTOOL_DEPS])

AC_PATH_PROG(AR, ar, ar)
AC_PATH_PROG(RM, rm, rm)
AC_PATH_PROG(CP, cp, cp)
AC_PATH_PROG(LN, ln, ln)
AC_PATH_PROG(LS, ls, ls)
AC_PATH_PROG(SED, sed, sed)
AC_PATH_PROG(MAKE, make)

dnl COMPILE-TIME OPTIONS

AM_GNU_GETTEXT_VERSION([0.16.1])
AM_GNU_GETTEXT([external])

dnl enable dmalloc per http://dmalloc.com
dnl NOTE: does not check c-client
AC_MSG_CHECKING([option: dmalloc enabled])
AC_ARG_ENABLE(dmalloc, AS_HELP_STRING([--enable-dmalloc],[Enable dmalloc debugging]))
if test x$enable_dmalloc = "xyes" ; then
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

AC_ARG_WITH(dmalloc-dir,
  AS_HELP_STRING([--with-dmalloc-dir=DIR],[Root of dmalloc lib/include path]),
  [
    if test "x$withval" != "xno" ; then
      enable_dmalloc = "yes"
      CPPFLAGS="$CPPFLAGS -I${withval}"
      LDFLAGS="$LDFLAGS -L${withval}"
    fi
  ])

if test x$enable_dmalloc = "xyes" ; then
  AC_DEFINE(ENABLE_DMALLOC, 1, [Define enable dmalloc debugging])
fi

dnl set date and hostname
ALPINE_datestamp=`date`
AC_ARG_WITH(date-stamp,
  AS_HELP_STRING([--with-date-stamp=DATE],[Set this as the date this program was built. Default: output of `date`]),
  [ 
    if test "x$withval" != "xno" ; then
     ALPINE_datestamp=$withval
    fi
  ])
AC_SUBST([ALPINE_DATESTAMP], $ALPINE_datestamp)

ALPINE_hoststamp=`hostname`
AC_ARG_WITH(host-stamp,
  AS_HELP_STRING([--with-host-stamp=HOST],[Set name of computer for compilation. Default: output of `hostname`]),
  [ 
    if test "x$withval" != "xno" ; then
      ALPINE_hoststamp="$withval"
    fi
  ])
AC_SUBST([ALPINE_HOSTSTAMP], $ALPINE_hoststamp)

dnl Set default locale dir.
case $host in
    *apple-darwin*)
      if test -d /opt/local ; then
	localedir="/opt/local/share/locale"
      else
	localedir="\${datadir}/locale"
      fi
      ;;
    *-*-cygwin)
	localedir="/usr/share"
      ;;
    *)  
      localedir="\${datadir}/locale"
      ;;
esac

AC_ARG_WITH(localedir,
  AS_HELP_STRING([--with-localedir=DIR],[Name of gettext locale directory]),
  [
    case $withval in
      yes)
        ;;
      no)
        ;;
      *)
        localedir=$withval
        ;;
    esac
  ])
AC_SUBST(localedir, "[$localedir]")

# Setup OS-Specific features
case "$host" in
  *darwin*)
    dnl OS X Universal Binary Support
    AC_ARG_ENABLE(osx-universal-binaries,
      AS_HELP_STRING([--enable-osx-universal-binaries],[Produce universal binaries under OS X [[default=no]]]))
    if test "x$enable_osx_universal_binaries" = "xyes" ; then
      if test "x$enable_dependency_tracking" != xno ; then
	AC_MSG_ERROR([--enable-osx-universal-binary requires --disable-dependency-tracking.
Please re-run configure with these options:
    --disable-dependency-tracking --enable-osx-universal-binary])
      fi
      if [test -d /Developer/SDKs/MacOSX10.5.sdk] ; then
        alpine_sysroot=/Developer/SDKs/MacOSX10.5.sdk
      elif [test -d /Developer/SDKs/MacOSX10.4u.sdk] ; then
        alpine_sysroot=/Developer/SDKs/MacOSX10.4u.sdk
      else
	AC_MSG_ERROR([No suitable MacOSX SDK found.  Make sure Xcode tools are installed])
      fi
      ub_cflags="-isysroot $alpine_sysroot -arch ppc -arch i386"
      ub_ldflags="-Wl,-syslibroot,$alpine_sysroot -arch ppc -arch i386"
      AM_CFLAGS="$AM_CFLAGS $ub_cflags"
      AM_LDFLAGS="$AM_LDFLAGS $ub_ldflags"
      alpine_c_client_cflags="$alpine_c_client_cflags $ub_cflags"
      alpine_c_client_ldflags="$alpine_c_client_ldflags $ub_ldflags"
    fi
    ;;
esac

AC_ARG_WITH(include-path,
  AS_HELP_STRING([--with-include-path=PATHS],[Colon-separated list of directories used for include file search]),
  [
    case $withval in
      no)
        ;;
      yes)
        ;;
      *)
	new_cppflags="-I`echo ${withval} | ${SED} 's/:/ -I/g'`"
	CPPFLAGS="$CPPFLAGS ${new_cppflags}"
	alpine_c_client_cflags="$alpine_c_client_cflags ${new_cppflags}"
	;;
    esac
  ])

AC_ARG_WITH(lib-path,
  AS_HELP_STRING([--with-lib-path=PATHS],[Colon-separated list of directories used for library search]),
  [
    case $withval in
      no)
        ;;
      yes)
        ;;
      *)
      	new_ldflags="-L`echo ${withval} | ${SED} 's/:/ -L/g'`"
      	LDFLAGS="$LDFLAGS $new_ldflags"
        alpine_c_client_ldflags="$alpine_c_client_ldflags ${new_ldflags}"
	;;
    esac
  ])

AC_ARG_WITH(pubcookie,
  AS_HELP_STRING([--with-pubcookie],[Include support for UW-Pubcookie Web Authentication]),
  [
    if test "x$withval" != "xno" ; then
      WEB_PUBCOOKIE_BUILD=web/src/pubcookie
    fi
  ])


AC_ARG_WITH(web-bin,
  AS_HELP_STRING([--with-web-bin=PATH],[Directory to hold Web Alpine component binary files]),
  [
    case "$withval" in
      no)
	;;
      yes)
	;;
      *)
	WEB_BINDIR=$withval
	;;
    esac
  ])

dnl disable debug, turned on by default
AC_MSG_CHECKING([option: debugging is enabled])
AC_ARG_ENABLE(debug, AS_HELP_STRING([--disable-debug],[Exclude debug from the binary]))
if test x$enable_debug != "xno" ; then
  AM_CFLAGS="$AM_CFLAGS -g"
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi
dnl we want debug messages to be compiled into the binary, but only write to a file
dnl upon user request.
AC_DEFINE([DEBUG], [1], [Compile in debugging])
AC_DEFINE([DEBUGJOURNAL], [1], [Display debug messages in journal])


dnl disable optimization, on by default
AC_MSG_CHECKING([option: optimization is enabled])
AC_ARG_ENABLE(optimization, AS_HELP_STRING([--disable-optimization],[Exclude optimizing compiler flags]))
if test x$enable_optimization != "xno" ; then
  AC_MSG_RESULT([yes])
else
  CFLAGS="`echo $AM_CFLAGS | ${SED} 's/-O2//'`"
  alpine_c_client_gccoptlevel="-O0"
  AC_MSG_RESULT([no])
fi

dnl disable mouse support
AC_MSG_CHECKING([option: mouse support enabled])
AC_ARG_ENABLE(mouse, AS_HELP_STRING([--disable-mouse],[Disable mouse support]))
if test x$enable_mouse != "xno" ; then
  AC_DEFINE([MOUSE], [], [Compile in mouse support])
  AC_MSG_RESULT([yes])
else
   AC_MSG_RESULT([no])
fi

dnl enable quotas
AC_MSG_CHECKING([option: quotas enabled])
AC_ARG_ENABLE(quotas, AS_HELP_STRING([--enable-quotas],[Enable disk quota checking on startup]))
if test x$enable_quotas = "xyes" ; then
  AC_DEFINE([USE_QUOTAS], [], [Compile in quota check on startup])
  AC_MSG_RESULT([yes])
else
   AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([option: From changing enabled])
AC_ARG_ENABLE(from_changing, AS_HELP_STRING([--disable-from-changing],[Disallow users changing From address]))
if test x$enable_from_changing != "xno" ; then
  AC_MSG_RESULT([yes])
else
  AC_DEFINE([NEVER_ALLOW_CHANGING_FROM], [], [Disallow users changing their From address])
  AC_MSG_RESULT([no])
fi

dnl enable background posting support
AC_MSG_CHECKING([option: background post enabled])
AC_ARG_ENABLE(background-post, AS_HELP_STRING([--disable-background-post],[Disable background posting]))
if test x$enable_background_post != "xno" ; then
  AC_DEFINE([BACKGROUND_POST], [], [Enable background posting support])
  AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi

dnl enable keyboard locking support
AC_MSG_CHECKING([option: keyboard lock enabled])
AC_ARG_ENABLE(keyboard-lock, AS_HELP_STRING([--disable-keyboard-lock],[Disable keyboard locking]))
if test x$enable_keyboard_lock != "xno" ; then
  AC_DEFINE([KEYBOARD_LOCK], [], [Enable keyboard lock support])
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

dnl enable from encoding support
AC_MSG_CHECKING([option: from encoding enabled])
AC_ARG_ENABLE(from-encoding, AS_HELP_STRING([--enable-from-encoding],[Enable From encoding in sent messages]))
if test x$enable_from_encoding = "xyes" ; then
  AC_DEFINE([ENCODE_FROMS], [], [Enable From address encoding in sent messages])
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

dnl OPTION: name of local submission agent
dnl         Might not be sendmail, but it MUST speak SMTP on stdin/stdout
AC_ARG_WITH(smtp-msa,
  AS_HELP_STRING([--with-smtp-msa=PATH],[Local Mail Submission Agent (sendmail)]),
    [
      case "$withval" in
	no)
	  ;;
	yes)
	  AC_PATH_PROG(SENDMAIL, sendmail, "", $PATH:/usr/sbin:/usr/lib)
	  ;;
	*)
	  SENDMAIL=$withval
	  ;;
      esac
    ],
    [
	  AC_PATH_PROG(SENDMAIL, sendmail, "", $PATH:/usr/sbin:/usr/lib)
    ])
if test -n "$SENDMAIL" ; then
    AC_DEFINE_UNQUOTED([SENDMAIL], "$SENDMAIL", [Local mail submission agent])
fi

dnl OPTION: local msa arguments
smtp_msa_flags="-bs -odb -oem"
AC_ARG_WITH(smtp-msa-flags,
  AS_HELP_STRING([--with-smtp-msa-flags=FLAGS],[MSA flags for SMTP on stdin/stdout (-bs -odb -oem)]),
  [
    if test "x$withval" != "xno" ; then
      smtp_msa_flags=$withval
    fi
  ])
AC_DEFINE_UNQUOTED([SENDMAILFLAGS], "$smtp_msa_flags", [Local MSA flags for SMTP on stdin/stdout])

dnl OPTION: name of local news posting agent and flags
npa="inews"
AC_ARG_WITH(npa,
  AS_HELP_STRING([--with-npa=PATH],[Posting agent when no nntp-servers defined (inews)]),
    [
      case "$withval" in
	no)
	  ;;
	yes)
	  AC_PATH_PROG(NPA_PROG, inews, "", $PATH:/usr/sbin:/usr/lib)
	  ;;
	*)
	  NPA_PROG=$withval
	  ;;
      esac
    ],
    [
	  AC_PATH_PROG(NPA_PROG, inews, "", $PATH:/usr/sbin:/usr/lib)
    ])

npa_flags="-h"
AC_ARG_WITH(npa-flags,
  AS_HELP_STRING([--with-npa-flags=FLAGS],[Flags to allow posting via local agent (-h)]),
  [
    if test "x$withval" != "xno" ; then
      npa_flags=$withval
    fi
  ])
if test -n "$NPA_PROG" ; then
  AC_DEFINE_UNQUOTED([SENDNEWS], "$NPA_PROG $npa_flags", [Posting agent to use when no nntp-servers defined])
fi

dnl OPTION: password changing program
AC_ARG_WITH(password-prog,
  AS_HELP_STRING([--with-password-prog=PATH],[Password change program (/bin/passwd)]),
    [
      case "$withval" in
	no)
	  ;;
	yes)
	  AC_PATH_PROG(PWPROG, passwd, "", $PATH:/usr/sbin:/usr/lib)
	  ;;
	*)
	  AC_PATH_PROG(PWPROG, $withval, "", $PATH:/usr/sbin:/usr/lib)
	  ;;
      esac
    ],
    [
	  AC_PATH_PROG(PWPROG, passwd, "", $PATH:/usr/sbin:/usr/lib)
    ])
if test -n "$PWPROG" ; then
    AC_DEFINE_UNQUOTED([PASSWD_PROG], "$PWPROG", [Program users use to change their password])
fi

dnl OPTION: basic spell checking program
AC_ARG_WITH(simple-spellcheck,
  AS_HELP_STRING([--with-simple-spellcheck=PROG],[Spellcheck program reads stdin, emits misspellings on stdout]),
    [
      if test "x$withval" != "xno" ; then
        SPELLPROG=$withval
      fi
    ],
    [
      AC_CHECK_PROG([SPELLPROG], [hunspell], [hunspell], [])
      if test -z "$SPELLPROG" ; then
        AC_CHECK_PROG([SPELLPROG], [aspell], [aspell], [])
        if test -z "$SPELLPROG" ; then
          AC_CHECK_PROG([SPELLPROG], [ispell], [ispell], [])
          if test -z "$SPELLPROG" ; then
           SPELLPROG="spell"
          fi
        fi
      fi
    ])

if test "x$SPELLPROG" != "xno" ; then
  AC_PATH_PROG(alpine_simple_spellcheck, $SPELLPROG)
  if test -n "$alpine_simple_spellcheck" ; then
    case "$SPELLPROG" in
      hunspell)
        alpine_simple_spellcheck="$alpine_simple_spellcheck -l"
        ;;
      aspell)
        alpine_simple_spellcheck="$alpine_simple_spellcheck --dont-backup --mode=email list"
        ;;
      ispell)
        alpine_simple_spellcheck="$alpine_simple_spellcheck -l"
        ;;
      *)
        ;;
    esac
  fi
fi

dnl OPTION: interactive spell checking program
AC_ARG_WITH(interactive-spellcheck,
  AS_HELP_STRING([--with-interactive-spellcheck=PROG],[Interactive, filewise spell checker]),
    [
      if test "x$withval" != "xno" ; then
        ISPELLPROG=$withval
      fi
    ],
    [
      AC_CHECK_PROG([ISPELLPROG], [hunspell], [hunspell], [])
      if test -z "$ISPELLPROG" ; then
        AC_CHECK_PROG([ISPELLPROG], [aspell], [aspell], [])
        if test -z "$SPELLPROG" ; then
          ISPELLPROG="ispell"
        fi
      fi
    ])

if test "x$ISPELLPROG" != "xno" ; then
  AC_PATH_PROG(alpine_interactive_spellcheck, $ISPELLPROG)
  if test -n "$alpine_interactive_spellcheck" ; then
    case "$ISPELLPROG" in
      aspell)
        alpine_interactive_spellcheck="$alpine_interactive_spellcheck --dont-backup --mode=email check"
        ;;
      *)
        ;;
    esac
  fi
fi

if test -n "$alpine_interactive_spellcheck" ; then
    AC_DEFINE_UNQUOTED([DF_VAR_SPELLER], "$alpine_interactive_spellcheck", [Interactive, filewise spell checker])
fi

if test -z "$alpine_simple_spellcheck" -a -n "$alpine_interactive_spellcheck" ; then
  alpine_simple_spellcheck=test
fi
AC_DEFINE_UNQUOTED([SPELLER], "$alpine_simple_spellcheck", [Simple spell checker: reads stdin, emits misspellings on stdout])

dnl OPTION: system-pinerc
dnl NOTE: historically we used /lib for the config dir.
dnl       don't ask, it was a long time ago. but, we can't
dnl       change it now without breaking compatibility
case "$prefix" in
  NONE) dpv=/usr/local/lib/pine.conf ;;
  *) dpv=${prefix}/lib/pine.conf ;;
esac
AC_ARG_WITH(system-pinerc,
  AS_HELP_STRING([--with-system-pinerc=VALUE],[System pinerc (/usr/local/lib/pine.conf)]),
    [
      case "$withval" in
	no)
	  ;;
	yes)
	  ;;
	*)
	  dpv=$withval
	  ;;
      esac
    ])
AC_DEFINE_UNQUOTED(SYSTEM_PINERC, "$dpv", [System pinerc])

dnl OPTION: system-fixed-pinerc
dnl NOTE: historically we used /lib for the config dir.
dnl       don't ask, it was a long time ago. but, we can't
dnl       change it now without breaking compatibility
case "$prefix" in
  NONE) dpv=/usr/local/lib/pine.conf.fixed ;;
  *) dpv=${prefix}/lib/pine.conf.fixed ;;
esac
AC_ARG_WITH(system-fixed-pinerc,
  AS_HELP_STRING([--with-system-fixed-pinerc=VALUE],[System fixed pinerc (/usr/local/lib/pine.conf.fixed)]),
    [
      case "$withval" in
	no)
	  ;;
	yes)
	  ;;
	*)
	  dpv=$withval
	  ;;
      esac
    ])
AC_DEFINE_UNQUOTED(SYSTEM_PINERC_FIXED, "$dpv", [System fixed pinerc])

dnl OPTION: local support information, file that contains information on
dnl 	    how to contact local support for Alpine.
dnl NOTE: historically we used /lib for the config dir.
dnl       don't ask, it was a long time ago. but, we can't
dnl       change it now without breaking compatibility
case "$prefix" in
  NONE) dpv=/usr/local/lib/pine.info ;;
  *) dpv=${prefix}/lib/pine.info ;;
esac
AC_ARG_WITH(local-support-info,
  AS_HELP_STRING([--with-local-support-info=VALUE],[Local Support Info File (/usr/local/lib/pine.info)]),
    [
      case "$withval" in
	no)
	  ;;
	yes)
	  ;;
	*)
	  dpv=$withval
	  ;;
      esac
    ])
AC_DEFINE_UNQUOTED(SYSTEM_PINE_INFO_PATH, "$dpv", [Local Support Info File])

dnl Function to simplify setting alpine/pico defaults
dnl usage: PINEVAR(configure-name, definition-name, definition-value, help)
AC_DEFUN([PINEVAR],
  [
    dpv=$3
    AC_ARG_WITH($1,
      AS_HELP_STRING([--with-$1=VALUE],[$4 ($3)]),
      [
	if test "x$withval" != "xno" ; then
	  dpv=$withval
	fi
      ])
    AC_DEFINE_UNQUOTED($2, "$dpv", [Default configuration value])
  ])

dnl Function to simplify setting pine/pico defaults
dnl usage: PINEVAR_UNQUOTED(configure-name, definition-name, definition-value, help)
AC_DEFUN([PINEVAR_UNQUOTED],
  [
    dpv=$3
    AC_ARG_WITH($1,
      AS_HELP_STRING([--with-$1=VALUE],[$4 ($3)]),
      [
	if test "x$withval" != "xno" ; then
	  dpv=$withval
	fi
      ])
    AC_DEFINE_UNQUOTED($2, $dpv, [Default configuration value])
  ])

PINEVAR(mailcheck-interval, DF_MAILCHECK, 150, [Specify default mail-check-interval])
PINEVAR_UNQUOTED(checkpoint-interval, CHECK_POINT_TIME, 420, [Specify default checkpoint-interval])
PINEVAR_UNQUOTED(checkpoint-frequency, CHECK_POINT_FREQ, 12, [State change count before checkpoint])
PINEVAR_UNQUOTED(display-rows, DEFAULT_LINES_ON_TERMINAL, 24, [Initial rows on display])
PINEVAR_UNQUOTED(display-columns, DEFAULT_COLUMNS_ON_TERMINAL, 80, [Initial columns on display])
PINEVAR_UNQUOTED(max-display-rows, MAX_SCREEN_ROWS, 200, [Maximum display rows])
PINEVAR_UNQUOTED(max-display-columns, MAX_SCREEN_COLS, 500, [Maximum display columns])
PINEVAR(fill-column, DF_FILLCOL, 74, [Default fill column])
PINEVAR_UNQUOTED(max_fill-column, MAX_FILLCOL, 80, [Maximum fill column])
PINEVAR_UNQUOTED(debug-level, DEFAULT_DEBUG, 2, [Specify default debug verbosity level])
PINEVAR_UNQUOTED(debug-files, NUMDEBUGFILES, 4, [Specify number of debug files])
PINEVAR(debug-file, DEBUGFILE, [.pine-debug], [Specify debug file name])
PINEVAR(forwarded-keyword, FORWARDED_FLAG, ["\$Forwarded"], [IMAP (c-client) keyword to store forwarded status])
PINEVAR(display-overlap, DF_OVERLAP, [2], [Lines preserved while paging])
PINEVAR(display-margin, DF_MARGIN, [0], [Lines visible while scrolling])
PINEVAR(default-fcc, DF_DEFAULT_FCC, [sent-mail], [Default sent mail folder])
PINEVAR(default-save-folder, DEFAULT_SAVE, [saved-messages], [Default save folder])
PINEVAR(default-legacy-postponed-folder, POSTPONED_MAIL, [postponed-mail], [Pre Pine 3.90 postponed folder])
PINEVAR(default-postponed-folder, POSTPONED_MSGS, [postponed-msgs], [Default postponed folder])
PINEVAR(default-trash-folder, TRASH_FOLDER, [Trash], [Default Trash folder for Web Alpine])
PINEVAR(default-interrupted-mail, INTERRUPTED_MAIL, [.pine-interrupted-mail], [Default folder for interrupted mail])
PINEVAR(default-dead-letter-folder, DEADLETTER, [dead.letter], [Default dead letter folder])
PINEVAR(default-mail-directory, DF_MAIL_DIRECTORY, [mail], [Default mail directory])
PINEVAR(default-inbox-name, INBOX_NAME, [INBOX], [Default inbox name])
PINEVAR(default-signature-file, DF_SIGNATURE_FILE, [.signature], [Default signature file])
PINEVAR(default-elm-style-save, DF_ELM_STYLE_SAVE, [no], [Default to Elm style save])
PINEVAR(default-header-in-reply, DF_HEADER_IN_REPLY, [no], [Include header in reply])
PINEVAR(default-old-style-reply, DF_OLD_STYLE_REPLY, [no], [Default to old style reply])
PINEVAR(default-use-only-domain-name, DF_USE_ONLY_DOMAIN_NAME, [no], [Default to using only the domain name])
PINEVAR(default-save-by-sender, DF_SAVE_BY_SENDER, [no], [Default to save by sender])
PINEVAR(default-sort-key, DF_SORT_KEY, [arrival], [Default sort key])
PINEVAR(default-addressbook-sort-rule, DF_AB_SORT_RULE, [fullname-with-lists-last], [Default addressbook sort rule])
PINEVAR(default-folder-sort-rule, DF_FLD_SORT_RULE, [alphabetical], [Default folder sort rule])
PINEVAR(default-saved-message-name-rule, DF_SAVED_MSG_NAME_RULE, [default-folder], [Default saved message name rule])
PINEVAR(default-fcc-rule, DF_FCC_RULE, [default-fcc], [Default fcc rule])
PINEVAR(default-standard-printer, DF_STANDARD_PRINTER, [lpr], [Default standard printern])
PINEVAR(default-ansi-printer, ANSI_PRINTER, [attached-to-ansi], [ANSI printer definition])
PINEVAR(default-addressbook, DF_ADDRESSBOOK, [.addressbook], [Default addressbook name])
PINEVAR(default-local-fullname, DF_LOCAL_FULLNAME, ["Local Support"], [Default local support fullname])
PINEVAR(default-local-address, DF_LOCAL_ADDRESS, [postmaster], [Default local support address])
PINEVAR(default-keyboard-lock-count, DF_KBLOCK_PASSWD_COUNT, [1], [Default keyboard lock count])
PINEVAR(default-remote-addressbook-history, DF_REMOTE_ABOOK_HISTORY, [3], [Default address book history count])
PINEVAR(default-html-directory, DF_HTML_DIRECTORY, [.alpine-html], [Default Directory to Temporarily Save HTML Messages])
PINEVAR(smime-public-cert-directory, DF_PUBLICCERT_DIR, [.alpine-smime/public], [Default Public Cert Directory])
PINEVAR(smime-private-key-directory, DF_PRIVATEKEY_DIR, [.alpine-smime/private], [Default Private Key Directory])
PINEVAR(smime-cacert-directory, DF_CACERT_DIR, [.alpine-smime/ca], [Default Cert Authority Directory])
PINEVAR_UNQUOTED(default-printer, DF_DEFAULT_PRINTER, [ANSI_PRINTER], [Default printer])

AC_DEFINE_UNQUOTED([DF_PUBLIC_CONTAINER], "PublicContainer", [Name of default public container])
AC_DEFINE_UNQUOTED([DF_PRIVATE_CONTAINER], "PrivateContainer", [Name of default private container])
AC_DEFINE_UNQUOTED([DF_CA_CONTAINER], "CAContainer", [Name of default certificate authority container])
AC_DEFINE_UNQUOTED([DEFAULT_SSLUSERCAPATH], ".alpine-certs", [Default directory for user trusted certificates])
AC_DEFINE_UNQUOTED([DEFAULT_SSLUSERCAFILE], ".alpine-certs/certs.pem", [Name of default container for user trusted certificates])

dnl set PASSFILE?
AC_ARG_WITH(passfile,
  AS_HELP_STRING([--with-passfile=FILENAME],[Password cache file (recommended when S/MIME is enabled and configured)]),
    [
      case "$withval" in
	no)
	  ;;
	yes)
	  ;;
	*)
	  alpine_PASSFILE=$withval
	  ;;
      esac
    ])


dnl os-specific credential cache?
AC_ARG_WITH(local-password-cache,
 AS_HELP_STRING([--without-local-password-cache],[Disable OS-specific password cache, if supported]),
   [
     alpine_os_credential_cache=$withval
   ])

dnl Particular os-specific credential cache?
AC_ARG_WITH(local-password-cache-method,
 AS_HELP_STRING([--with-local-password-cache-method],[OS-specific credential cache (OSX=APPLEKEYCHAIN, Windows=WINCRED)]),
   [
     alpine_os_credential_cache_method=$withval
   ])

if test -n "$alpine_PASSFILE" ; then
  case $alpine_os_credential_cache in
    no)
      ;;
    *)
      alpine_os_credential_cache="no"
      AC_MSG_NOTICE([--with-passfile definition overrides OS-Specific password caching])
      ;;
  esac
  AC_DEFINE_UNQUOTED([PASSFILE], "$alpine_PASSFILE", [Password cache file (recommended if S/MIME is enabled and configured)])
fi

dnl set DF_SSHPATH?
AC_ARG_WITH(default-sshpath,
  AS_HELP_STRING([--with-default-sshpath=FILENAME],[set default value of ssh command path (defining should cause ssh to be preferred to rsh)]),
    [
      case "$withval" in
	no)
	  ;;
	yes)
	  ;;
	*)
	  AC_DEFINE_UNQUOTED([DF_SSHPATH], "$withval", [set default value of ssh command path (defining should cause ssh to be preferred to rsh)])
	  ;;
      esac
    ])

dnl set DF_SSHCMD?
AC_ARG_WITH(default-sshcmd,
  AS_HELP_STRING([--with-default-sshcmd=PERCENT_S_STRING],[set default value of ssh command string (usually "%s %s -l %s exec /etc/r%sd")]),
    [
      case "$withval" in
	no)
	  ;;
	yes)
	  ;;
	*)
	  AC_DEFINE_UNQUOTED([DF_SSHCMD], "$withval", [set default value of ssh command string (usually "%s %s -l %s exec /etc/r%sd")])
	  ;;
      esac
    ])

dnl Include SSL?
dnl Set SSLDIR for c-client make
AC_ARG_WITH(ssl,
  AS_HELP_STRING([--without-ssl],[Disable SSL support (OpenSSL)]),
  [ with_ssl=$withval ])

if test "x$with_ssl" = "xno" ; then
  alpine_SSLTYPE="none"
elif test -d /usr/local/ssl ; then
dnl When the system has openssl installed in its default location
dnl instead of the one used by the distribution assume that this
dnl is the one intended to be used.
  alpine_SSLDIR="/usr/local/ssl"
  alpine_SSLINCLUDE="$alpine_SSLDIR/include" 
  alpine_SSLLIB="$alpine_SSLDIR/lib"
else
  dnl preload c-client default locations/options
  case $host in
    *-linux*|*-k*bsd*-gnu*|*-gnu*)
      if test -f /etc/fedora-release -o -f /etc/redhat-release -o -f /etc/redhat_version ; then  
        alpine_SSLTYPE="nopwd"
	if test -d /etc/pki/tls ; then  
	  alpine_SSLDIR="/etc/pki/tls"
	else
	  alpine_SSLDIR="/usr/share/ssl"
	fi
	alpine_SSLCERTS="$alpine_SSLDIR/certs"
	alpine_SSLKEYS="$alpine_SSLDIR/private"
	alpine_SSLINCLUDE="/usr/include/openssl" 
	alpine_SSLLIB="/usr/lib"
      elif test -f /etc/mandrake-release ; then
	alpine_SSLDIR="/usr/lib/ssl"
	alpine_SSLCERTS="$alpine_SSLDIR/certs" 
	alpine_SSLKEYS="$alpine_SSLDIR/private"
	alpine_SSLINCLUDE="/usr/include/openssl" 
	alpine_SSLLIB="/usr/lib"
      elif test -f /etc/SuSE-release ; then
        alpine_SSLTYPE="nopwd"
        alpine_SSLDIR="/etc/ssl"
        alpine_SSLCERTS="$alpine_SSLDIR/certs"
	alpine_SSLKEYS="$alpine_SSLDIR/private"
	alpine_SSLINCLUDE="/usr/include/openssl" 
	alpine_SSLLIB="/usr/lib"
      elif test -d /etc/osso-af-init ; then
        alpine_SSLTYPE="nopwd"
        alpine_SSLDIR="/usr"
        alpine_SSLCERTS="/usr/share/certs"
	alpine_SSLINCLUDE="/usr/include/openssl"
	alpine_SSLLIB="/usr/lib"
      elif test -f /etc/debian_release -o -f /etc/debian_version ; then
        if test ! -d /etc/osso-af-init ; then
	   alpine_SSLDIR="/etc/ssl"
	   alpine_SSLCERTS="$alpine_SSLDIR/certs"
	   alpine_SSLKEYS="$alpine_SSLDIR/private"
	   alpine_SSLINCLUDE="/usr/include/openssl" 
	   alpine_SSLLIB="/usr/lib"
        fi
      elif test -f /etc/manjaro-release ; then
	   alpine_SSLDIR="/etc/ssl"
	   alpine_SSLCERTS="$alpine_SSLDIR/certs"
	   alpine_SSLKEYS="$alpine_SSLDIR/private"
	   alpine_SSLINCLUDE="/usr/include/openssl" 
	   alpine_SSLLIB="/usr/lib"
      else
        alpine_SSLTYPE="nopwd"
        alpine_SSLDIR="/usr"
        alpine_SSLCERTS="/etc/ssl/certs"
      fi
      ;;
    *-apple-darwin*)
      alpine_SSLTYPE="nopwd"
dnl Originally this is where certs are, and they might still be there, even
dnl after installing Homebrew, MacPorts or Fink. We will use it if we cannot
dnl find it anywhere else.
      alpine_SSLCERTS_ORIG="/System/Library/OpenSSL/certs"
      if test -d /usr/local/opt/openssl ; then
	alpine_SSLDIR="/usr/local/opt/openssl"
	alpine_SSLINCLUDE="$alpine_SSLDIR/include"
	alpine_SSLLIB="$alpine_SSLDIR/lib"
	alpine_SSLCERTS="/usr/local/etc/openssl"
	alpine_SSLKEYS="$alpine_SSLDIR/private"
      elif test -d /opt/local/etc/openssl ; then
	alpine_SSLDIR="/opt/local"
	alpine_SSLINCLUDE="$alpine_SSLDIR/include"
	alpine_SSLLIB="$alpine_SSLDIR/lib"
	alpine_SSLCERTS="/opt/local/etc/openssl/certs"
	alpine_SSLKEYS="/opt/local/etc/openssl/private"
      elif test -d /sw/etc/ssl ; then
	alpine_SSLDIR="/sw/etc/ssl"
	alpine_SSLINCLUDE="/sw/include"
	alpine_SSLLIB="/sw/lib"
	alpine_SSLCERTS="/sw/etc/ssl/certs"
	alpine_SSLKEYS="/sw/etc/ssl/private"
      elif test -d /usr/local/ssl ; then
	alpine_SSLDIR="/usr/local/ssl"
      elif test -d /System/Library/OpenSSL ; then
	alpine_SSLDIR="/System/Library/OpenSSL"
        alpine_SSLCERTS="$alpine_SSLDIR/certs"
	alpine_SSLKEYS="$alpine_SSLDIR/private"
	alpine_SSLLIB="/usr/lib"
	alpine_SSLINCLUDE="/usr/include/openssl"
      fi
      ;;
    *-*-netbsd*)
	alpine_SSLDIR="/etc/openssl"
	alpine_SSLCERTS="$alpine_SSLDIR/certs"
	alpine_SSLKEYS="$alpine_SSLDIR/private"
	alpine_SSLINCLUDE="/usr/include/openssl"
	alpine_SSLLIB="/usr/lib"
      ;;
    *-*-dragonfly*)
	alpine_SSLDIR="/etc/openssl"
	alpine_SSLCERTS="$alpine_SSLDIR/certs"
	alpine_SSLKEYS="$alpine_SSLDIR/private"
	alpine_SSLINCLUDE="/usr/include/openssl"
	alpine_SSLLIB="/usr/lib"
      ;;
    *-openbsd*)
	alpine_SSLTYPE="nopwd"
	alpine_SSLDIR="/usr"
	alpine_SSLCERTS="/etc/ssl/certs"
      ;;
    *-*-freebsd*)
	alpine_SSLDIR="/etc/ssl"
	alpine_SSLCERTS="$alpine_SSLDIR/certs"
	alpine_SSLKEYS="$alpine_SSLDIR/private"
	if test -d /usr/local/include/openssl ; then
	  alpine_SSLINCLUDE="/usr/local/include/openssl" 
	  alpine_SSLLIB="/usr/local/lib"
	else
	  alpine_SSLINCLUDE="/usr/include/openssl" 
	  alpine_SSLLIB="/usr/lib"
	fi
      ;;
    *-*-openbsd*)
	alpine_SSLDIR="/etc/ssl"
	alpine_SSLINCLUDE="/usr/include/openssl"
	alpine_SSLLIB="/usr/lib"
	alpine_SSLCERTS="/etc/ssl" 
	alpine_SSLKEYS="/etc/ssl/private"
      ;;
    *-*-cygwin)
	alpine_SSLDIR="/usr/ssl"
	alpine_SSLCERTS="$alpine_SSLDIR/certs" 
	alpine_SSLKEYS="$alpine_SSLDIR/certs"
	alpine_SSLINCLUDE="/usr/include/openssl" 
	alpine_SSLLIB="/usr/lib"
      ;;
    *-sco-sysv* | *-sysv*UnixWare | *-sysv*OpenUNIX)
	alpine_SSLTYPE="sco.nopwd"
	alpine_SSLDIR="/usr/local/ssl"
      ;;
    *-*-solaris*)
      if test -d /usr/include/openssl ; then
	alpine_SSLINCLUDE="/usr/include/openssl" 
      elif test -d /usr/sfw/include/openssl ; then
        alpine_SSLDIR="/usr/sfw"
      elif test -d /opt/csw/include/openssl ; then
        alpine_SSLDIR="/opt/csw"
	if test -d /opt/csw/ssl/certs ; then
	  alpine_SSLCERTS="/opt/csw/ssl/certs"
	fi
      fi
      if test -z "$alpine_SSLCERTS" -a -d /etc/certs ; then
        alpine_SSLCERTS="/etc/certs"
      fi
      ;;
    *)
      alpine_SSLTYPE="nopwd"
      alpine_SSLDIR="/usr/local/ssl"
      ;;
  esac
fi

if test "x$alpine_SSLTYPE" != "xnone" ; then
  AC_ARG_WITH(ssl-dir,
    AS_HELP_STRING([--with-ssl-dir=DIR],[Root of SSL lib/include path]),
    [
      if test "x$withval" != "xno" ; then
	alpine_SSLDIR=$withval
	alpine_SSLINCLUDE=$alpine_SSLDIR/include
	alpine_SSLLIB=$alpine_SSLDIR/lib
      fi
    ])

  AC_ARG_WITH(ssl-certs-dir,
    AS_HELP_STRING([--with-ssl-certs-dir=DIR],[Path to SSL certificate directory]),
    [
      if test "x$withval" != "xno" ; then
	alpine_SSLCERTS=$withval
      fi
    ])

  AC_ARG_WITH(ssl-include-dir,
    AS_HELP_STRING([--with-ssl-include-dir=DIR],[SSL include file path]),
    [
      if test "x$withval" != "xno" ; then
	alpine_SSLINCLUDE=$withval
      fi
    ])

  AC_ARG_WITH(ssl-lib-dir,
    AS_HELP_STRING([--with-ssl-lib-dir=DIR],[SSL library path]),
    [
      if test "x$withval" != "xno" ; then
	alpine_SSLLIB=$withval
      fi
    ])

  dnl setup globals so tests below work
  if test -n "$alpine_SSLINCLUDE" ; then
    CPPFLAGS="-I$alpine_SSLINCLUDE $CPPFLAGS"
  elif test -n "$alpine_SSLDIR" ; then
    CPPFLAGS="-I${alpine_SSLDIR}/include $CPPFLAGS"
  fi
  if test -n "$alpine_SSLLIB" ; then
    LDFLAGS="-L$alpine_SSLLIB $LDFLAGS"
  elif test -n "$alpine_SSLDIR" ; then
    LDFLAGS="-L${alpine_SSLDIR}/lib $LDFLAGS"
  fi
fi

if test "x$alpine_SSLTYPE" != "xnone" ; then
  alpine_default_SSLMIN="no_min"
  alpine_default_SSLMAX="no_max"
  alpine_default_RANGE="${alpine_default_SSLMIN},${alpine_default_SSLMAX}"
  alpine_ENCRYPTION="$alpine_default_SSLMIN ssl3 tls1 tls1_1 tls1_2 tls1_3 $alpine_default_SSLMAX"
  alpine_SSLMIN="$alpine_default_SSLMIN"
  alpine_SSLMAX="$alpine_default_SSLMAX"
  alpine_RANGE="$alpine_default_RANGE"
  AC_ARG_WITH(encryption-minimum-version,
    AS_HELP_STRING([--encryption-minimum-version=VERSION],[Minimum SSL encryption version. Default: no_min]),
    [
      if test "x$withval" != "xno" ; then
	alpine_SSLMIN=$withval
      fi
    ])
  AC_ARG_WITH(encryption-maximum-version,
    AS_HELP_STRING([--encryption-maximum-version=VERSION],[Maximum SSL encryption version. Default: no_max]),
    [
      if test "x$withval" != "xno" ; then
	alpine_SSLMAX=$withval
      fi
    ])
  alpine_RANGE="$alpine_SSLMIN $alpine_SSLMAX"
  for range in ${alpine_RANGE} ; do
      for encryption in ${alpine_ENCRYPTION} ; do
	  if test "x$range" = "x$encryption" ; then
	     if test -z $alpine_min ; then
		alpine_min="yes"
	     else
		alpine_max="yes"
	     fi
	  fi
      done
  done

  if test -z $alpine_max ; then
     AC_MSG_ERROR(Unrecognized maximum encryption version: $alpine_max)
  fi

  if test -z $alpine_min ; then
     AC_MSG_ERROR(Unrecognized minimum encryption version: $alpine_min)
  fi

  if test "x$alpine_SSLMIN" != "x$alpine_SSLMAX" ; then
     alpine_RANGE_FEASIBLE=`echo "$alpine_ENCRYPTION" | sed "s/^.*$alpine_SSLMIN//" | grep "$alpine_SSLMAX"`
     if test -n "$alpine_RANGE_FEASIBLE" ; then
	alpine_RANGE="${alpine_SSLMIN},${alpine_SSLMAX}"
     else
        AC_MSG_WARN(Reversing order of minimum and maximum encryption)
	alpine_RANGE="${alpine_SSLMAX},${alpine_SSLMIN}"
     fi
  else
     if test "x$alpine_SSLMIN" = "x$alpine_default_SSLMIN" ; then
	AC_MSG_WARN(Overriding maximum encryption to default)
	alpine_SSLMAX="$alpine_default_SSLMAX"
     fi
     if test "x$alpine_SSLMAX" = "x$alpine_default_SSLMAX" ; then
	AC_MSG_WARN(Overriding minimum encryption to default)
	alpine_SSLMIN="$alpine_default_SSLMIN"
     fi
     alpine_RANGE="${alpine_SSLMIN},${alpine_SSLMAX}"
  fi
PINEVAR(encryption-range, DF_ENCRYPTION_RANGE, [$alpine_RANGE] , [Default Encryption Range])
fi

dnl Include Kerberos?
dnl Set GSSDIR for c-client make
AC_ARG_WITH(krb5,
  AS_HELP_STRING([--without-krb5],[Disable Kerberos support]),
  [ with_krb5=$withval ])

if test "x$with_krb5" = "xno" ; then
  alpine_GSSTYPE="none"
else
  alpine_GSSTYPE=

  AC_ARG_WITH(krb5-dir,
    AS_HELP_STRING([--with-krb5-dir=DIR],[Root of Kerberos lib/include path]),
    [
      if test "x$withval" != "xno" ; then
	CPPFLAGS="$CPPFLAGS -I${withval}/include"
	LDFLAGS="$LDFLAGS -L${withval}/lib"
      fi
    ])

  AC_ARG_WITH(krb5-include-dir,
    AS_HELP_STRING([--with-krb5-include-dir=DIR],[Kerberos include file path]),
    [
      if test "x$withval" != "xno" ; then
	CPPFLAGS="$CPPFLAGS -I$withval"
      fi
    ])

  AC_ARG_WITH(krb5-lib-dir,
    AS_HELP_STRING([--with-krb5-lib-dir=DIR],[Kerberos library path]),
    [
      if test "x$withval" != "xno" ; then
	LDFLAGS="$LDFLAGS -L$withval"
      fi
    ])
fi

dnl Include LDAP?
AC_ARG_WITH(ldap,
  AS_HELP_STRING([--without-ldap],[Disable LDAP query support]),
  [ with_ldap=$withval ])

if test "x$with_ldap" = "xno" ; then
  alpine_with_ldap=
  AC_MSG_NOTICE([Excluding LDAP Support])
else
  dnl Do stuff to figure out where OpenLDAP is

  case $host in
    *-*-freebsd*)
	alpine_LDAPDIR="/usr/local"
	alpine_LDAPINCLUDE="${alpine_LDAPDIR}/include"
	alpine_LDAPLIB="${alpine_LDAPDIR}/lib"
        ;;
  esac;

  alpine_with_ldap=yes

  AC_ARG_WITH(ldap-dir,
    AS_HELP_STRING([--with-ldap-dir=DIR],[Root of LDAP lib/include path]),
    [
      if test "x$withval" != "xno" ; then 
	alpine_LDAPDIR="${withval}"
	alpine_LDAPINCLUDE="${alpine_LDAPDIR}/include"
	alpine_LDAPLIB="${alpine_LDAPDIR}/lib"
      fi
    ])

  AC_ARG_WITH(ldap-include-dir,
    AS_HELP_STRING([--with-ldap-include-dir=DIR],[Directory containing LDAP include files]),
    [
      if test "x$withval" != "xno" ; then
	alpine_LDAPINCLUDE="$withval"
      fi
    ])

  AC_ARG_WITH(ldap-lib-dir,
    AS_HELP_STRING([--with-ldap-lib-dir=DIR],[LDAP library path]),
    [
      if test "x$withval" != "xno" ; then
	alpine_LDAPLIB="${withval}"
      fi
    ])

   if test -n "$alpine_LDAPINCLUDE" ; then
	CPPFLAGS="$CPPFLAGS -I${alpine_LDAPINCLUDE}/include"
   fi
   if test -n "$alpine_LDAPLIB" ; then
	LDFLAGS="$LDFLAGS -L${alpine_LDAPLIB}/lib"
   fi
fi

dnl Include SMIME?
AC_ARG_WITH(smime,
  AS_HELP_STRING([--without-smime],[Disable S/MIME]),
  [ with_smime=$withval ])

dnl Include TCL?
AC_ARG_WITH(tcl,
  AS_HELP_STRING([--without-tcl],[Disable TCL, thus Web Alpine support]),
  [ with_tcl=$withval ])

if test "x$with_tcl" = "xno" ; then
  WEB_BUILD=
  AC_MSG_NOTICE([Excluding TCL Support, and thus Web Alpine Support])
else
  AC_ARG_WITH(tcl-lib-dir,
    AS_HELP_STRING([--with-tcl-lib-dir=PATH],[Specific TCL Librar dir, like \"/usr/opt/tcl86/lib\"]),
    [
      if test "x$withval" != "xno" ; then 
	alpine_TCLLIBDIR=$withval
	if test -n "$alpine_TCLLIBDIR" ; then
           LDFLAGS="-L$alpine_TCLLIBDIR $LDFLAGS"
	fi
      fi
    ])
  AC_ARG_WITH(tcl-lib,
    AS_HELP_STRING([--with-tcl-lib=LIBRARY],[Specific TCL Library, like \"tcl8.6\"]),
    [
      if test "x$withval" != "xno" ; then 
	alpine_TCLLIB=$withval
      fi
    ])
  AC_ARG_WITH(tcl-include,
    AS_HELP_STRING([--with-tcl-include=DIR],[Directory containing TCL include files]),
    [
      if test "x$withval" != "xno" ; then
        CPPFLAGS="$CPPFLAGS -I$withval"
	alpine_TCLINC=$withval
      fi
    ])
fi

AC_ARG_WITH(supplied-regex,
  AS_HELP_STRING([--with-supplied-regex],[Use regex library supplied with alpine]),
  [ alpine_REGEX=$withval ])

AC_ARG_WITH(pthread,
  AS_HELP_STRING([--without-pthread],[Do NOT test for nor build with POSIX thread support]),
  [ with_pthread=$withval ])

AC_ARG_WITH(system-mail-directory,
  AS_HELP_STRING([--with-system-mail-directory=DIR],[Directory where local mail is delivered]),
  [
    if test "x$withval" != "xno" ; then
      alpine_with_local_maildir="$withval"
    fi
  ])

AC_ARG_WITH(c-client-target,
  AS_HELP_STRING([--with-c-client-target=TARGET],[IMAP build target (see imap/Makefile)]),
  [
    if test "x$withval" != "xno" ;then
      alpine_with_c_client_target="$withval"
    fi
  ])


dnl Do not build bundled tools (Default)
alpine_c_client_bundled="no"
AC_ARG_WITH(bundled-tools,
  AS_HELP_STRING([--with-bundled-tools],[ Build additional tools (mtest, imapd, etc.) Default: --with-bundled-tools=no]),
  [ 
    if test "x$withval" = "xyes" ; then
     alpine_c_client_bundled=""
    fi
  ])

dnl Assume PAM is *not* required and only set the systems that need it.
alpine_PAM="none"

dnl HOST-OS SPECIFIC DEFINITIONS
dnl Tests and assignments below are mostly to coax the appropriate
dnl build from c-client.  Most of this will go away when c-client
dnl adopts configure
case "$host" in
  *-linux*|*-k*bsd*-gnu*|*-gnu*)
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    if test -f /etc/fedora-release ; then  
      systype="LFD"
      alpine_PAM="yes"
      if test -d /etc/pki/tls ; then  
	alpine_c_client_target="lfd"
      else
	alpine_c_client_target="lrh"
      fi
    elif test -f /etc/mandrake-release ; then
      systype="LMD"
      alpine_c_client_target="lmd"
      alpine_PAM="yes"
    elif test -f /etc/redhat-release -o -f /etc/redhat_version ; then
      systype="LRH"
      alpine_PAM="yes"
      if test -d /etc/pki/tls ; then  
	alpine_c_client_target="lr5"
      else
	alpine_c_client_target="lrh"
      fi
    elif test -f /etc/debian_release -o -f /etc/debian_version ; then
      if test -d /etc/osso-af-init ; then
        systype="LN8"
        alpine_c_client_target="ln8"
      else
        systype="DEB"
        alpine_c_client_target="ldb"
	alpine_PAM="yes"
      fi
    elif test -f /etc/SuSE-release; then
      systype="LSU"
      alpine_c_client_target="lsu"
      alpine_PAM="yes"
    else
      systype="LNX"
      if test -z "$alpine_c_client_bundled" ; then
        AC_CHECK_LIB(pam, am_start,
        [
          alpine_c_client_target="lnp"
	  alpine_PAM="yes"
        ],
        [
	  if test -f /etc/shadow ; then
	    alpine_c_client_target="slx"
	  else
	    alpine_c_client_target="lnx"
	  fi
        ])
      else
	  if test -f /etc/shadow ; then
	    alpine_c_client_target="slx"
	  else
	    alpine_c_client_target="lnx"
	  fi
      fi
    fi
    ;;
  *-apple-darwin*)
    systype="OSX"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    LIBS="$LIBS -framework Carbon -framework ApplicationServices -framework Security"
    AM_CFLAGS="$AM_CFLAGS -Dbsd"
    dnl SEE include/system.h
    AC_DEFINE([OSX_TARGET],[1],[OSX TARGET])
    case "$alpine_os_credential_cache" in
      no)
	;;
      *)
	AC_DEFINE([APPLEKEYCHAIN], [1], [Use Apple OS X key chain for credential caching])
	;;
    esac
    if test -z "$alpine_c_client_bundled" ; then
      AC_CHECK_LIB(pam, pam_start,
      [
	AC_CHECK_HEADER([security/pam_appl.h],
	[
	  alpine_PAM="yes"
	  alpine_c_client_target="oxs"
	],
	[	AC_CHECK_HEADER([pam/pam_appl.h],
		[
		   alpine_PAM="yes"
		   alpine_c_client_target="oxp" 
		],
		[
		  alpine_PAM="none"
		  alpine_pam_none_reason="header files not found"
		])
	])
      ],
      [
        alpine_c_client_target="osx"
      ])
    else
        alpine_c_client_target="osx"
    fi
    ;;
  *-*-solaris*)
    if test x$GCC = "xyes" ; then
      systype="GSO"
      alpine_c_client_target="gso"
      CFLAGS="$CFLAGS -D__USE_LEGACY_PROTOTYPES__"
    else
      systype="SOC"
      alpine_c_client_target="soc"
      AC_DEFINE([__EXTENSIONS__], [1], [Enable extended pthread features on Solaris])
    fi
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    dnl possible other OS's need this.
    dnl Use autoconf 2.61's AC_USE_SYSTEM_EXTENSIONS at some point
    ;;
  *-*-sunos4*)
    systype="SUN"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="s40"
    ;;
  *-*-sco3.2v5*)
    if test x$GCC = "xyes" ; then
      systype="GO5"
      alpine_c_client_target="go5"
    else
      systype="SC5"
      alpine_c_client_target="sc5"
    fi
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    dnl possible other OS's need this.
    dnl Use autoconf 2.61's AC_USE_SYSTEM_EXTENSIONS at some point
    ;;
  *-next-*)
    systype="NXT"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="nx3"
    ;;
  *-*-netbsd*)
    systype="NEB"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="neb"
    ;;
  *-*-dragonfly*)
    systype="DFB"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="neb"
    ;;
  *-*-bsdi*)
    systype="BSI"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="bsi"
    ;;
  *-*-freebsd*)
    systype="BSF"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="bsf"
    LIBS="$LIBS $LIBINTL"
    ;;
  *-*-openbsd*)
    systype="BSO"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="bso"
    LIBS="$LIBS $LIBINTL"
    ;;
  *-*-aix5*)
    systype="A52"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="a52"
    ;;
  *-*-aix4*)
    systype="A41"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="a41"
    ;;
  *-*-aix3*)
    systype="A32"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="a32"
    ;;
  *-*UNIX_SV | *-*-sysv5UnixWare7* | *-*OpenUNIX*)
    systype="UW2"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="uw2"
    ;;
  *-*-osf5*)
    systype="OSF"
    alpine_path_delim="/"
    alpine_mode_readonly="(0600)"
    alpine_c_client_target="osf"
    ;;
  *-*-cygwin)
    systype="CYG"
    alpine_path_delim="/"
    alpine_mode_readonly="(S_IREAD | S_IWRITE)"
    alpine_c_client_target="cyg"
    LIBS="$LIBS $LIBINTL"
    ;;
  windows* | *-*-pw32*)
    systype="WNT"
    alpine_path_delim="\\"
    alpine_mode_readonly="(S_IREAD | S_IWRITE)"
    alpine_c_client_target="wnt"
    AC_DEFINE([_WINDOWS], [1], [Windows is just too different])
    ;;
  *)
    AC_MSG_ERROR(Unrecognized system: $host)
    ;;
esac

dnl Without IPv6?
AC_ARG_WITH(ipv6,
  AS_HELP_STRING([--without-ipv6],[Disable IPv6, primarily to work around resolver problems]),
  [ with_ipv6=$withval ])

if test "x$with_ipv6" = "xno" ; then
  AC_MSG_NOTICE([Excluding IPv6 Support])
  c_client_specials="${c_client_specials}IP6=4 "
  c_client_ip6="true"
else
  c_client_ip6="touch imap/ip6"
fi


dnl CHECK LIBRARIES

if test x$enable_dmalloc = "xyes" ; then
  if test "x$with_pthread" = "xyes" ; then
    dmalloc_lib=dmallocth
  else
    dmalloc_lib=dmalloc
  fi

  AC_CHECK_LIB($dmalloc_lib,dmalloc_shutdown,,
    [
      AC_MSG_ERROR($dmalloc_lib requested, but -ldmalloc not found)
    ])
fi

dnl which terminal cabability database
AC_CHECK_LIB(tinfo, setupterm,
  [
    alpine_termdata=info
    LIBS="$LIBS -ltinfo"
  ],
  [
    AC_CHECK_LIB(ncurses, setupterm,
      [
        alpine_termdata=info
        LIBS="$LIBS -lncurses"
      ],
      [
        AC_CHECK_LIB(curses, setupterm,
          [
            alpine_termdata=info
            LIBS="$LIBS -lcurses"
          ],
          [
            AC_CHECK_LIB(termlib, tgetent,
              [
                alpine_termdata=cap
                LIBS="$LIBS -ltermlib"
              ],
              [
                AC_CHECK_LIB(termcap, tgetent,
                  [
                    alpine_termdata=cap
                    LIBS="$LIBS -ltermcap"
                  ],
                  [
                    AC_MSG_ERROR(Terminfo/termcap not found)
                  ])
              ])
          ])
      ])
  ])
case $alpine_termdata in
  info)
    AC_DEFINE(HAS_TERMINFO, [1], [Define if systems uses terminfo terminal database])
    ;;
  cap)
    AC_DEFINE(HAS_TERMCAP, [1], [Define if systems uses termcap terminal database])
    ;;
esac

dnl is -ldl present? if so, add it
AC_SEARCH_LIBS([dlopen], [dl dld],, [ alpine_DL="none" ])
if test "x$alpine_DL" = "xnone" ; then
    AC_MSG_ERROR([No library containing dlopen found])
    exit 1	
fi

dnl Check if openssl = LibreSSL
if test "x$alpine_SSLTYPE" != "xnone" ; then
  AC_MSG_CHECKING([if OpenSSL is LibreSSL])
  AC_TRY_COMPILE([
#include <stdio.h>
#include <stdlib.h>
#if HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */
#include <openssl/ssl.h>
	],[
#if OPENSSL_VERSION_NUMBER != 0x20000000L
#error
#endif
	],
	[ AC_MSG_RESULT(yes)
	  alpine_SSLPROVIDER="libressl"
	],
	[ AC_MSG_RESULT(no)
	],
	[ AC_MSG_WARN([cross compiling: not checking])])
fi

dnl Check Openssl/LibreSSL version first
if test "x$alpine_SSLTYPE" != "xnone" -a "x$alpine_SSLPROVIDER" != "xlibressl" ; then
  AC_MSG_CHECKING([Openssl library version >= 1.0.0c])
  AC_TRY_COMPILE([
#include <stdio.h>
#include <stdlib.h>
#if HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */
#include <openssl/ssl.h>
	],[
#if OPENSSL_VERSION_NUMBER < 0x1000003fL
#error
#endif
	],
	[ AC_MSG_RESULT(yes) 
	  alpine_SSLPROVIDER="openssl"
	],
	[ alpine_SSLTYPE="none" ],
	[ AC_MSG_WARN([cross compiling: not checking])])

    if test "x$alpine_SSLTYPE" = "xnone" ; then
	AC_MSG_ERROR(Install openssl version >= 1.0.0c)
	exit 1
    fi
fi

dnl Now check if we are working with version 1.1.0 of openssl
if test "x$alpine_SSLTYPE" != "xnone" -a "x$alpine_SSLPROVIDER" != "xlibressl" ; then
  AC_MSG_CHECKING([Openssl library version >= 1.1.0])
  AC_TRY_COMPILE([
#include <stdio.h>
#include <stdlib.h>
#if HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */
#include <openssl/ssl.h>
	],[
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error
#endif
	],
	[ AC_MSG_RESULT(yes)
	  alpine_SSLVERSION="new"
	  CFLAGS="$CFLAGS -DOPENSSL_1_1_0 -DOPENSSL_API_COMPAT=0x10100000L"
	],
	[ AC_MSG_RESULT(no)
	  alpine_SSLVERSION="old" ],
	[ AC_MSG_WARN([cross compiling: not checking])])
fi

dnl Crypto support is needed 
if test "x$alpine_SSLTYPE" != "xnone" ; then
  if test "x$alpine_SSLVERSION" = "xold" ; then
     AC_SEARCH_LIBS(SSLeay,crypto,, [ alpine_CRYPTO="none" ])
  else
     AC_SEARCH_LIBS(OpenSSL_version_num,crypto,, [ alpine_CRYPTO="none" ])
  fi
  if test "x$alpine_CRYPTO" = "xnone" ; then
     AC_MSG_ERROR(crypto library NOT found)
     exit 1
  fi
  case $host in
    *-*-cygwin)
	AC_CHECK_HEADER(crypto.h, , [ alpine_CRYPTO_DEVEL="none" ])
	if test "x$alpine_CRYPTO_DEVEL" = "xnone" ; then
	   AC_MSG_ERROR(crypto library file crypto.h NOT found. Install corresponding libcrypt-devel package)
	   exit 1
	fi
	;;
    *)  ;;
   esac
fi

dnl provide SSL support?
if test "x$alpine_SSLTYPE" != "xnone" ; then
  if test "x$alpine_SSLVERSION" = "xold" ; then
     AC_SEARCH_LIBS(SSL_library_init,ssl,,[ alpine_SSLTYPE="none" ])
     if test "x$alpine_SSLTYPE" = "xnone" ; then
        AC_MSG_ERROR(No library containing SSL_library_init found in your path)
        exit 1
     fi
  else
     AC_SEARCH_LIBS(OPENSSL_init_ssl,ssl,, [ alpine_SSLTYPE="none" ])
     if test "x$aalpiLlpine_SSLTYPE" = "xnone" ; then
        AC_MSG_ERROR(No library containing OPENSSL_init_ssl found in your path)
        exit 1
     fi
  fi
fi

dnl provide LDAP support?
if test "$alpine_with_ldap" = "yes" ; then
  alpine_has_ldap=
  AC_CHECK_LIB(lber, ber_alloc,
    [
      LIBS="$LIBS -llber"
    ])
  AC_SEARCH_LIBS(ldap_initialize,ldap,
    [
      alpine_has_ldap=yes
    ],
    [
      AC_SEARCH_LIBS(ldap_open,ldap,
	[
	  alpine_has_ldap=yes
	])
    ])

  if test "$alpine_has_ldap" = "yes" ; then
    AC_MSG_NOTICE([* * * Including LDAP Support])
    AC_DEFINE([ENABLE_LDAP], [], [Enable LDAP query support])
  fi
fi

dnl PAM support is needed to build c-client in some linux, and hence Alpine.
if test -z "$alpine_c_client_bundled" ; then
  if test "x$alpine_PAM" != "xnone" ; then
     AC_SEARCH_LIBS(pam_start,pam,
      [
	LIBS="$LIBS -lpam"
	AC_CHECK_HEADER([security/pam_appl.h],
	[
	  alpine_PAM="yes"
	],
	dnl Only mac is incompatible, do not spread bad habits.
	[ AC_CHECK_HEADER([pam/pam_appl.h],
	  [
		alpine_PAM="yes"
		if test "x$alpine_c_client_target" != "xoxp" ; then
		   alpine_PAM="none"
		   alpine_pam_none_reason="header files not in security/ directory"
		fi
	  ],
	  [
		alpine_PAM="none"
		alpine_pam_none_reason="header files not found"
	  ])
	])
      ],
      [
	alpine_PAM="none"
	alpine_pam_none_reason="library files not found"
      ])
    if test -n "$alpine_pam_none_reason" ; then
       AC_MSG_ERROR(Trying to build bundled tools but could not find libpam. Install it first and try again, or do not use --with-bundled-tools)
    fi
  fi
fi

if test -n "$alpine_c_client_bundled" ; then
     AC_SEARCH_LIBS(crypt,crypt,,
      [
       AC_MSG_ERROR([crypt library not found.])
      ])
fi

AC_SUBST([C_CLIENT_BUNDLED], $alpine_c_client_bundled)

dnl provide KRB5 support?
if test "x$alpine_GSSTYPE" != "xnone" ; then
  AC_SEARCH_LIBS(gss_init_sec_context,gss gssapi gssapi_krb5,
    [
      dnl MIT-based?
      LIBS="$LIBS -lkrb5"
      AC_CHECK_HEADER([gssapi/gssapi_generic.h],,
	[
	  if test ! -d /usr/kerberos/include ; then
	    alpine_GSSTYPE="none"
	    alpine_gss_none_reason="header files not found"
	  fi
	])
    ],
    [
      alpine_GSSTYPE="none"
      alpine_gss_none_reason="libraries not found"
    ])
  if test -n "$alpine_gss_none_reason" ; then
    AC_MSG_NOTICE([NOT including Kerberos Support: $alpine_gss_none_reason])
  fi
fi

dnl Include NTLM?
AC_ARG_WITH(ntlm,
  AC_HELP_STRING([--without-ntlm],[Disable NTLM client support]),
  [with_ntlm=$withval])

dnl provide NTLM support?
if test "x$with_ntlm" = "xno" ; then
  alpine_NTLM="none"
else
  alpine_NTLM=

  AC_SEARCH_LIBS(buildSmbNtlmAuthRequest, ntlm, 
     [
        AC_CHECK_HEADER([ntlm.h],
	[
	    extra_auth_ntlm=ntl
	    AC_MSG_NOTICE([including NTLM support])
	],
	[
	    alpine_NTLM="none"
	    alpine_ntlm_none_reason="header file ntlm.h not found"
	])
     ],
     [
	alpine_NTLM="none"
	alpine_ntlm_none_reason="ntlm library not found"
     ])
  if test -n "$alpine_ntlm_none_reason" ; then
     AC_MSG_NOTICE([NOT including NTLM Support: $alpine_ntlm_none_reason])
  fi
fi

dnl check for tcl libraries for Web Alpine (HACKY)
if test -n "$WEB_BUILD" ; then
TCL_VERSIONS_DOT="tcl8.6 tcl8.5 tcl8.4 tcl8.3"
TCL_VERSIONS_NODOT="`echo ${TCL_VERSIONS_DOT} | ${SED} 's/\.//g'`"
TCL_VERSIONS="${TCL_VERSIONS_DOT} ${TCL_VERSIONS_NODOT} tcl"
  dnl look for header file
  if test -n "$alpine_TCLINC" ; then
    AC_CHECK_HEADER($alpine_TCLINC/tcl.h,,
      [
	WEB_BUILD=
      ])
    if test -z "$WEB_BUILD" ; then
      AC_MSG_NOTICE([Tcl Include file NOT found])
    fi
  else
    AC_CHECK_HEADER(tcl.h,,
      [
	for base in /usr /usr/local ; do
	 for dir in ${TCL_VERSIONS} ; do
	  if test -f $base/include/$dir/tcl.h ; then
	    CPPFLAGS="$CPPFLAGS -I$base/include/$dir"
	    found=yes
	    break
	  fi
	 done
	 if test "x$found" = "xyes" ; then
	    break
	 fi
	done
	if test "$found" != "yes" ; then
	    WEB_BUILD=
	    AC_MSG_NOTICE([header file tcl.h NOT found: Web Alpine will not be built])
	fi
      ])
  fi
  if test -n "$WEB_BUILD" ; then
    AC_SEARCH_LIBS([Tcl_Eval],[$alpine_TCLLIB ${TCL_VERSIONS}],,
      [
        WEB_BUILD=
      ])
    fi
fi

dnl Local or supplied regex?
if test "x$alpine_REGEX" != "xyes" ; then
  AC_SEARCH_LIBS([regcomp],posix regexp regex re,,
    [
      if test x$alpine_REGEX = "xno" ; then
        AC_MSG_ERROR(Unable to find system regex library)
      else
	alpine_REGEX=yes
      fi
    ])
fi
if test "x$alpine_REGEX" != "xyes" ; then
  AC_CHECK_HEADER([regex.h],,
    [
      if test x$alpine_REGEX = "xno" ; then
	AC_MSG_ERROR(Unable to find system regex include file)
      else
	alpine_REGEX=yes
      fi
    ])
fi
AC_DEFINE(HAVE_REGEX_H,1,[Regular expression header file exists])
if test "x$alpine_REGEX" = "xyes" ; then
  CPPFLAGS="$CPPFLAGS -I${top_builddir}/regex"
  LDFLAGS="$LDFLAGS -L${top_builddir}/regex"
  REGEX_BUILD=regex
  REGEX_MAKEFILE="$REGEX_BUILD/Makefile"
fi

if test "x$with_pthread" != "xno" ; then
  AC_MSG_CHECKING([for pthread support])
  ACX_PTHREAD(
    [
      AC_MSG_RESULT([yes])
      case "$target" in
	  *openbsd*)
	    AC_MSG_NOTICE([WARNING: pthread support on OpenBSD is unstable!])
	    AM_CFLAGS="$AM_CFLAGS -pthread"
	    ;;
      esac
      LIBS="$PTHREAD_LIBS $LIBS"
      AM_CFLAGS="$AM_CFLAGS $PTHREAD_CFLAGS"
      CC="$PTHREAD_CC"
      AC_DEFINE([HAVE_PTHREAD], [1], [System has pthread support])
    ],
    [
      AC_MSG_RESULT([no])
    ])

  AC_SEARCH_LIBS([nanosleep], [rt posix4],
    [
      AC_DEFINE([HAVE_NANOSLEEP], [1], [Define if system supports subsecond, non-alarm sleep])
    ])
fi



dnl CHECK HEADERS

AC_HEADER_STDC
AC_HEADER_DIRENT
AC_HEADER_STAT
AC_HEADER_SYS_WAIT
AC_HEADER_TIME
AC_HEADER_TIOCGWINSZ

AC_CHECK_HEADERS([unistd.h])

AC_CHECK_HEADERS([errno.h \
		  ctype.h \
		  fcntl.h \
		  signal.h \
		  setjmp.h \
		  memory.h \
		  sys/ioctl.h \
		  sys/param.h \
		  sys/socket.h \
		  sys/uio.h \
		  sys/un.h \
		  limits.h \
		  wchar.h \
		  sys/poll.h \
		  stropts.h \
		  netdb.h \
		  syslog.h \
		  sys/syslog.h \
		  locale.h \
		  langinfo.h \
		  utime.h \
		  sys/utime.h \
		  pthread.h \
		  pwd.h \
		  assert.h])

dnl terminal line discipline?
AC_CHECK_HEADER([termios.h],
  AC_DEFINE(HAS_TERMIOS, [1], [Define if systems uses termios terminal control]),
  [
    AC_CHECK_HEADER([termio.h],
      AC_DEFINE(HAS_TERMIO, [1], [Define if systems uses termio terminal control]),
      [
        AC_CHECK_HEADER([sgtty.h],
	  AC_DEFINE(HAS_SGTTY, [1], [Define if systems uses old BSD-style terminal control]),
	[
	  AC_MSG_ERROR(Unable to figure out terminal control method)
	])
      ])
  ])


dnl CHECK TYPEDEFS

AC_DIAGNOSE([obsolete],[your code may safely assume C89 semantics that RETSIGTYPE is void.
Remove this warning and the `AC_CACHE_CHECK' when you adjust the code.])dnl
AC_CACHE_CHECK([return type of signal handlers],[ac_cv_type_signal],[AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([#include <sys/types.h>
#include <signal.h>
],
		 [return *(signal (0, 0)) (0) == 1;])],
		   [ac_cv_type_signal=int],
		   [ac_cv_type_signal=void])])
AC_DEFINE_UNQUOTED([RETSIGTYPE],[$ac_cv_type_signal],[Define as the return type of signal handlers
		    (`int' or `void').])

AC_TYPE_SIZE_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_UID_T
AC_STRUCT_TM

AC_CHECK_TYPES([union wait])

AC_CHECK_HEADERS([stdint.h], [uint16=uint16_t], [
  AC_CHECK_HEADERS([inttypes.h], [uint16=uint16_t], [
    AC_CHECK_HEADERS([sys/types.h], [uint16=u_int16_t], [
      AC_CHECK_SIZEOF(unsigned short)
      if test $ac_cv_sizeof_unsigned_short -eq 2 ; then
	uint16="unsigned short"
      else
	AC_CHECK_SIZEOF(unsigned int)
	if $ac_cv_sizeof_unsigned_int -eq 2 ; then
	  uint16="unsigned int"
	else
	  AC_MSG_ERROR(Unable to determine 16 bit integer type)
        fi
      fi
    ])
  ])
])
AC_DEFINE_UNQUOTED([UINT16], $uint16, [System defined unsigned 16 bit integer])

AC_CHECK_HEADERS([stdint.h], [uint32=uint32_t], [
  AC_CHECK_HEADERS([inttypes.h], [uint32=uint32_t], [
    AC_CHECK_HEADERS([sys/types.h], [uint32=u_int32_t], [
      AC_CHECK_SIZEOF(unsigned int)
      if test $ac_cv_sizeof_unsigned_int -eq 4 ; then
	uint32="unsigned int"
      else
	AC_CHECK_SIZEOF(unsigned long)
	if $ac_cv_sizeof_unsigned_long -eq 4 ; then
	  uint32="unsigned long"
	else
	  AC_MSG_ERROR(Unable to determine 32 bit integer type)
        fi
      fi
    ])
  ])
])
AC_DEFINE_UNQUOTED([UINT32], $uint32, [System defined unsigned 32 bit integer])

AC_CACHE_CHECK(argument pointer type of qsort compare function and base,
ac_cv_func_qsort_argtype,
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if	HAVE_STDLIB_H
#include "stdlib.h"
#endif

extern void *base;
extern sortf(const void *, const void *);
int sortf(a, b)
  const void *a;
  const void *b; { return 0; }
]], [[
qsort(base, 2, sizeof(char *), sortf);
]])],[ac_cv_func_qsort_argtype=void],[ac_cv_func_qsort_argtype=char])
])
AC_DEFINE_UNQUOTED([qsort_t], $ac_cv_func_qsort_argtype, [qsort compare function argument type])

dnl check for "struct passwd" ?

AC_FUNC_SELECT_ARGTYPES

AC_FUNC_STRCOLL

dnl CHECK FOR LIBRARY FUNCTIONS

AC_FUNC_FORK
AC_CHECK_FUNCS([strchr \
		memcpy \
		strtol \
		strtoul \
		select \
		poll \
		qsort \
	 	getuid \
		getpwuid \
		getpwnam \
	        gettimeofday \
		tmpfile \
		uname \
		rename \
		read \
		signal \
		setjmp \
		chown \
		wait4 \
		waitpid \
		wait \
		srandom \
		popen \
		pclose \
		fsync \
		truncate \
		listen \
		wcwidth \
		mbstowcs \
		wcrtomb \
		putenv \
		setenv])

AC_SEARCH_LIBS([gethostname],[nsl])

AC_SEARCH_LIBS([socket],[socket],,
  [
    WEB_BUILD=
  ])

AC_SEARCH_LIBS([bind],[bind],,
  [
    WEB_BUILD=
  ])

dnl check for POSIX signal interface
AC_CHECK_FUNCS([sigaction sigemptyset sigaddset sigprocmask],
  [
    AC_DEFINE([POSIX_SIGNALS], [], [Define if system supports POSIX signal interface])
  ],
  [
    AC_CHECK_FUNCS([sigset sigrelse],
      [
	AC_DEFINE([SYSV_SIGNALS], [], [Define if system supports SYSV signal interface])
      ])
  ])

AC_SEARCH_LIBS([syslog], [bsd socket inet],
  [
    AC_DEFINE([HAVE_SYSLOG], [1], [Define if system supplies syslog() logging])
  ])


dnl set pico newmail check directory
if test -n "$alpine_with_local_maildir" ; then
    alpine_local_maildir=$alpine_with_local_maildir
elif test -d /var/spool/mail ; then
    alpine_local_maildir="/var/spool/mail"
elif test -d /var/mail ; then
    alpine_local_maildir="/var/mail"
else
    alpine_local_maildir="/usr/spool/mail"
fi

dnl set c-client make target
if test -n "$alpine_with_c_client_target" ; then
    alpine_c_client_target=$alpine_with_c_client_target
fi

AC_DEFINE_UNQUOTED([SYSTYPE], "$systype", [Pine-Centric Host Specifier])
AC_DEFINE_UNQUOTED([C_FILESEP],'$alpine_path_delim',[File name separator as character constant])
AC_DEFINE_UNQUOTED([S_FILESEP],"$alpine_path_delim",[File name separator as string constant])
AC_DEFINE_UNQUOTED([MAILDIR],"$alpine_local_maildir",[Path to local inboxes for pico newmail check])
AC_DEFINE_UNQUOTED([MODE_READONLY], $alpine_mode_readonly, [File mode used to set readonly access])
AC_DEFINE_UNQUOTED([HTML_EXT],"html",[Default extension for html files])

dnl c-client make particulars
AC_SUBST([C_CLIENT_TARGET], $alpine_c_client_target)
AC_SUBST([C_CLIENT_WITH_IPV6], $c_client_ip6)
if test "x$alpine_SSLTYPE" = "xnone" ; then 
  AC_MSG_NOTICE([* * *  NOT Including SSL Support])
  c_client_specials="${c_client_specials}SSLTYPE=none "
else
  dnl issue any warnings for common OpenSSL issues

  if test -n "$alpine_SSLCERTS" -a -d "$alpine_SSLCERTS" ; then
    certdir="$alpine_SSLCERTS"
  elif test -n "$alpine_SSLDIR" -a -d "${alpine_SSLDIR}/certs" ; then
    certdir="${alpine_SSLDIR}/certs"
  elif test -n "$alpine_SSLDIR" -a -d "${alpine_SSLDIR}/ssl/certs" ; then
    certdir="${alpine_SSLDIR}/ssl/certs"
  elif test -n "$alpine_SSLCERTS_ORIG" -a -d "$alpine_SSLCERTS_ORIG" ; then
    certdir="$alpine_SSLCERTS_ORIG"
  elif test -n "$alpine_SSLCERTS" ; then
    certdir="$alpine_SSLCERTS"
  else
    AC_MSG_NOTICE([SSL Problem: certificate directory not found])
  fi

  if test "x$with_smime" != "xno" ; then
    if test -n "$certdir" ; then
      AC_MSG_NOTICE([* * * S/MIME support enabled])
      AC_DEFINE([SMIME], [], [Enable S/MIME code])
      AC_DEFINE_UNQUOTED([SMIME_SSLCERTS],"$certdir",[Directory where S/MIME CACerts are located])
    fi
  fi


  SSL_CERT_LINK="no"
  if test -z "`ls ${certdir} | $EGREP '^@<:@0-9A-Fa-f@:>@{8}\.@<:@0-9@:>@'`" ; then
     SSL_BUNDLE_EXISTS="no"
     SSL_PEM="factory.pem ca-bundle.pem cert.pem ca-bundle.crt ca-root-nss.crt"
     for SSL_BUNDLE in $SSL_PEM
     do
       if test -f ${certdir}/${SSL_BUNDLE} ; then
          SSL_BUNDLE_EXISTS="yes"
       fi
     done
  else
     SSL_CERT_LINK="yes"
  fi

  if test "x$SSL_BUNDLE_EXISTS" = "xno" -a "x$SSL_CERT_LINK" = "xno" ; then
     AC_MSG_NOTICE([* * * No certificates found in "${certdir}".])
     AC_MSG_NOTICE([* * *   This might indicate that CA certs did not get properly])
     AC_MSG_NOTICE([* * *   installed.  If you get certificate validation failures])
     AC_MSG_NOTICE([* * *   in Alpine, this might be the reason for them.])
  fi

  if test -n "$alpine_SSLINCLUDE" ; then
    c_client_specials="${c_client_specials}SSLINCLUDE=$alpine_SSLINCLUDE "
  fi

  if test -n "$alpine_SSLLIB" ; then
    c_client_specials="${c_client_specials}SSLLIB=$alpine_SSLLIB "
  fi

  if test -n "$alpine_SSLDIR" ; then
    c_client_specials="${c_client_specials}SSLDIR=$alpine_SSLDIR "
  fi

  if test -n "$certdir" ; then
    c_client_specials="${c_client_specials}SSLCERTS=$certdir "
  fi

  if test -n "$alpine_SSLKEYS" ; then
      c_client_specials="${c_client_specials}SSLKEYS=$alpine_SSLKEYS "
  fi
fi

extra_auth_gss=
if test "x$alpine_GSSTYPE" != "xnone" ; then
  extra_auth_gss=gss
  AC_MSG_NOTICE([* * * Including Kerberos5 functionality])
fi

extra_auth_ntlm=
if test "x$alpine_NTLM" != "xnone" ; then
  extra_auth_ntlm=ntl
  AC_MSG_NOTICE([* * * Including NTLM Authenticator])
fi

if test -n "$CPPFLAGS" ; then
  alpine_c_client_cflags="$alpine_c_client_cflags ${CPPFLAGS}"
fi
if test -n "$CFLAGS" ; then
  alpine_c_client_cflags="$alpine_c_client_cflags ${CFLAGS}"
fi

if test -n "$alpine_c_client_cflags" ; then
  AC_SUBST(C_CLIENT_CFLAGS, EXTRACFLAGS=\"$alpine_c_client_cflags\")
fi

if test -n "$LDFLAGS" ; then
  alpine_c_client_ldflags="$alpine_c_client_ldflags ${LDFLAGS}"
fi
if test -n "$LIBS" ; then
  alpine_c_client_ldflags="$alpine_c_client_ldflags ${LIBS}"
fi

if test -n "$alpine_c_client_ldflags" ; then
  AC_SUBST(C_CLIENT_LDFLAGS, EXTRALDFLAGS=\"$alpine_c_client_ldflags\")
fi

if test -n "$alpine_c_client_gccoptlevel" ; then
  AC_SUBST(C_CLIENT_GCCOPTLEVEL, GCCOPTLEVEL=\"$alpine_c_client_gccoptlevel\")
fi

c_client_auths="$extra_auth_gss $extra_auth_ntlm"
AC_SUBST([C_CLIENT_AUTHS], $c_client_auths)

AC_SUBST([C_CLIENT_SPECIALS], $c_client_specials)

dnl Deal with Web Alpine
if test -z "$WEB_BUILD" ; then
  WEB_PUBCOOKIE_BUILD=
  AC_MSG_NOTICE([* * * TCL libraries could not be found.])
  AC_MSG_NOTICE([* * * WEB ALPINE COMPONENT WILL NOT BE BUILT.])
else
  if test -n "$WEB_PUBCOOKIE_BUILD" ; then
    if test "x$alpine_GSSTYPE" = "xnone" ; then
      WEB_PUBCOOKIE_BUILD=
      AC_MSG_NOTICE([* * * Kerberos5 support not found.])
      AC_MSG_NOTICE([* * * WEB ALPINE PUBCOOKIE COMPONENT WILL NOT BE BUILT.])
    elif test -z "$WEB_BINDIR" ; then
      WEB_PUBCOOKIE_BUILD=
      AC_MSG_NOTICE([* * * Web Alpine binary directory not provided.])
	AC_MSG_ERROR([* * * --with-pubcookie requires --with-web-bin=PATH.
        Please re-run configure with these options:
        --with-pubcookie --with-web-bin=/usr/local/libexec/alpine/bin])
    else
      AC_DEFINE([PUBCOOKIE],[1],[Include support for UW Pubcookie Web Authentication])
      WEB_PUBCOOKIE_LIB=../pubcookie/libauthgssproxy.a
      WEB_PUBCOOKIE_LINK=gssapi_proxy.l
    fi
  fi
fi

AC_SUBST([REGEX_BUILD])

AC_SUBST([WEB_BUILD])
AC_SUBST([WEB_BINDIR])
AC_SUBST([WEB_PUBCOOKIE_BUILD])
AC_SUBST([WEB_PUBCOOKIE_LIB])
AC_SUBST([WEB_PUBCOOKIE_LINK])

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_CONFIG_FILES([m4/Makefile po/Makefile.in $REGEX_MAKEFILE \
	  pith/osdep/Makefile pith/charconv/Makefile pith/Makefile \
	  pico/osdep/Makefile pico/Makefile \
	  alpine/osdep/Makefile alpine/Makefile \
	  web/src/Makefile web/src/pubcookie/Makefile \
	  web/src/alpined.d/Makefile \
	  Makefile])
AC_OUTPUT
