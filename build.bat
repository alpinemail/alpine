@echo OFF
rem $Id: build.bat 14098 2005-10-03 18:54:13Z jpf@u.washington.edu $
rem ========================================================================
rem Copyright 2006-2007 University of Washington
rem
rem Licensed under the Apache License, Version 2.0 (the "License");
rem you may not use this file except in compliance with the License.
rem You may obtain a copy of the License at
rem
rem     http://www.apache.org/licenses/LICENSE-2.0
rem
rem ========================================================================

if "%1"=="" goto blank
if "%1"=="wnt" goto wnt
if "%1"=="w2k" goto w2k
if "%1"=="clean" goto clean
echo Unknown build command: %1 %2 %3 %4
goto usage
:blank
echo Must specify build command!
:usage
echo usage: BUILD cmd
echo   where "cmd" is one of either:
echo         wnt        -- Windows
echo         w2k        -- Windows with Win2k Kerb
echo         clean      -- to remove obj, lib, and exe files from source
goto fini

:wnt
echo PC-Alpine for Windows/Winsock (Win32) build sequence
set cclntmake=makefile.nt
set alpinemake=makefile.wnt
if not defined ALPINE_LIBRESSL set ALPINE_LIBRESSL=%cd%\libressl
if exist "%ALPINE_LIBRESSL%" goto yeslibresslwnt
echo NOT including LIBRESSL functionality
set libresslflags=
set libressllibes=
set libresslextralibes="crypt32.lib"
goto ldapincludewnt
:yeslibresslwnt
set libresslflags=-I\"%ALPINE_LIBRESSL%\"\include -DENABLE_WINDOWS_LIBRESSL -DLIBRESSL_INTERNAL
set libressllibes=\"%ALPINE_LIBRESSL%\"\x86\libcrypto-41.lib \"%ALPINE_LIBRESSL%\"\x86\libssl-43.lib \"%ALPINE_LIBRESSL%\"\x86\libtls-15.lib
set libresslextralibes=
:ldapincludewnt
if not defined ALPINE_LDAP set ALPINE_LDAP=%cd%\ldap
if exist "%ALPINE_LDAP%" goto yesldapwnt
echo NOT including LDAP functionality
set ldapinclude=
set ldaplibes=
goto noldapwnt
:yesldapwnt
echo including LDAP functionality
set ldapflags=-I\"%ALPINE_LDAP%\"\inckit -DENABLE_LDAP
set ldaplibes=\"%ALPINE_LDAP%\"\binaries\release\ldap32.lib
:noldapwnt
set extracflagsnq=/DWINVER=0x0501 /Zi -Od %ldapflags% %libresslflags% -D_USE_32BIT_TIME_T -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE -DSPCL_REMARKS=\"\\\"\\\"\"
set extralibes="%libresslextralibes%"
set extralibesalpine="%ldaplibes% %libressllibes%"
set extrarcflags="/D_PCP_WNT"
set extramakecommand=
goto buildsetup

:w2k
echo Krb5ized PC-Alpine for Windows/Winsock (Win32) build sequence
set cclntmake=makefile.w2k
set alpinemake=makefile.wnt
if not defined ALPINE_LIBRESSL set ALPINE_LIBRESSL=%cd%\libressl
if exist "%ALPINE_LIBRESSL%" goto yeslibresslw2k
echo NOT including LIBRESSL functionality
set libresslflags=
set libressllibes=
set libresslextralibes="crypt32.lib"
goto ldapincludew2k
:yeslibresslw2k
set libresslflags=-I\"%ALPINE_LIBRESSL%\"\include -DENABLE_WINDOWS_LIBRESSL  -DLIBRESSL_INTERNAL
set libressllibes=\"%ALPINE_LIBRESSL%\"\x86\libcrypto-41.lib \"%ALPINE_LIBRESSL%\"\x86\libssl-43.lib \"%ALPINE_LIBRESSL%\"\x86\libtls-15.lib
set libresslextralibes=
:ldapincludew2k
if not defined ALPINE_LDAP set ALPINE_LDAP=%cd%\ldap
if exist "%ALPINE_LDAP%" goto yesldapw2k
echo NOT including LDAP functionality
set ldapinclude=
set ldaplibes=
goto noldapw2k
:yesldapw2k
echo including LDAP functionality
set ldapflags=-I\"%ALPINE_LDAP%\"\inckit -DENABLE_LDAP
set ldaplibes=\"%ALPINE_LDAP%\"\binaries\release\ldap32.lib
:noldapw2k
set extracflagsnq=/DWINVER=0x0501 /Zi -Od %ldapflags% %libresslflags% -D_USE_32BIT_TIME_T -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE -DSPCFC_WINVER=\"\\\" 2000\\\"\" -DSPCL_REMARKS=\"\\\" with krb5\\\"\"
set extralibes="secur32.lib %libresslextralibes%"
set extralibesalpine="secur32.lib crypt32.lib %ldaplibes% %libressllibes%"
set extrarcflags="/D_PCP_W2K"
set extramakecommand=
goto buildsetup

:clean
echo Sure you want to delete object, library and executable files?!?!
echo If NOT, type Ctrl-C to terminate build script NOW.  Type ENTER if you do.
pause
echo Cleaning alpine, pico, mailutil, mapi, and c-client directories
echo del *.pdb
del /Q alpine\*.pdb
del /Q c-client\*.pdb
del /Q c-client-dll\*.pdb
rem del /Q mailutil\*.pdb
rem del /Q mapi\*.pdb
del /Q pico\*.pdb
del /Q pith\*.pdb
del /Q regex\*.pdb
del /Q alpine\osdep\*.pdb
del /Q pico\osdep\*.pdb
del /Q pith\charconv\*.pdb
del /Q pith\osdep\*.pdb
echo del *.ilk
del /Q alpine\*.ilk
rem del /Q mapi\*.ilk
del /Q pico\*.ilk
del /Q pith\*.ilk
set alpinemake=makefile.wnt
set extramakecommand=clean
if NOT exist c-client goto nocclient
del /Q c-client\*
rmdir c-client
:nocclient
if NOT exist c-client-dll goto nocclientdll
del /Q c-client-dll\*
rmdir c-client-dll
:nocclientdll
set cclntmake=makefile.w2k
goto buildmailutil

:buildsetup
if not exist c-client mkdir c-client
if not defined ALPINE_IMAP set ALPINE_IMAP=imap
echo Copying imap files to c-client directory
copy /Y "%ALPINE_IMAP%"\src\c-client\* c-client\ > garbageout.txt
copy /Y "%ALPINE_IMAP%"\src\charset\* c-client\ > garbageout.txt
copy /Y "%ALPINE_IMAP%"\src\osdep\nt\* c-client\ > garbageout.txt
del garbageout.txt
rem if not exist c-client-dll mkdir c-client-dll
rem copy /Y "%ALPINE_IMAP%"\src\c-client\* c-client-dll\ > garbageout.txt
rem copy /Y "%ALPINE_IMAP%"\src\charset\* c-client-dll\ > garbageout.txt
rem copy /Y "%ALPINE_IMAP%"\src\osdep\nt\* c-client-dll\ > garbageout.txt
rem del garbageout.txt
if not exist mailutil mkdir mailutil
copy /Y "%ALPINE_IMAP%"\src\mailutil\* mailutil\ > garbageout.txt
del garbageout.txt
goto build

:build
set extraldflags="/DEBUG /DEBUGTYPE:CV"
set extracflags="%extracflagsnq%"
set extradllcflags="%extracflagsnq% /D_DLL"
goto buildcclnt

:buildcclnt
echo Building c-client...
cd c-client
nmake -nologo -f %cclntmake% EXTRACFLAGS=%extracflags% %extramakecommand%
if errorlevel 1 goto bogus
cd ..
goto buildmailutil

:buildmailutil
if exist mailutil goto yesbuildmailutil
goto nobuildmailutil
:yesbuildmailutil
echo Building mailutil
cd mailutil
nmake -nologo -f %cclntmake% EXTRACFLAGS=%extracflags% %extramakecommand%
if errorlevel 1 goto bogus
cd ..
:nobuildmailutil
goto buildpithosd

:buildpithosd
echo Building pith-osdep...
cd pith\osdep
nmake -nologo -f %alpinemake% wnt=1 EXTRACFLAGS=%extracflags% EXTRALDFLAGS=%extraldflags% EXTRALIBES=%extralibes% %extramakecommand%
if errorlevel 1 goto bogus
cd ..\..
goto buildpithcc

:buildpithcc
echo Building pith-charconv...
cd pith\charconv
nmake -nologo -f %alpinemake% wnt=1 EXTRACFLAGS=%extracflags% EXTRALDFLAGS=%extraldflags% EXTRALIBES=%extralibes% %extramakecommand%
if errorlevel 1 goto bogus
cd ..\..
goto buildpith

:buildpith
echo Building pith...
cd pith
nmake -nologo -f %alpinemake% wnt=1 EXTRACFLAGS=%extracflags% EXTRALDFLAGS=%extraldflags% EXTRALIBES=%extralibes% %extramakecommand%
if errorlevel 1 goto bogus
cd ..
goto buildregex

:buildregex
echo Building regex...
cd regex
nmake -nologo -f %alpinemake% wnt=1 EXTRACFLAGS=%extracflags% EXTRALDFLAGS=%extraldflags% EXTRALIBES=%extralibes% %extramakecommand%
if errorlevel 1 goto bogus
cd ..
goto buildpicoosd

:buildpicoosd
echo Building pico-osdep...
cd pico\osdep
nmake -nologo -f %alpinemake% wnt=1 EXTRACFLAGS=%extracflags% EXTRALDFLAGS=%extraldflags% EXTRALIBES=%extralibes% %extramakecommand%
if errorlevel 1 goto bogus
cd ..\..
goto buildpico

:buildpico
echo Building pico...
cd pico
nmake -nologo -f %alpinemake% wnt=1 EXTRACFLAGS=%extracflags% EXTRALDFLAGS=%extraldflags% EXTRALIBES=%extralibes% %extramakecommand%
if errorlevel 1 goto bogus
cd ..
goto buildalpineosd

:buildalpineosd
echo Building alpine-osdep...
cd alpine\osdep
nmake -nologo -f %alpinemake% wnt=1 EXTRACFLAGS=%extracflags% EXTRALDFLAGS=%extraldflags% EXTRALIBES=%extralibes% EXTRARCFLAGS=%extrarcflags% %extramakecommand%
if errorlevel 1 goto bogus
cd ..\..
goto buildalpine

:buildalpine
echo Building alpine...
cd alpine
nmake -nologo -f %alpinemake% wnt=1 EXTRACFLAGS=%extracflags% EXTRALDFLAGS=%extraldflags% EXTRALIBES=%extralibesalpine% EXTRARCFLAGS=%extrarcflags% %extramakecommand%
if errorlevel 1 goto bogus
cd ..
goto nobuildmapi

:buildcclntdll
if NOT exist c-client-dll goto buildmapi
echo Building c-client-dll
cd c-client-dll
nmake -nologo -f %cclntmake% EXTRACFLAGS=%extradllcflags% %extramakecommand%
if errorlevel 1 goto bogus
cd ..
goto buildmapi

:buildmapi
echo Building mapi
cd mapi
nmake -nologo -f makefile EXTRACFLAGS=%extracflags% EXTRALDFLAGS=%extraldflags% EXTRALIBES=%extralibes% %extramakecommand%
if errorlevel 1 goto bogus
cd ..

:nobuildmapi
echo Alpine build complete.
goto fini

:bogus
echo Problems building Alpine!

:fini
