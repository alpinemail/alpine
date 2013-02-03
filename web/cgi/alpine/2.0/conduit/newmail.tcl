#!./tclsh
# $Id: newmail.tcl 1266 2009-07-14 18:39:12Z hubert@u.washington.edu $
# ========================================================================
# Copyright 2008 University of Washington
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# ========================================================================

#  newmail.tcl
#
#  Purpose:  CGI script generating response to xmlHttpRequest
#
#  Input:    
#            
set newmail_args {
  {reload	{}	0}
}

# inherit global config
source ../alpine.tcl


# Import data validate it and get session id
if {[catch {WPGetInputAndID sessid}]} {
  return
}

# grok parameters
foreach item $newmail_args {
  if {[catch {eval WPImport $item} errstr]} {
    WPInfoPage "Web Alpine Error" [font size=+2 $errstr] "Please close this window."
    return
  }
}

puts stdout "Content-type: application/json\n"

if {[catch {WPCmd PESession mailcheck $reload} newmail]} {
  puts -nonewline stdout "{error: '$newmail'}"
} else {
  puts -nonewline "\["
  set comma ""
  foreach nm $newmail {
    set text [lindex $nm 2]
    regsub -all {'} $text {\'} text
    puts -nonewline "${comma}\{newcount:[lindex $nm 0],uid:[lindex $nm 1],verbiage:'${text}'\}"
    set comma ","
  }

  puts -nonewline "\]"
}
