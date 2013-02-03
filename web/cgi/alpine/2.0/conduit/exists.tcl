#!./tclsh
# $Id: exists.tcl 1266 2009-07-14 18:39:12Z hubert@u.washington.edu $
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

#  exists
#
#  Purpose:  CGI script generating response to xmlHttpRequest
#
#  Input:    
#            
set exists_args {
  {c		{}	""}
  {f		{}	""}
  {create	{}	"no"}
}

# inherit global config
source ../alpine.tcl

puts stdout "Content-type: application/json\n"

if {[catch {WPGetInputAndID sessid}]} {
  set harderr "No Session ID: $sessid"
} else {
  # grok parameters
  foreach item $exists_args {
    if {[catch {eval WPImport $item} importerr]} {
      set harderr "Cannot init session: $importerr"
      break
    }
  }
}

if {[info exists harderr]} {
  puts -nonewline stdout "{error: '$harderr'}"
} elseif {![regexp {^([0-9]+)$} $c]} {
  puts -nonewline stdout "{error: 'Missing collection ID: $c'}"
} elseif {[string length $f] <= 0} {
  puts -nonewline stdout "{error: 'Missing folder name'}"
} elseif {0 == [catch {WPCmd PEFolder exists $c $f} result]} {
  if {1 == $result} {
    puts -nonewline stdout "{exists:1}"
  } else {
    if {0 == [string compare $create yes]} {
      if {0 == [catch {WPCmd PEFolder create $c $f} result]} {
	puts -nonewline stdout "{exists:1}"
      } else {
	puts -nonewline stdout "{error: '$result'}"
      }
    } else {
      puts -nonewline stdout "{exists:0}"
    }
  }
} else {
  puts -nonewline stdout "{error: '$result'}"
}
