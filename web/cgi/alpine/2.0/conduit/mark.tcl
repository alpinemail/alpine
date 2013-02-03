#!./tclsh
# $Id: mark.tcl 1266 2009-07-14 18:39:12Z hubert@u.washington.edu $
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

#  mark.tcl
#
#  Purpose:  CGI script generating response to xmlHttpRequest
#
#  Input:    
#            
set mark_args {
  {u	{}	""}
  {mark	{}	""}
}

# inherit global config
source ../alpine.tcl

WPEval $mark_args {
  cgi_body {
    switch -- $mark {
      false {
	set setting 0
      }
      true {
	set setting 1
      }
      default {
      }
    }

    if {[info exists setting]} {
      regsub -all {,} $u { } u
      if {[regexp {^[ 0123456789]*$} $u]} {
	foreach eu $u {
	  if {[catch {WPCmd PEMessage $eu select $setting} result]} {
	    set result "FAILURE: setting $eu to $setting : $result"
	    break
	  }
	}
      } elseif {0 == [string compare $u all]} {
	if {$setting} {
	  set setting all
	} else {
	  set setting none
	}

	if {[catch {WPCmd PEMailbox select $setting} result]} {
	  set result "FAILURE: $result"
	}
      } elseif {0 == [string compare $u searched]} {
	if {$setting} {
	  set setting searched
	} else {
	  set setting unsearched
	}

	if {[catch {WPCmd PEMailbox select $setting} result]} {
	  set result "FAILURE: $result"
	}
      }
    } else {
      set reult "FAILURE: Unknown mark value: $mark"
    }

    cgi_puts $result
  }
}
