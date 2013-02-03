/* $Id: contacts.js 1266 2009-07-14 18:39:12Z hubert@u.washington.edu $
 * ========================================================================
 * Copyright 2008 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 */


function boxChecked(o){
    if(o) markOne(o);
}

function editContact(o){
    getContact({ book:o.book, index:o.index, f:function(c){ contactEditor(c,storeEditedContact); }});
    return(false);
}

function editCheckedContact(){
    var checked = contactsChecked('');
    switch (checked.length){
    case 1 :
	getContact({ book:checked[0].book, index:checked[0].index, f:function(c){ contactEditor(c,storeEditedContact); }});
	break;
    default :
	panelAlert('Choose just one contact to Edit');
    case 0 :
	break;
    }

    return(false);
}

function contactDelete(){
    var checked = contactsChecked('');
    var plural = (checked.length > 1) ? 's' : '';
    var count = (checked.length > 1) ? '<b>' + checked.length + '</b> ' : '';
    if(checked.length) panelConfirm('Are you sure you want to permanently delete the ' + count + 'selected contact' + plural + '?',{text:'Delete Forever',fn:doContactDelete});
    return false;
}

function doContactDelete(o){
    var checked = contactsChecked('');
    if(checked.length){
	var el = YAHOO.alpine.containers.contactlist;
	var elist = '';
	for(var i = 0; i < checked.length; i++){
	    if(elist.length) elist += ',';
	    elist += checked[i].book + '.' + checked[i].index;
	}
	    
	if(el && elist.length){
	    var o = {
		hdr:'on',
		sendto:'on',
		canedit:'on',
		op:'delete',
		entryList:elist
	    }

	    newContactList(el,null,gCurrentAbook,o);
	}
    }
}

function storeEditedContact(oFields){
    var el = YAHOO.alpine.containers.contactlist;
    if(el){
	var o = {
	    hdr:'on',
	    sendto:'on',
	    canedit:'on',
	    op:'change'
	}

	for(var f in oFields){
	    o[f] = oFields[f];
	}

	newContactList(el,null,gCurrentAbook,o);
    }
}

function storeNewContact(oFields){
    var el = YAHOO.alpine.containers.contactlist;
    if(el){
	var o = {
	    hdr:'on',
	    sendto:'on',
	    canedit:'on',
	    op:'add'
	}

	for(var f in oFields){
	    o[f] = oFields[f];
	}

	newContactList(el,null,gCurrentAbook,o);
    }
}

function sendToContact(){
    var checked = contactsChecked('Send Email');
    if(checked.length){
	var cUrl = 'compose?contacts=';
	var comma = '';
	for(var i = 0; i < checked.length; i++){
	    cUrl += comma + checked[i].book + '.' + checked[i].index;
	    comma = ',';
	}
	
	window.location.href = cUrl;
    }

    return(false);
}
