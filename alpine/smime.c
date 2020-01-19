#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: smime.c 1074 2008-06-04 00:08:43Z hubert@u.washington.edu $";
#endif

/*
 * ========================================================================
 * Copyright 2013-2020 Eduardo Chappa
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

/*
 *  This is based on a contribution from Jonathan Paisley
 *
 *  File:   	    smime.c
 *  Author: 	    paisleyj@dcs.gla.ac.uk
 *  Date:   	    01/2001
 */


#include "headers.h"

#ifdef SMIME

#include "../pith/charconv/utf8.h"
#include "../pith/status.h"
#include "../pith/store.h"
#include "../pith/conf.h"
#include "../pith/list.h"
#include "../pith/mailcmd.h"
#include "../pith/tempfile.h"
#include "../pith/body.h"
#include "radio.h"
#include "keymenu.h"
#include "mailcmd.h"
#include "mailview.h"
#include "conftype.h"
#include "confscroll.h"
#include "setup.h"
#include "smime.h"

/* internal prototypes */
void     format_smime_info(int pass, BODY *body, long msgno, gf_io_t pc);
void     print_separator_line(int percent, int ch, gf_io_t pc);
void     output_cert_info(X509 *cert, gf_io_t pc);
void     output_X509_NAME(X509_NAME *name, gf_io_t pc);
void     side_by_side(STORE_S *left, STORE_S *right, gf_io_t pc);
STORE_S *wrap_store(STORE_S *in, int width);
void     smime_config_init_display(struct pine *, CONF_S **, CONF_S **);
void     revert_to_saved_smime_config(struct pine *ps, SAVED_CONFIG_S *vsave);
SAVED_CONFIG_S *save_smime_config_vars(struct pine *ps);
void     free_saved_smime_config(struct pine *ps, SAVED_CONFIG_S **vsavep);
int      smime_helper_tool(struct pine *, int, CONF_S **, unsigned);
void 	 manage_certificates(struct pine *, WhichCerts);
#ifdef PASSFILE
void 	 manage_password_file_certificates(struct pine *);
#endif /* PASSFILE */
void smime_manage_certs_init (struct pine *, CONF_S **, CONF_S **, WhichCerts, int);
void smime_manage_password_file_certs_init(struct pine *, CONF_S **, CONF_S **, int, int *);
void display_certificate_information(struct pine *, X509 *, char *, WhichCerts, int num);
int  manage_certs_tool(struct pine *ps, int cmd, CONF_S **cl, unsigned flags);
int  manage_certificate_info_tool(int, MSGNO_S *, SCROLL_S *);
void smime_setup_size(char **, size_t, size_t);


/*
 * prompt the user for their passphrase 
 *  (possibly prompting with the email address in s_passphrase_emailaddr)
 */
int
smime_get_passphrase(void)
{
    int rc;
    int	flags;
    char prompt[500];
    HelpType help = NO_HELP;

    assert(ps_global->smime != NULL);
    snprintf(prompt, sizeof(prompt),
            _("Enter passphrase for <%s>: "), (ps_global->smime && ps_global->smime->passphrase_emailaddr) ? ps_global->smime->passphrase_emailaddr[0] : "unknown");

    do {
        flags = OE_PASSWD | OE_DISALLOW_HELP;
	((char *) ps_global->smime->passphrase)[0] = '\0';
        rc =  optionally_enter((char *) ps_global->smime->passphrase,
			       -FOOTER_ROWS(ps_global), 0,
			       sizeof(ps_global->smime->passphrase),
                               prompt, NULL, help, &flags);
    } while (rc!=0 && rc!=1 && rc>0);

    if(rc==0){
	if(ps_global->smime)
	  ps_global->smime->entered_passphrase = 1;
    }

    return rc;	/* better return rc and make the caller check its return value */
}

int
smime_check(BODY *body)
{
  int rv = 0;
  PKCS7 *p7 = NULL;

  if(body->type == TYPEMULTIPART){
	PART *p;
        
	for(p=body->nested.part; p && rv == 0; p=p->next)
	  rv += smime_check(&p->body);
  }
  if(rv > 0) return rv;
  if(body->sparep)
	p7 = get_body_sparep_type(body->sparep) == P7Type
		? (PKCS7 *)get_body_sparep_data(body->sparep)
		: NULL;
  if(p7 && (PKCS7_type_is_signed(p7) || PKCS7_type_is_enveloped(p7)))
    rv += 1;
  return rv;
}


void
display_smime_info(struct pine *ps, ENVELOPE *env, BODY *body)
{    
    OtherMenu what = FirstMenu;
    HANDLE_S *handles = NULL;
    SCROLL_S  scrollargs;
    STORE_S  *store = NULL;
    long  msgno;
    int	  offset = 0;

    msgno = mn_m2raw(ps->msgmap, mn_get_cur(ps->msgmap));
    store = so_get(CharStar, NULL, EDIT_ACCESS);

    while(ps->next_screen == SCREEN_FUN_NULL){

    	ClearLine(1);

	so_truncate(store, 0);
	
	view_writec_init(store, &handles, HEADER_ROWS(ps),
			 HEADER_ROWS(ps) + 
			 ps->ttyo->screen_rows - (HEADER_ROWS(ps)
						  + HEADER_ROWS(ps)));

    	gf_puts_uline("Overview", view_writec);
    	gf_puts(NEWLINE, view_writec);

	format_smime_info(1, body, msgno, view_writec);
	gf_puts(NEWLINE, view_writec);
	format_smime_info(2, body, msgno, view_writec);

	view_writec_destroy();

	ps->next_screen = SCREEN_FUN_NULL;

	memset(&scrollargs, 0, sizeof(SCROLL_S));
	scrollargs.text.text	= so_text(store);
	scrollargs.text.src	= CharStar;
	scrollargs.text.desc	= "S/MIME information";
	scrollargs.body_valid = 1;

	if(offset){		/* resize?  preserve paging! */
	    scrollargs.start.on		= Offset;
	    scrollargs.start.loc.offset = offset;
	    offset = 0L;
	}

	scrollargs.bar.title	= "S/MIME INFORMATION";
/*	scrollargs.end_scroll	= view_end_scroll; */
	scrollargs.resize_exit	= 1;
	scrollargs.help.text	= NULL;
	scrollargs.help.title	= "HELP FOR S/MIME INFORMATION VIEW";
	scrollargs.keys.menu	= &smime_info_keymenu;
	scrollargs.keys.what    = what;
	setbitmap(scrollargs.keys.bitmap);

	if(scrolltool(&scrollargs) == MC_RESIZE)
	  offset = scrollargs.start.loc.offset;
    }

    so_give(&store);
}

void
smime_info_screen(struct pine *ps)
{
    long      msgno;
    BODY     *body;
    ENVELOPE *env;
    
/*    ps->prev_screen = smime_info_screen;
    ps->next_screen = SCREEN_FUN_NULL; */

    msgno = mn_m2raw(ps->msgmap, mn_get_cur(ps->msgmap));
    
    env = mail_fetch_structure(ps->mail_stream, msgno, &body, 0);

    if(!env || !body){
	q_status_message(SM_ORDER, 0, 3,
			 _("Can't fetch body of message."));
	return;
    }

    if(smime_check(body) == 0){
      q_status_message(SM_ORDER | SM_DING, 0, 3,
			 _("Not a signed or encrypted message"));
      return;
    }

    if(mn_total_cur(ps->msgmap) > 1L){
	q_status_message(SM_ORDER | SM_DING, 0, 3,
			 _("Can only view one message's information at a time."));
	return;
    }

    display_smime_info(ps, env, body);
}


void
format_smime_info(int pass, BODY *body, long msgno, gf_io_t pc)
{
    PKCS7 *p7 = NULL;
    int    i;
    
    if(body->type == TYPEMULTIPART){
    	PART *p;    

        for(p=body->nested.part; p; p=p->next)
          format_smime_info(pass, &p->body, msgno, pc);
    }
    if(body->sparep)
       p7 = get_body_sparep_type(body->sparep) == P7Type 
		? (PKCS7 *)get_body_sparep_data(body->sparep)
		: NULL;
    if(p7){

    	if(PKCS7_type_is_signed(p7)){
            STACK_OF(X509) *signers;

    	    switch(pass){
	      case 1:
		gf_puts(_("This message was cryptographically signed."), pc);
		gf_puts(NEWLINE, pc);
		break;

	      case 2:
		signers = PKCS7_get0_signers(p7, NULL, 0);

		if(signers){

		    snprintf(tmp_20k_buf, SIZEOF_20KBUF, _("Certificate%s used for signing"),
			     plural(sk_X509_num(signers)));
		    gf_puts_uline(tmp_20k_buf, pc);
		    gf_puts(NEWLINE, pc);
		    print_separator_line(100, '-', pc);

		    for(i=0; i<sk_X509_num(signers); i++){
			X509 *x = sk_X509_value(signers, i);

			if(x){
			    output_cert_info(x, pc);
			    gf_puts(NEWLINE, pc);
			}
		    }
		}

		sk_X509_free(signers);
		break;
	    }
    	
	}
	else if(PKCS7_type_is_enveloped(p7)){
	
    	    switch(pass){
	      case 1:
		gf_puts(_("This message was encrypted."), pc);
		gf_puts(NEWLINE, pc);
		break;

	      case 2:
		if(p7->d.enveloped && p7->d.enveloped->enc_data){
		    X509_ALGOR *alg = p7->d.enveloped->enc_data->algorithm;
		    STACK_OF(PKCS7_RECIP_INFO) *ris = p7->d.enveloped->recipientinfo;
		    int found = 0;

		    gf_puts(_("The algorithm used to encrypt was "), pc);

		    if(alg){
			char *n = (char *) OBJ_nid2sn( OBJ_obj2nid(alg->algorithm));

			gf_puts(n ? n : "<unknown>", pc);

		    }
		    else
		      gf_puts("<unknown>", pc);

		    gf_puts("." NEWLINE NEWLINE, pc);

		    snprintf(tmp_20k_buf, SIZEOF_20KBUF, _("Certificate%s for decrypting"),
			     plural(sk_PKCS7_RECIP_INFO_num(ris)));
		    gf_puts_uline(tmp_20k_buf, pc);
		    gf_puts(NEWLINE, pc);
		    print_separator_line(100, '-', pc);

		    for(i=0; i<sk_PKCS7_RECIP_INFO_num(ris); i++){
			PKCS7_RECIP_INFO *ri;
			PERSONAL_CERT *pcert;

			ri = sk_PKCS7_RECIP_INFO_value(ris, i);
			if(!ri)
			  continue;

			pcert = find_certificate_matching_recip_info(ri);

			if(pcert){
			    if(found){
				print_separator_line(25, '*', pc);
				gf_puts(NEWLINE, pc);
			    }

			    found = 1;

			    output_cert_info(pcert->cert, pc);
			    gf_puts(NEWLINE, pc);

			}
		    }

		    if(!found){
			gf_puts(_("No certificate capable of decrypting could be found."), pc);
			gf_puts(NEWLINE, pc);
			gf_puts(NEWLINE, pc);
		    }
		}

		break;
	    }
	}
    }
}


void
print_separator_line(int percent, int ch, gf_io_t pc)
{
    int i, start, len;
    
    len = ps_global->ttyo->screen_cols * percent / 100;
    start = (ps_global->ttyo->screen_cols - len)/2;
    
    for(i=0; i<start; i++)
      pc(' ');

    for(i=start; i<start+len; i++)
      pc(ch);

    gf_puts(NEWLINE, pc);
}


void
output_cert_info(X509 *cert, gf_io_t pc)
{
    char    buf[256];
    STORE_S *left,*right;
    gf_io_t spc;
    int len, error;
    STACK_OF(X509) *chain;
        
    left = so_get(CharStar, NULL, EDIT_ACCESS);
    right = so_get(CharStar, NULL, EDIT_ACCESS);
    if(!(left && right))
      return;

    gf_set_so_writec(&spc, left);

    gf_puts_uline("Certificate Owner", spc);
    gf_puts(NEWLINE, spc);

    output_X509_NAME(X509_get_subject_name(cert), spc);
    gf_puts(NEWLINE, spc);

    gf_puts_uline("Serial Number", spc);
    gf_puts(NEWLINE, spc);

    {   ASN1_INTEGER *bs;
	long l;
	const char *neg;
	int i;

	bs = X509_get_serialNumber(cert);
	if (bs->length <= (int)sizeof(long)){
	   l = ASN1_INTEGER_get(bs);
           if (bs->type == V_ASN1_NEG_INTEGER){
	      l = -l;
	      neg="-";
	   }
           else
              neg="";
	   snprintf(buf, sizeof(buf), " %s%lu (%s0x%lx)", neg, l, neg, l);
	} else {
	    snprintf(buf, sizeof(buf), "%s", bs->type == V_ASN1_NEG_INTEGER ? "(Negative)" : "");
	    for (i = 0; i < bs->length; i++)
		 snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%02x%s", bs->data[i],
			i+1 == bs->length ? "" : ":");
	}
    }
    gf_puts(buf, spc);
    gf_puts(NEWLINE, spc);
    gf_puts(NEWLINE, spc);

    gf_puts_uline("Validity", spc);
    gf_puts(NEWLINE, spc);
    { BIO *mb = BIO_new(BIO_s_mem());
      char iobuf[4096];
	    
      gf_puts("Not Before: ", spc);

      (void) BIO_reset(mb);
      ASN1_UTCTIME_print(mb, X509_get0_notBefore(cert));
      (void) BIO_flush(mb);
      while((len = BIO_read(mb, iobuf, sizeof(iobuf))) > 0)
       gf_nputs(iobuf, len, spc);

      gf_puts(NEWLINE, spc);

      gf_puts("Not After:  ", spc);

      (void) BIO_reset(mb);
      ASN1_UTCTIME_print(mb, X509_get0_notAfter(cert));
      (void) BIO_flush(mb);
      while((len = BIO_read(mb, iobuf, sizeof(iobuf))) > 0)
        gf_nputs(iobuf, len, spc);
    	    
      gf_puts(NEWLINE, spc);
      gf_puts(NEWLINE, spc);
	    	    
      BIO_free(mb);
    }

    gf_clear_so_writec(left);

    gf_set_so_writec(&spc, right);

    gf_puts_uline("Issuer", spc);
    gf_puts(NEWLINE, spc);

    output_X509_NAME(X509_get_issuer_name(cert), spc);
    gf_puts(NEWLINE, spc);
    
    gf_clear_so_writec(right);
    
    side_by_side(left, right, pc);

    gf_puts_uline("SHA1 Fingerprint", pc);
    gf_puts(NEWLINE, pc);
    get_fingerprint(cert, EVP_sha1(), buf, sizeof(buf), ":");
    gf_puts(buf, pc);
    gf_puts(NEWLINE, pc);

    gf_puts_uline("MD5 Fingerprint", pc);
    gf_puts(NEWLINE, pc);
    get_fingerprint(cert, EVP_md5(), buf, sizeof(buf), ":");
    gf_puts(buf, pc);
    gf_puts(NEWLINE, pc);
    gf_puts(NEWLINE, pc);

    gf_puts_uline("Certificate Chain Information", pc);
    gf_puts(NEWLINE, pc);
    
    if((chain = get_chain_for_cert(cert, &error, &len)) != NULL){
       X509 *x;
       X509_NAME_ENTRY *e;
       int i, offset = 2;
       char space[256];
       X509_NAME *subject;

       for(i = 0; i < offset; i++) space[i] = ' ';

       for(i = -1; i < sk_X509_num(chain); i++){
	  char buf[256];

	  x = i == -1 ? cert : sk_X509_value(chain, i);

	  if(x){
	    if(i>=0){ 
	      space[offset + i + 0] = ' ';
	      space[offset + i + 1] = '\\';
	      space[offset + i + 2] = '-';
	      space[offset + i + 3] = ' ';
	      space[offset + i + 4] = '\0';
	      gf_puts(space, pc);
	    }
	    else{
	      space[offset] = '\0';
	      gf_puts(space, pc);
	    }
	    if(i >= 0)
	      gf_puts_uline("Signed by: ", pc);
	    else
	      gf_puts_uline("Issued to: ", pc);

	    subject = X509_get_subject_name(x);

	    if((e = X509_NAME_get_entry(subject, X509_NAME_entry_count(subject)-1)) != NULL){
	      X509_NAME_get_text_by_OBJ(subject, X509_NAME_ENTRY_get_object(e), buf, sizeof(buf));
	      gf_puts(buf, pc);
	      gf_puts(NEWLINE, pc);    
	    }
          }
	  else{
	    gf_puts("No certificate info found", pc);
	    gf_puts(NEWLINE, pc);
	    break;
	  }
       }
       e = X509_NAME_get_entry(X509_get_issuer_name(x),
			X509_NAME_entry_count(X509_get_issuer_name(x))-1);
       if(e){
	  X509_NAME_get_text_by_OBJ(X509_get_issuer_name(x), X509_NAME_ENTRY_get_object(e), buf, sizeof(buf));
	  space[offset + i + 0] = ' ';
	  space[offset + i + 1] = '\\';
	  space[offset + i + 2] = '-';
	  space[offset + i + 3] = ' ';
	  space[offset + i + 4] = '\0';
	  gf_puts(space, pc);
	  gf_puts_uline("Signed by: ", pc);
	  gf_puts(buf, pc);
	  gf_puts(NEWLINE, pc);    
       }
       sk_X509_pop_free(chain, X509_free);
    }
    gf_puts(NEWLINE, pc);

    so_give(&left);
    so_give(&right);
}


void
output_X509_NAME(X509_NAME *name, gf_io_t pc)
{
    int i, c;
    char buf[256];
    
    c = X509_NAME_entry_count(name);
    
    for(i=c-1; i>=0; i--){
    	X509_NAME_ENTRY *e;
	
    	e = X509_NAME_get_entry(name,i);
	if(!e)
	  continue;
	
    	X509_NAME_get_text_by_OBJ(name, X509_NAME_ENTRY_get_object(e), buf, sizeof(buf));
	
    	gf_puts(buf, pc);
	gf_puts(NEWLINE, pc);    
    }
}


/*
 * Output the contents of the given stores (left and right)
 * to the given gf_io_t.
 * The width of the terminal is inspected and two columns
 * are created to fit the stores into. They are then wrapped
 * and merged.
 */
void
side_by_side(STORE_S *left, STORE_S *right, gf_io_t pc)
{
    STORE_S *left_wrapped;
    STORE_S *right_wrapped;
    char    buf_l[256];
    char    buf_r[256];
    char    *l, *r;
    char    *b;
    int i;
    int w = ps_global->ttyo->screen_cols/2 - 1;
    
    so_seek(left, 0, 0);
    so_seek(right, 0, 0);
    
    left_wrapped = wrap_store(left, w);
    right_wrapped = wrap_store(right, w);
    
    so_seek(left_wrapped, 0, 0);
    so_seek(right_wrapped, 0, 0);

    for(;;){
    
    	l = so_fgets(left_wrapped, buf_l, sizeof(buf_l));
        r = so_fgets(right_wrapped, buf_r, sizeof(buf_r));
	if(l == NULL && r == NULL)
	  break;
    
	for(i=0, b=buf_l; i<w && *b && *b!='\r' && *b!='\n'; i++,b++){
	    pc(*b);
	    /* reduce accumulated width if an embed tag is discovered */
	    if(*b==TAG_EMBED)
	      i-=2;
	}

	if(buf_r[0]){
    	    while(i<w){
		pc(' ');
		i++;
	    }
	    pc(' ');

	    for(i=0, b=buf_r; i<w && *b && *b!='\r' && *b!='\n'; i++,b++)
	      pc(*b);
	}

	gf_puts(NEWLINE, pc);
    }
    
    so_give(&left_wrapped);
    so_give(&right_wrapped);
}

/*
 * Wrap the text in the given store to the given width.
 * A new store is created for the result.
 */
STORE_S *
wrap_store(STORE_S *in, int width)
{
    STORE_S *result;
    void  *ws;
    gf_io_t ipc,opc;
    
    if(width<10)
      width = 10;
    
    result = so_get(CharStar, NULL, EDIT_ACCESS);
    ws = gf_wrap_filter_opt(width, width, NULL, 0, 0);

    gf_filter_init();
    gf_link_filter(gf_wrap, ws);

    gf_set_so_writec(&opc, result);
    gf_set_so_readc(&ipc, in);

    gf_pipe(ipc, opc);
    
    gf_clear_so_readc(in);
    gf_clear_so_writec(result);
    
    return result;
}


void
smime_config_screen(struct pine *ps, int edit_exceptions)
{
    CONF_S	   *ctmp = NULL, *first_line = NULL;
    SAVED_CONFIG_S *vsave;
    OPT_SCREEN_S    screen;
    int             ew, readonly_warning = 0;

    dprint((9, "smime_config_screen()"));
    ps->next_screen = SCREEN_FUN_NULL;

    /* 
     * this is necessary because we need to know the correct paths
     * to configure certificates and keys, and we could get here
     * without having done that before we reach this place.
     */
    smime_reinit();

    if(ps->fix_fixed_warning)
      offer_to_fix_pinerc(ps);

    ew = edit_exceptions ? ps_global->ew_for_except_vars : Main;

    if(ps->restricted)
      readonly_warning = 1;
    else{
	PINERC_S *prc = NULL;

	switch(ew){
	  case Main:
	    prc = ps->prc;
	    break;
	  case Post:
	    prc = ps->post_prc;
	    break;
	  default:
	    break;
	}

	readonly_warning = prc ? prc->readonly : 1;
	if(prc && prc->quit_to_edit){
	    quit_to_edit_msg(prc);
	    return;
	}
    }

    smime_config_init_display(ps, &ctmp, &first_line);

    vsave = save_smime_config_vars(ps);

    memset(&screen, 0, sizeof(screen));
    screen.deferred_ro_warning = readonly_warning;
    switch(conf_scroll_screen(ps, &screen, first_line,
			      edit_exceptions ? _("SETUP S/MIME EXCEPTIONS")
					      : _("SETUP S/MIME"),
			      /* TRANSLATORS: Print something1 using something2.
				 configuration is something1 */
			      _("configuration"), 0, NULL)){
      case 0:
	break;

      case 1:
	write_pinerc(ps, ew, WRP_NONE);
	break;
    
      case 10:
	revert_to_saved_smime_config(ps, vsave);
	break;
      
      default:
	q_status_message(SM_ORDER, 7, 10,
			 _("conf_scroll_screen bad ret in smime_config"));
	break;
    }

    free_saved_smime_config(ps, &vsave);
    smime_reinit();
}


int
smime_related_var(struct pine *ps, struct variable *var)
{
    return(var == &ps->vars[V_PUBLICCERT_DIR] ||
	   var == &ps->vars[V_PUBLICCERT_CONTAINER] ||
	   var == &ps->vars[V_PRIVATEKEY_DIR] ||
	   var == &ps->vars[V_PRIVATEKEY_CONTAINER] ||
	   var == &ps->vars[V_CACERT_DIR] ||
	   var == &ps->vars[V_CACERT_CONTAINER]);
}

void
smime_config_init_display(struct pine *ps, CONF_S **ctmp, CONF_S **first_line)
{
    char            tmp[200];
    int		    i, ind, ln = 0;
    struct	    variable  *vtmp;
    CONF_S         *ctmpb;
    FEATURE_S      *feature;

    /* find longest variable name */
    for(vtmp = ps->vars; vtmp->name; vtmp++){
	if(!(smime_related_var(ps, vtmp)))
	  continue;

	if((i = utf8_width(pretty_var_name(vtmp->name))) > ln)
	  ln = i;
    }

    for(vtmp = ps->vars; vtmp->name; vtmp++){
	if(!(smime_related_var(ps, vtmp)))
	  continue;

	new_confline(ctmp)->var = vtmp;
	if(first_line && !*first_line)
	  *first_line = *ctmp;

	(*ctmp)->valoffset = ln+3;
	(*ctmp)->keymenu   = &config_text_keymenu;
	(*ctmp)->help      = config_help(vtmp - ps->vars, 0);
	(*ctmp)->tool	   = text_tool;

	utf8_snprintf(tmp, sizeof(tmp), "%-*.100w =", ln, pretty_var_name(vtmp->name));
	tmp[sizeof(tmp)-1] = '\0';

	(*ctmp)->varname  = cpystr(tmp);
	(*ctmp)->varnamep = (*ctmp);
	(*ctmp)->flags    = CF_STARTITEM;
	(*ctmp)->value    = pretty_value(ps, *ctmp);
    }


    vtmp = &ps->vars[V_FEATURE_LIST];

    new_confline(ctmp);
    ctmpb = (*ctmp);
    (*ctmp)->flags		 |= CF_NOSELECT | CF_STARTITEM;
    (*ctmp)->keymenu		  = &config_checkbox_keymenu;
    (*ctmp)->tool		  = NULL;

    /* put a nice delimiter before list */
    new_confline(ctmp)->var = NULL;
    (*ctmp)->varnamep		  = ctmpb;
    (*ctmp)->keymenu		  = &config_checkbox_keymenu;
    (*ctmp)->help		  = NO_HELP;
    (*ctmp)->tool		  = checkbox_tool;
    (*ctmp)->valoffset		  = feature_indent();
    (*ctmp)->flags		 |= CF_NOSELECT;
    (*ctmp)->value = cpystr("Set    Feature Name");

    new_confline(ctmp)->var = NULL;
    (*ctmp)->varnamep		  = ctmpb;
    (*ctmp)->keymenu		  = &config_checkbox_keymenu;
    (*ctmp)->help		  = NO_HELP;
    (*ctmp)->tool		  = checkbox_tool;
    (*ctmp)->valoffset		  = feature_indent();
    (*ctmp)->flags		 |= CF_NOSELECT;
    (*ctmp)->value = cpystr("---  ----------------------");

    ind = feature_list_index(F_DONT_DO_SMIME);
    feature = feature_list(ind);
    new_confline(ctmp)->var 	= vtmp;
    (*ctmp)->varnamep		= ctmpb;
    (*ctmp)->keymenu		= &config_checkbox_keymenu;
    (*ctmp)->help		= config_help(vtmp-ps->vars, feature->id);
    (*ctmp)->tool		= checkbox_tool;
    (*ctmp)->valoffset		= feature_indent();
    (*ctmp)->varmem		= ind;
    (*ctmp)->value		= pretty_value(ps, (*ctmp));

    ind = feature_list_index(F_ENCRYPT_DEFAULT_ON);
    feature = feature_list(ind);
    new_confline(ctmp)->var 	= vtmp;
    (*ctmp)->varnamep		= ctmpb;
    (*ctmp)->keymenu		= &config_checkbox_keymenu;
    (*ctmp)->help		= config_help(vtmp-ps->vars, feature->id);
    (*ctmp)->tool		= checkbox_tool;
    (*ctmp)->valoffset		= feature_indent();
    (*ctmp)->varmem		= ind;
    (*ctmp)->value		= pretty_value(ps, (*ctmp));

    ind = feature_list_index(F_REMEMBER_SMIME_PASSPHRASE);
    feature = feature_list(ind);
    new_confline(ctmp)->var 	= vtmp;
    (*ctmp)->varnamep		= ctmpb;
    (*ctmp)->keymenu		= &config_checkbox_keymenu;
    (*ctmp)->help		= config_help(vtmp-ps->vars, feature->id);
    (*ctmp)->tool		= checkbox_tool;
    (*ctmp)->valoffset		= feature_indent();
    (*ctmp)->varmem		= ind;
    (*ctmp)->value		= pretty_value(ps, (*ctmp));

    ind = feature_list_index(F_SIGN_DEFAULT_ON);
    feature = feature_list(ind);
    new_confline(ctmp)->var 	= vtmp;
    (*ctmp)->varnamep		= ctmpb;
    (*ctmp)->keymenu		= &config_checkbox_keymenu;
    (*ctmp)->help		= config_help(vtmp-ps->vars, feature->id);
    (*ctmp)->tool		= checkbox_tool;
    (*ctmp)->valoffset		= feature_indent();
    (*ctmp)->varmem		= ind;
    (*ctmp)->value		= pretty_value(ps, (*ctmp));

    ind = feature_list_index(F_USE_CERT_STORE_ONLY);
    feature = feature_list(ind);
    new_confline(ctmp)->var 	= vtmp;
    (*ctmp)->varnamep		= ctmpb;
    (*ctmp)->keymenu		= &config_checkbox_keymenu;
    (*ctmp)->help		= config_help(vtmp-ps->vars, feature->id);
    (*ctmp)->tool		= checkbox_tool;
    (*ctmp)->valoffset		= feature_indent();
    (*ctmp)->varmem		= ind;
    (*ctmp)->value		= pretty_value(ps, (*ctmp));

#ifdef APPLEKEYCHAIN
    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(_("Mac OS X specific features"));

    ind = feature_list_index(F_PUBLICCERTS_IN_KEYCHAIN);
    feature = feature_list(ind);
    new_confline(ctmp)->var 	= vtmp;
    (*ctmp)->varnamep		= ctmpb;
    (*ctmp)->keymenu		= &config_checkbox_keymenu;
    (*ctmp)->help		= config_help(vtmp-ps->vars, feature->id);
    (*ctmp)->tool		= checkbox_tool;
    (*ctmp)->valoffset		= feature_indent();
    (*ctmp)->varmem		= ind;
    (*ctmp)->value		= pretty_value(ps, (*ctmp));
#endif /* APPLEKEYCHAIN */

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    for(i = 0; i < sizeof(tmp) && i < (ps->ttyo ? ps->ttyo->screen_cols : sizeof(tmp)); i++)
	tmp[i] = '-';
    tmp[i] = '\0';
    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(tmp);

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(_("Be careful with the following commands, they REPLACE contents in the target"));

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(tmp);

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    /* copy public directory to container */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_helper_keymenu;
    (*ctmp)->help           = h_config_smime_transfer_pub_to_con;
    (*ctmp)->value          = cpystr(_("Transfer public certs FROM directory TO container"));
    (*ctmp)->varmem         = 1;

    /* copy private directory to container */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_helper_keymenu;
    (*ctmp)->help           = h_config_smime_transfer_priv_to_con;
    (*ctmp)->value          = cpystr(_("Transfer private keys FROM directory TO container"));
    (*ctmp)->varmem         = 3;

    /* copy cacert directory to container */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_helper_keymenu;
    (*ctmp)->help           = h_config_smime_transfer_cacert_to_con;
    (*ctmp)->value          = cpystr(_("Transfer CA certs FROM directory TO container"));
    (*ctmp)->varmem         = 5;

    new_confline(ctmp)->var = vtmp;
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    /* copy public container to directory */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_helper_keymenu;
    (*ctmp)->help           = h_config_smime_transfer_pub_to_dir;
    (*ctmp)->value          = cpystr(_("Transfer public certs FROM container TO directory"));
    (*ctmp)->varmem         = 2;

    /* copy private container to directory */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_helper_keymenu;
    (*ctmp)->help           = h_config_smime_transfer_priv_to_dir;
    (*ctmp)->value          = cpystr(_("Transfer private keys FROM container TO directory"));
    (*ctmp)->varmem         = 4;

    /* copy cacert container to directory */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_helper_keymenu;
    (*ctmp)->help           = h_config_smime_transfer_cacert_to_dir;
    (*ctmp)->value          = cpystr(_("Transfer CA certs FROM container TO directory"));
    (*ctmp)->varmem         = 6;

#ifdef APPLEKEYCHAIN

    new_confline(ctmp)->var = vtmp;
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    /* copy public container to keychain */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_helper_keymenu;
    (*ctmp)->help           = h_config_smime_transfer_pubcon_to_key;
    (*ctmp)->value          = cpystr(_("Transfer public certs FROM container TO keychain"));
    (*ctmp)->varmem         = 7;

    /* copy public keychain to container */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_helper_keymenu;
    (*ctmp)->help           = h_config_smime_transfer_pubkey_to_con;
    (*ctmp)->value          = cpystr(_("Transfer public certs FROM keychain TO container"));
    (*ctmp)->varmem         = 8;

#endif /* APPLEKEYCHAIN */

    if(ps_global->smime
	&& SMHOLDERTYPE(Private) == Keychain
	&& SMHOLDERTYPE(Public) == Keychain
	&& SMHOLDERTYPE(CACert) == Keychain)
	return;

    new_confline(ctmp)->var = vtmp;
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(tmp);

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(_("Manage your own certificates"));

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(tmp);

    new_confline(ctmp)->var = vtmp;
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    /* manage public certificates */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_manage_certs_menu_keymenu;
    (*ctmp)->help           = h_config_smime_public_certificates;
    (*ctmp)->value          = cpystr(_("Manage Public Certificates"));
    (*ctmp)->varmem         = 9;
    (*ctmp)->d.s.ctype	    = Public;

    /* manage private keys */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_manage_certs_menu_keymenu;
    (*ctmp)->help           = h_config_smime_private_keys;
    (*ctmp)->value          = cpystr(_("Manage Private Keys"));
    (*ctmp)->varmem         = 10;
    (*ctmp)->d.s.ctype	    = Private;

    /* manage Certificate Authorities */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_manage_certs_menu_keymenu;
    (*ctmp)->help           = h_config_smime_certificate_authorities;
    (*ctmp)->value          = cpystr(_("Manage Certificate Authorities"));
    (*ctmp)->varmem         = 11;
    (*ctmp)->d.s.ctype	    = CACert;

#ifdef PASSFILE
    new_confline(ctmp)->var = vtmp;
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(tmp);

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(_("Manage Key and Certificate for Password File"));

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(tmp);

    new_confline(ctmp)->var = vtmp;
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    /* manage password file certificates */
    new_confline(ctmp);
    (*ctmp)->tool           = smime_helper_tool;
    (*ctmp)->keymenu        = &config_smime_manage_password_file_menu_keymenu;
    (*ctmp)->help           = h_config_smime_password_file_certificates;
    (*ctmp)->value          = cpystr(_("Manage Password File Key and Certificate"));
    (*ctmp)->varmem         = 12;
    (*ctmp)->d.s.ctype	    = Password;
#endif /* PASSFILE */

    (*ctmp)->next	    = NULL;
}

void
display_certificate_information(struct pine *ps, X509 *cert, char *email, WhichCerts ctype, int num)
{
    STORE_S  *store;
    SCROLL_S  scrollargs;
    int cmd, offset;
    int pub_cert, priv_cert, new_store;
    long error;
    BIO *out = NULL;

    cmd = offset = pub_cert = priv_cert = 0;
    new_store = 1;
    ps->next_screen = SCREEN_FUN_NULL;
    do {
      /* MC_PRIVATE and MC_PUBLIC cancel each other, 
       * they can not be active at the same time
       */
      switch(cmd){
	case MC_PRIVATE:
	   pub_cert = 0;
	   priv_cert = 1 - priv_cert;
	   smime_certificate_info_keymenu.keys[PUBLIC_KEY].label  = N_("Public Key");
	   smime_certificate_info_keymenu.keys[PRIVATE_KEY].label = priv_cert ? N_("No Priv Key") : N_("Pivate Key");
	   break;

	case MC_PUBLIC:
	   priv_cert = 0;
	   pub_cert = 1 - pub_cert;
	   smime_certificate_info_keymenu.keys[PRIVATE_KEY].label = priv_cert ? N_("No Priv Key") : N_("Pivate Key");
	   smime_certificate_info_keymenu.keys[PUBLIC_KEY].label  = N_("Public Key");
	   break;

	case MC_TRUST:
	   if(SMHOLDERTYPE(CACert) == Directory)
	      save_cert_for(email, cert, CACert);
	   else{ /* if(SMHOLDERTYPE(CACert) == Container) */
	      char  path[MAXPATH];
	      char  *upath = PATHCERTDIR(ctype);
	      char *tempfile = tempfile_in_same_dir(path, "az", NULL);
	      CertList *clist;

	      if(IS_REMOTE(upath))
		strncpy(path, temp_nam(NULL, "a6"), sizeof(path)-1);
	      else
		strncpy(path, upath, sizeof(path)-1);
	      path[sizeof(path)-1] = '\0';

	      add_to_end_of_certlist(&ps_global->smime->cacertlist, email, X509_dup(cert));
	      for(clist=ps_global->smime->cacertlist; clist && clist->next; clist = clist->next);
	      certlist_to_file(tempfile, clist);
	      add_file_to_container(CACert, tempfile, email);
	      unlink(tempfile);
	   }
	   renew_store();
	   new_store = 1;
	   break;

	case MC_DELETE:
	   if (get_cert_deleted(ctype, num) != 0)
	      q_status_message(SM_ORDER, 1, 3, _("Certificate already deleted"));
	   else{
	      mark_cert_deleted(ctype, num, 1);
	      q_status_message(SM_ORDER, 1, 3, _("Certificate marked deleted"));
	   }
	   break;

	case MC_UNDELETE:
	   if (get_cert_deleted(ctype, num) != 0){
	      mark_cert_deleted(ctype, num, 0);
	      q_status_message(SM_ORDER, 1, 3, _("Certificate marked UNdeleted"));
	   }
	   else
	      q_status_message(SM_ORDER, 1, 3, _("Certificate not marked deleted"));
	   break;

	default: break;
      }

      if((pub_cert || priv_cert) 
	&& (out = print_private_key_information(email, priv_cert)) == NULL)
	  q_status_message(SM_ORDER, 1, 3, _("Problem Reading Private Certificate Information"));

      if(new_store){
	store = so_get(CharStar, NULL, EDIT_ACCESS);
	view_writec_init(store, NULL, HEADER_ROWS(ps),
        	HEADER_ROWS(ps) + ps->ttyo->screen_rows - (HEADER_ROWS(ps)+ FOOTER_ROWS(ps)));

	snprintf(tmp_20k_buf, SIZEOF_20KBUF,"%s",  _("Certificate Information"));
	gf_puts_uline(tmp_20k_buf, view_writec);
	gf_puts(NEWLINE, view_writec);
	print_separator_line(100, '-', view_writec);

	output_cert_info(cert, view_writec);
	gf_puts(NEWLINE, view_writec);

	if(smime_validate_cert(cert, &error) < 0){
	  const char *errorp = X509_verify_cert_error_string(error);
	  snprintf(tmp_20k_buf, SIZEOF_20KBUF,_("Error validating certificate: %s"), errorp);
        } else
	  snprintf(tmp_20k_buf, SIZEOF_20KBUF, "%s", _("Certificate validated without errors"));

	gf_puts_uline(tmp_20k_buf, view_writec);
	gf_puts(NEWLINE, view_writec);

	if(out != NULL){	/* print private key information */
	  unsigned char ch[2];

	  gf_puts(NEWLINE, view_writec);
	  ch[1] = '\0';
	  while(BIO_read(out, ch, 1) >= 1)
	    gf_puts((char *)ch, view_writec); 
	  gf_puts(NEWLINE, view_writec);
	  q_status_message1(SM_ORDER, 1, 3, _("%s information shown at bottom of certificate information"), pub_cert ? _("Public") : _("Private"));
	  BIO_free_all(out);
	  out = NULL;
	}
	view_writec_destroy();
	new_store = 0;
      }

      memset(&scrollargs, 0, sizeof(SCROLL_S));
		      
      scrollargs.text.text  = so_text(store);
      scrollargs.text.src   = CharStar;
      scrollargs.text.desc  = "certificate information";
      scrollargs.body_valid = 1;

      if(offset){             /* resize?  preserve paging! */
	scrollargs.start.on         = Offset;
	scrollargs.start.loc.offset = offset;
	scrollargs.body_valid = 0;
	offset = 0L;
      }

      scrollargs.use_indexline_color = 1;

      scrollargs.bar.title   = _("CERTIFICATE INFORMATION");
      scrollargs.proc.tool   = manage_certificate_info_tool;
      scrollargs.resize_exit = 1;
      scrollargs.help.text   = h_certificate_information;
      scrollargs.help.title  = _("HELP FOR MESSAGE TEXT VIEW");
      scrollargs.keys.what   = FirstMenu;
      scrollargs.keys.menu   = &smime_certificate_info_keymenu;
      setbitmap(scrollargs.keys.bitmap);
      if(ctype != Public || error != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
/*error != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)*/
	  clrbitn(TRUST_KEY, scrollargs.keys.bitmap);
      if(ctype != Private){
	  clrbitn(PUBLIC_KEY,  scrollargs.keys.bitmap);
	  clrbitn(PRIVATE_KEY, scrollargs.keys.bitmap);
      }
      if(ctype == Password){
	  clrbitn(DELETE_CERT_KEY,  scrollargs.keys.bitmap);
	  clrbitn(UNDELETE_CERT_KEY,  scrollargs.keys.bitmap);
      }

      cmd = scrolltool(&scrollargs);

      switch(cmd){
	case MC_RESIZE : 
	case MC_PRIVATE:
	case MC_PUBLIC : if(scrollargs.start.on == Offset)
			   offset = scrollargs.start.loc.offset;
			 new_store = 1;
		default: break;
      }
      if(new_store)
	so_give(&store);
   } while (cmd != MC_EXIT);
   ps->mangled_screen = 1;
}

/* 
 * This is silly, we just need this function so that we can tell scrolltool
 * that some commands are recognized. We use scrolltool because we do not
 * want to rewrite output_cert_info.
 */
int
manage_certificate_info_tool(int cmd, MSGNO_S *msgmap, SCROLL_S *sparms)
{
  int rv;
  switch(cmd){
     case MC_DELETE:
     case MC_UNDELETE:
     case MC_PRIVATE:
     case MC_PUBLIC:
     case MC_TRUST: rv = 1; break;
	default: rv = 0; break;
  }
  return rv;
}


int
manage_certs_tool(struct pine *ps, int cmd, CONF_S **cl, unsigned flags)
{
    int rv = 0;
    X509 *cert = NULL;
    WhichCerts ctype = (*cl)->d.s.ctype;

    switch(cmd){
      case MC_ADD:	/* create a self signed certificate and import it */
	   if(ctype == Password){
	      PERSONAL_CERT *pc;
	      char pathdir[MAXPATH+1], filename[MAXPATH+1];
	      struct stat sbuf;
	      int st;
	      smime_path(DF_SMIMETMPDIR, pathdir, sizeof(pathdir));   
	      if(((st = our_stat(pathdir, &sbuf)) == 0
		   && (sbuf.st_mode & S_IFMT) == S_IFDIR)
		 || (st != 0
		     && can_access(pathdir, ACCESS_EXISTS) != 0
	             && our_mkpath(pathdir, 0700) == 0)){
	        pc = ALPINE_self_signed_certificate(NULL, 0, pathdir, MASTERNAME);
		snprintf(filename, sizeof(filename), "%s/%s.key", 
					pathdir, MASTERNAME);
		filename[sizeof(filename)-1] = '\0';
		rv = import_certificate(ctype, pc, filename);
		if(rv == 1){
		  ps->keyemptypwd = 0;
		  if(our_stat(pathdir, &sbuf) == 0){
		    if(unlink(filename) < 0)
		      q_status_message1(SM_ORDER, 0, 2, 
			_("Could not remove private key %s.key"), MASTERNAME);
		    filename[strlen(filename)-4] = '\0';
		    strcat(filename, ".crt");
		    if(unlink(filename) < 0)
		      q_status_message1(SM_ORDER, 0, 2, 
			_("Could not remove public certificate %s.crt"), MASTERNAME);
		    if(rmdir(pathdir) < 0)
		      q_status_message1(SM_ORDER, 0, 2, 
		      _("Could not remove temporary directory %s"), pathdir);
		  }
		}
	      }
	      rv = 10;		/* forces redraw */
	   }
	   break;

      case MC_CHOICE:
	   if(PATHCERTDIR(ctype) == NULL)
	     return 0;
	   
	   if((cert = get_cert_for((*cl)->d.s.address, ctype, 0)) == NULL){
	      q_status_message(SM_ORDER, 1, 3, _("Problem Reading Certificate"));
	      rv = 0;
	   }
	   else{
	      display_certificate_information(ps, cert, (*cl)->d.s.address, ctype, (*cl)->varmem);
	      rv = 10 + (*cl)->varmem;
	   }
	   break;

      case MC_DELETE:
	   if(ctype == Password){
	      EVP_PKEY *key = NULL;
	      PERSONAL_CERT *pc =  (PERSONAL_CERT *) ps->pwdcert;
	      RSA *rsa = NULL;
	      const EVP_CIPHER *enc = NULL;
	      BIO *out = NULL;
	      BIO *in = NULL;
	      char filename[MAXPATH+1];
	      char passwd[MAILTMPLEN];
	      char prompt[MAILTMPLEN];

	      if (pc != NULL && pc->key != NULL){
		  strncpy(prompt, _("Enter password to unlock key: "), sizeof(prompt));
		  prompt[sizeof(prompt)-1] = '\0';
		  passwd[0] = '\0';

		  rv = alpine_get_password(prompt, passwd, sizeof(passwd));

		  if(rv == 1)
		     q_status_message(SM_ORDER, 1, 3, _("Password deletion cancelled"));
		  else if(rv == 0){
		     snprintf(filename, sizeof(filename), "%s/%s.key", ps->pwdcertdir, pc->name);
		     filename[sizeof(filename)-1] = '\0';
		     if((in = BIO_new_file(filename, "r")) != NULL){
			key = PEM_read_bio_PrivateKey(in, NULL, NULL, passwd);
			if(key != NULL){
			  if((rsa = EVP_PKEY_get1_RSA(key)) != NULL
			     && (out = BIO_new(BIO_s_file())) != NULL
			     && BIO_write_filename(out, filename) > 0
			     && PEM_write_bio_RSAPrivateKey(out, rsa, enc, NULL, 0, NULL, passwd) > 0){
			     q_status_message(SM_ORDER, 1, 3, _("Password Removed from private key"));
			     ps->keyemptypwd = 1;
			  }
			  else
			     rv = 1;
			}
			else{
			  rv = 1;
			  q_status_message(SM_ORDER, 1, 3, _("Failed to unlock private key"));
			}
			BIO_free(in);
		     }
		     else
			rv = 1;
		  }
		  if(rv == 1)
		     q_status_message(SM_ORDER, 1, 3, _("Failed to remove password from private key"));
		  rv += 10;		/* forces redraw */
		  if(out != NULL)
		    BIO_free_all(out);
		  if(rsa != NULL)
		    RSA_free(rsa);
		  if(key != NULL)
		    EVP_PKEY_free(key);
	      }
	   }
	   else {
	      if ((*cl)->d.s.deleted != 0)
	         q_status_message(SM_ORDER, 1, 3, _("Certificate already deleted"));
	      else{
	         (*cl)->d.s.deleted = 1;
	         rv = 10 + (*cl)->varmem;		/* forces redraw */
	         mark_cert_deleted(ctype, (*cl)->varmem, 1);
	         q_status_message(SM_ORDER, 1, 3, _("Certificate marked deleted"));
	      }
	   }
	   break;

      case MC_UNDELETE:
	   if ((*cl)->d.s.deleted == 0)
	      q_status_message(SM_ORDER, 1, 3, _("Certificate not marked deleted"));
	   else{
	      (*cl)->d.s.deleted = 0;
	      mark_cert_deleted(ctype, (*cl)->varmem, 0);
	      rv = 10 + (*cl)->varmem;		/* forces redraw */
	      q_status_message(SM_ORDER, 1, 3, _("Certificate marked UNdeleted"));
	   }
	   break;

      case MC_EXPUNGE:
	{ CertList *cl;

	  for(cl = DATACERT(ctype); cl != NULL && DELETEDCERT(cl) == 0; cl = cl->next);
	  if(cl != NULL && DELETEDCERT(cl) != 0){
	    smime_expunge_cert(ctype);
	    rv = 10;		/* forces redraw */
	  }
	  else{
	    q_status_message(SM_ORDER, 3, 3, _("No certificates marked deleted"));
	    rv = 0;
	  }
	  break;
	}
      case MC_IMPORT: 
	rv = import_certificate(ctype, NULL, NULL);
	if(rv < 0){
	  switch(rv){
	    default:
	    case -1:
	       cmd_cancelled("Import certificate");
	    break;
 
	    case -2:
	      q_status_message1(SM_ORDER, 0, 2, _("Can't import certificate outside of %s"),
				ps_global->VAR_OPER_DIR);
	    break;
	  }
	}
	rv = 10;	/* forces redraw */
	break;

      case MC_EXIT:
	rv = config_exit_cmd(flags);
	break;

      default:
	rv = -1;
	break;
    }

    X509_free(cert);
    return rv;
}

void
smime_setup_size(char **s, size_t buflen, size_t n)
{
   char *t = *s;
  *t++ = ' ';
  *t++ = '%';
  *t++ = '-';
   snprintf(t, buflen-3, "%zu.%zu", n, n);
   t += strlen(t);
   *t++ = 's';
   *t = '\0';
   *s = t;
}

#ifdef PASSFILE
void
manage_password_file_certificates(struct pine *ps)
{
    OPT_SCREEN_S    screen;
    int             readonly_warning = 0, rv = 10, fline, state = 0;

    dprint((9, "manage_password_file_certificates"));
    ps->next_screen = SCREEN_FUN_NULL;
    ps->keyemptypwd = 0;	/* just in case */

    do {
      CONF_S *ctmp = NULL, *first_line = NULL;

      fline = rv >= 10 ? rv - 10 : 0;

      smime_manage_password_file_certs_init(ps, &ctmp, &first_line, fline, &state);

      if(ctmp == NULL){
	ps->mangled_screen = 1;
	q_status_message(SM_ORDER, 1, 3, _("Failed to initialize password management screen (no key)"));
        return;
      }

      memset(&screen, 0, sizeof(screen));
      screen.deferred_ro_warning = readonly_warning;

      rv = conf_scroll_screen(ps, &screen, first_line,
			       _("MANAGE PASSWORD FILE CERTS"),
			      /* TRANSLATORS: Print something1 using something2.
				 configuration is something1 */
			      _("configuration"), 0, NULL);
    } while (rv != 0);

    ps->mangled_screen = 1;
    ps->keyemptypwd = 0;	/* reset this so it will not confuse other routines */
    smime_reinit();
}

 /* state: 0 = first time, 
  *        1 = second or another time
  */
void 
smime_manage_password_file_certs_init(struct pine *ps, CONF_S **ctmp, CONF_S **first_line, int fline, int *state)
{
    char     tmp[200];
    char    *ext;
    CertList *cl;
    int	  i;
    void  *pwdcert = NULL;	/* this is our current password file */
    X509_LOOKUP *lookup = NULL;
    X509_STORE  *store  = NULL;
    char filename[MAXPATH+1];
    BIO *in = NULL;
    EVP_PKEY *key = NULL;
    PERSONAL_CERT *pc;

    if(*state == 0){		/* first time around? */
      setup_pwdcert(&pwdcert);
      if(pwdcert == NULL) return;
      if(ps->pwdcert == NULL)
         ps->pwdcert = pwdcert;
      else
         free_personal_certs((PERSONAL_CERT **) &pwdcert);
      (*state)++;
    }

    pc = (PERSONAL_CERT *) ps_global->pwdcert;
    snprintf(filename, sizeof(filename), "%s/%s.key", ps->pwdcertdir, pc->name);
    filename[sizeof(filename)-1] = '\0';
    if((in = BIO_new_file(filename, "r")) != NULL
	&& (key = PEM_read_bio_PrivateKey(in, NULL, NULL, "")) != NULL)
	ps->keyemptypwd = 1;
    if(in != NULL)
	BIO_free(in);
    if(key != NULL)
	EVP_PKEY_free(key);

    ps->pwdcertlist = cl = smime_X509_to_cert_info(X509_dup(pc->cert), pc->name);

    for(i = 0; i < sizeof(tmp) && i < (ps->ttyo ? ps->ttyo->screen_cols : sizeof(tmp)); i++)
	tmp[i] = '-';
    tmp[i] = '\0';

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(tmp);

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(_("Manage Certificates and Keys Used to Encrypt your Password File"));

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(tmp);

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    if(cl){
      int s, e, df, dt, md5;	/* sizes of certain fields */
      int nf;			/* number of fields */
      char u[MAILTMPLEN], *t;

      e = MIN(strlen(cl->name), ps->ttyo->screen_cols/3);	/* do not use too much screen */
      nf = 5;		/* there are 5 fields */
      s = 3;		/* status has fixed size */
      df = dt = 10;	/* date from and date to have fixed size */
      md5 = ps->ttyo->screen_cols - s - df - dt - e - (nf - 1);

      t = u;
      smime_setup_size(&t, sizeof(u), s);
      smime_setup_size(&t, sizeof(u) - strlen(t), e);
      smime_setup_size(&t, sizeof(u) - strlen(t), df);
      *t++ = ' ';	/* leave an extra space between dates */
      *t = '\0';	/* make valgrind happy */
      smime_setup_size(&t, sizeof(u) - strlen(t), dt);
      *t++ = ' ';	/* and another space between date and md5 sum */
      *t = '\0';	/* make valgrind happy again */
      smime_setup_size(&t, sizeof(u) - strlen(t), md5);
      *t = '\0';	/* tie off */

      new_confline(ctmp);
      (*ctmp)->flags |= CF_NOSELECT;
      (*ctmp)->value = cpystr(_("New Public Certificate and Key:"));

      new_confline(ctmp);
      (*ctmp)->d.s.ctype  = Password;
      (*ctmp)->help	  = h_config_smime_password_file_certificates;
      (*ctmp)->tool       = manage_certs_tool;
      (*ctmp)->keymenu    = &config_smime_add_new_key_keymenu;
      s += 2;
      for(i = 0; i < s; i++) tmp[i] = ' ';
      tmp[i] = '\0';
      strncpy(tmp+s, _("Press \"RETURN\" to add new personal key"), sizeof(tmp)-s-1);
      for(i = strlen(tmp); i < (ps->ttyo ? ps->ttyo->screen_cols : sizeof(tmp) - 1); i++)
         tmp[i] = ' ';
      tmp[i] = '\0';
      (*ctmp)->value      = cpystr(tmp);
      *first_line = *ctmp;

      new_confline(ctmp);
      (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

      new_confline(ctmp);
      (*ctmp)->flags |= CF_NOSELECT;
      (*ctmp)->value = cpystr(_("Current Public Certificate and Key:"));

      new_confline(ctmp);
      (*ctmp)->d.s.ctype   = Password;
      (*ctmp)->d.s.deleted = 0;
      (*ctmp)->help	   = h_config_smime_password_file_certificates;
      (*ctmp)->tool        = manage_certs_tool;
      (*ctmp)->keymenu     = ps->keyemptypwd == 0
			     ? &config_smime_manage_view_cert_keymenu
			     : &config_smime_manage_view_cert_keymenu_no_delete;
      (*ctmp)->varmem      = 0;
      strncpy((*ctmp)->d.s.address, cl->name, sizeof((*ctmp)->d.s.address));
      (*ctmp)->d.s.address[sizeof((*ctmp)->d.s.address) - 1] = '\0';
      snprintf(tmp, sizeof(tmp), u,
			(*ctmp)->d.s.deleted ? "D" : " ", 
			cl->name, 
			DATEFROMCERT(cl), DATETOCERT(cl), MD5CERT(cl));
      (*ctmp)->value      = cpystr(tmp);
    }
}
#endif /* PASSFILE */


void
smime_manage_certs_init(struct pine *ps, CONF_S **ctmp, CONF_S **first_line, WhichCerts ctype, int fline)
{
    char            tmp[200];
    char	   *ext;
    CertList	   *data;
    int		    i;

    smime_init();

    data = DATACERT(ctype);
    ext  = EXTCERT(ctype);

    if(data == NULL || RENEWCERT(data))
      renew_cert_data(&data, ctype);

    for(i = 0; i < sizeof(tmp) && i < (ps->ttyo ? ps->ttyo->screen_cols : sizeof(tmp)); i++)
	tmp[i] = '-';
    tmp[i] = '\0';

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(tmp);

    (*ctmp)->keymenu   = &config_text_keymenu;

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    sprintf(tmp, _("List of %s certificates"), ctype == Public ? _("public")
		: (ctype == Private ? _("private") 
		: (ctype == CACert ? _("certificate authority") : "unknown (?)")));
    (*ctmp)->value = cpystr(tmp);

    for(i = 0; i < sizeof(tmp) && i < (ps->ttyo ? ps->ttyo->screen_cols : sizeof(tmp)); i++)
       tmp[i] = '-';
    tmp[i] = '\0';

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT;
    (*ctmp)->value = cpystr(tmp);

    new_confline(ctmp);
    (*ctmp)->flags |= CF_NOSELECT | CF_B_LINE;

    if(data){
      CertList *cl; int i;
      int s, e, df, dt, md5;	/* sizes of certain fields */
      int nf;			/* number of fields */
      char u[MAILTMPLEN], *t;

      for(cl = data, e = 0; cl; cl = cl->next)
	 if(cl->name && strlen(cl->name) > e)
	   e = strlen(cl->name);

      if(ctype != Private && SMHOLDERTYPE(ctype) == Directory)
	e -= 4;		/* remove extension length */
      e = MIN(e, ps->ttyo->screen_cols/3);	/* do not use too much screen */
      nf = 5;		/* there are 5 fields */
      s = 3;		/* status has fixed size */
      df = dt = 10;	/* date from and date to have fixed size */
      md5 = ps->ttyo->screen_cols - s - df - dt - e - (nf - 1);

      t = u;
      smime_setup_size(&t, sizeof(u), s);
      smime_setup_size(&t, sizeof(u) - strlen(t), e);
      smime_setup_size(&t, sizeof(u) - strlen(t), df);
      *t++ = ' ';	/* leave an extra space between dates */
      *t = '\0';	/* make valgrind happy */
      smime_setup_size(&t, sizeof(u) - strlen(t), dt);
      *t++ = ' ';	/* and another space between date and md5 sum */
      *t = '\0';	/* make valgrind happy again */
      smime_setup_size(&t, sizeof(u) - strlen(t), md5);
      *t = '\0';	/* tie off */

      for(cl = data, i = 0; cl; cl = cl->next)
	 if(cl->name){
	    char *s, *t;

	    new_confline(ctmp);
	    (*ctmp)->d.s.ctype  = ctype;
	    (*ctmp)->d.s.deleted = get_cert_deleted(ctype, i);
	    (*ctmp)->tool       = manage_certs_tool;
	    (*ctmp)->keymenu    = &config_smime_manage_certs_work_keymenu;
	    (*ctmp)->varmem     = i++;
	    (*ctmp)->help	= ctype == Public ? h_config_smime_manage_public_menu
					: (ctype == Private ? h_config_smime_manage_private_menu
							   : h_config_smime_manage_cacerts_menu);
	    if(ctype != Private && SMHOLDERTYPE(ctype) == Directory)
	       cl->name[strlen(cl->name) - 4] = '\0';	 /* FIX FIX FIX */
	    strncpy((*ctmp)->d.s.address, cl->name, sizeof((*ctmp)->d.s.address));
	    (*ctmp)->d.s.address[sizeof((*ctmp)->d.s.address) - 1] = '\0';
	    snprintf(tmp, sizeof(tmp), u,
			(*ctmp)->d.s.deleted ? "D" : " ", 
			ctype == CACert ? cl->cn : cl->name, 
			DATEFROMCERT(cl), DATETOCERT(cl), MD5CERT(cl));
	    if(ctype != Private && SMHOLDERTYPE(ctype) == Directory)
	       cl->name[strlen(cl->name)] = '.';
	    (*ctmp)->value      = cpystr(tmp);
	    if(i == fline+1 && first_line && !*first_line)
	       *first_line = *ctmp;
	 }
    }
    else {
       new_confline(ctmp);
       (*ctmp)->d.s.ctype  = ctype;
       (*ctmp)->tool       = manage_certs_tool;
       (*ctmp)->keymenu    = &config_smime_add_certs_keymenu;
       (*ctmp)->value      = cpystr(_("  \tNo certificates found, press \"RETURN\" to add one."));
       if(first_line && !*first_line)
	 *first_line = *ctmp;
    }
}

void
manage_certificates(struct pine *ps, WhichCerts ctype)
{
    OPT_SCREEN_S    screen;
    int             readonly_warning = 0, rv = 10, fline;

    dprint((9, "manage_certificates(ps, %s)", ctype == Public ? _("Public") : (ctype == Private ? _("Private") : (ctype == CACert ? _("certificate authority") : _("unknown")))));
    ps->next_screen = SCREEN_FUN_NULL;

    do {
      CONF_S *ctmp = NULL, *first_line = NULL;

      fline = rv >= 10 ? rv - 10 : 0;

      smime_init();

      smime_manage_certs_init(ps, &ctmp, &first_line, ctype, fline);

      if(ctmp == NULL){
	ps->mangled_screen = 1;
	smime_reinit();
        return;
      }

      memset(&screen, 0, sizeof(screen));
      screen.deferred_ro_warning = readonly_warning;
      rv = conf_scroll_screen(ps, &screen, first_line,
			       _("MANAGE CERTIFICATES"),
			      /* TRANSLATORS: Print something1 using something2.
				 configuration is something1 */
			      _("configuration"), 0, NULL);
    } while (rv != 0);

    ps->mangled_screen = 1;
    smime_reinit();
}

int
smime_helper_tool(struct pine *ps, int cmd, CONF_S **cl, unsigned flags)
{
    int rv = 0;

    switch(cmd){
      case MC_CHOICE:
	switch((*cl)->varmem){
	  case 1:
	    rv = copy_publiccert_dir_to_container();
	    if(rv == 0)
	      q_status_message(SM_ORDER, 1, 3, _("Public certs transferred to container"));
	    else{
		q_status_message(SM_ORDER, 3, 3, _("Problem transferring certs"));
		rv = 0;
	    }

	    break;

	  case 2:
	    rv = copy_publiccert_container_to_dir();
	    if(rv == 0)
	      q_status_message(SM_ORDER, 1, 3, _("Public certs transferred to directory, delete Container config to use"));
	    else{
		q_status_message(SM_ORDER, 3, 3, _("Problem transferring certs"));
		rv = 0;
	    }

	    break;

	  case 3:
	    rv = copy_privatecert_dir_to_container();
	    if(rv == 0)
	      q_status_message(SM_ORDER, 1, 3, _("Private keys transferred to container"));
	    else{
		q_status_message(SM_ORDER, 3, 3, _("Problem transferring certs"));
		rv = 0;
	    }

	    break;

	  case 4:
	    rv = copy_privatecert_container_to_dir();
	    if(rv == 0)
	      q_status_message(SM_ORDER, 1, 3, _("Private keys transferred to directory, delete Container config to use"));
	    else{
		q_status_message(SM_ORDER, 3, 3, _("Problem transferring certs"));
		rv = 0;
	    }

	    break;

	  case 5:
	    rv = copy_cacert_dir_to_container();
	    if(rv == 0)
	      q_status_message(SM_ORDER, 1, 3, _("CA certs transferred to container"));
	    else{
		q_status_message(SM_ORDER, 3, 3, _("Problem transferring certs"));
		rv = 0;
	    }

	    break;

	  case 6:
	    rv = copy_cacert_container_to_dir();
	    if(rv == 0)
	      q_status_message(SM_ORDER, 1, 3, _("CA certs transferred to directory, delete Container config to use"));
	    else{
		q_status_message(SM_ORDER, 3, 3, _("Problem transferring certs"));
		rv = 0;
	    }

	    break;

#ifdef APPLEKEYCHAIN
	  case 7:
	    rv = copy_publiccert_container_to_keychain();
	    if(rv == 0)
	      q_status_message(SM_ORDER, 1, 3, _("Public certs transferred to keychain"));
	    else{
		q_status_message(SM_ORDER, 3, 3, _("Command not implemented yet"));
		rv = 0;
	    }

	    break;

	  case 8:
	    rv = copy_publiccert_keychain_to_container();
	    if(rv == 0)
	      q_status_message(SM_ORDER, 1, 3, _("Public certs transferred to container"));
	    else{
		q_status_message(SM_ORDER, 3, 3, _("Command not implemented yet"));
		rv = 0;
	    }

	    break;
#endif /* APPLEKEYCHAIN */

	  case  9: manage_certificates(ps, Public) ; break;
	  case 10: manage_certificates(ps, Private); break;
	  case 11: manage_certificates(ps, CACert) ; break;

#ifdef PASSFILE
	  case 12: manage_password_file_certificates(ps); break;
#endif /* PASSFILE */

	  default:
	    rv = -1;
	    break;
	}

	break;

      case MC_EXIT:
	rv = config_exit_cmd(flags);
	break;

      case MC_IMPORT:
	rv = import_certificate((*cl)->d.s.ctype, NULL, NULL);
	break;

      default:
	rv = -1;
	break;
    }

    return rv;
}


/*
 * Compare saved user_val with current user_val to see if it changed.
 * If any have changed, change it back and take the appropriate action.
 */
void
revert_to_saved_smime_config(struct pine *ps, SAVED_CONFIG_S *vsave)
{
    struct variable *vreal;
    SAVED_CONFIG_S  *v;
    int i, n;
    int changed = 0;
    char *pval, **apval, **lval, ***alval;

    v = vsave;
    for(vreal = ps->vars; vreal->name; vreal++,v++){
	if(!(smime_related_var(ps, vreal) || vreal==&ps->vars[V_FEATURE_LIST]))
	  continue;

	if(vreal->is_list){
	    lval  = LVAL(vreal, ew);
	    alval = ALVAL(vreal, ew);

	    if((v->saved_user_val.l && !lval)
	       || (!v->saved_user_val.l && lval))
	      changed++;
	    else if(!v->saved_user_val.l && !lval)
	      ;/* no change, nothing to do */
	    else
	      for(i = 0; v->saved_user_val.l[i] || lval[i]; i++)
		if((v->saved_user_val.l[i]
		      && (!lval[i]
			 || strcmp(v->saved_user_val.l[i], lval[i])))
		   ||
		     (!v->saved_user_val.l[i] && lval[i])){
		    changed++;
		    break;
		}
	    
	    if(changed){
		char  **list;

		if(alval){
		    if(*alval)
		      free_list_array(alval);
		
		    /* copy back the original one */
		    if(v->saved_user_val.l){
			list = v->saved_user_val.l;
			n = 0;
			/* count how many */
			while(list[n])
			  n++;

			*alval = (char **)fs_get((n+1) * sizeof(char *));

			for(i = 0; i < n; i++)
			  (*alval)[i] = cpystr(v->saved_user_val.l[i]);

			(*alval)[n] = NULL;
		    }
		}
	    }
	}
	else{
	    pval  = PVAL(vreal, ew);
	    apval = APVAL(vreal, ew);

	    if((v->saved_user_val.p &&
	        (!pval || strcmp(v->saved_user_val.p, pval))) ||
	       (!v->saved_user_val.p && pval)){
		/* It changed, fix it */
		changed++;
		if(apval){
		    /* free the changed value */
		    if(*apval)
		      fs_give((void **)apval);

		    if(v->saved_user_val.p)
		      *apval = cpystr(v->saved_user_val.p);
		}
	    }
	}

	if(changed){
	    if(vreal == &ps->vars[V_FEATURE_LIST])
	      set_feature_list_current_val(vreal);
	    else
	      set_current_val(vreal, TRUE, FALSE);

	    fix_side_effects(ps, vreal, 1);
	}
    }
}


SAVED_CONFIG_S *
save_smime_config_vars(struct pine *ps)
{
    struct variable *vreal;
    SAVED_CONFIG_S *vsave, *v;

    vsave = (SAVED_CONFIG_S *)fs_get((V_LAST_VAR+1)*sizeof(SAVED_CONFIG_S));
    memset((void *)vsave, 0, (V_LAST_VAR+1)*sizeof(SAVED_CONFIG_S));
    for(v = vsave, vreal = ps->vars; vreal->name; vreal++,v++){
	if(!(smime_related_var(ps, vreal) || vreal==&ps->vars[V_FEATURE_LIST]))
	  continue;
	
	if(vreal->is_list){
	    int n, i;
	    char **list;

	    if(LVAL(vreal, ew)){
		/* count how many */
		n = 0;
		list = LVAL(vreal, ew);
		while(list[n])
		  n++;

		v->saved_user_val.l = (char **)fs_get((n+1)*sizeof(char *));
		memset((void *)v->saved_user_val.l, 0, (n+1)*sizeof(char *));
		for(i = 0; i < n; i++)
		  v->saved_user_val.l[i] = cpystr(list[i]);

		v->saved_user_val.l[n] = NULL;
	    }
	}
	else{
	    if(PVAL(vreal, ew))
	      v->saved_user_val.p = cpystr(PVAL(vreal, ew));
	}
    }

    return(vsave);
}


void
free_saved_smime_config(struct pine *ps, SAVED_CONFIG_S **vsavep)
{
    struct variable *vreal;
    SAVED_CONFIG_S  *v;

    if(vsavep && *vsavep){
	for(v = *vsavep, vreal = ps->vars; vreal->name; vreal++,v++){
	    if(!(smime_related_var(ps, vreal) || vreal==&ps->vars[V_FEATURE_LIST]))
	      continue;
	    
	    if(vreal->is_list){  /* free saved_user_val.l */
		if(v && v->saved_user_val.l)
		  free_list_array(&v->saved_user_val.l);
	    }
	    else if(v && v->saved_user_val.p)
	      fs_give((void **)&v->saved_user_val.p);
	}

	fs_give((void **)vsavep);
    }
}

#endif /* SMIME */
