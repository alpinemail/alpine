/*
 * $Id: thread.h 761 2007-10-23 22:35:18Z hubert@u.washington.edu $
 *
 * ========================================================================
 * Copyright 2006 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 */

#ifndef PITH_THREAD_INCLUDED
#define PITH_THREAD_INCLUDED


#include "../pith/msgno.h"
#include "../pith/indxtype.h"
#include "../pith/state.h"
#include "../pith/conf.h"


#define	THD_TOP		0x0000		/* start of an individual thread */
#define	THD_NEXT	0x0001
#define	THD_BRANCH	0x0004

typedef struct pine_thrd {
    unsigned long rawno;	/* raw msgno of this message		*/
    unsigned long thrdno;	/* thread number			*/
    unsigned long flags;
    unsigned long next;		/* msgno of first reply to us		*/
    unsigned long branch;	/* like THREADNODE branch, next replier	*/
    unsigned long parent;	/* message that this is a reply to	*/
    unsigned long nextthd;	/* next thread, only tops have this	*/
    unsigned long prevthd;	/* previous thread, only tops have this	*/
    unsigned long top;		/* top of this thread			*/
    unsigned long toploose;	/* top of this thread, if is loose	*/
    unsigned long head;		/* head of the whole thread list	*/
} PINETHRD_S;


/*
 * Some macros useful for threading
 */

/* Sort is a threaded sort */
#define SORT_IS_THREADED(msgmap)					\
	(mn_get_sort(msgmap) == SortThread				\
	 || mn_get_sort(msgmap) == SortSubject2)

#define SEP_THRDINDX()							\
	(ps_global->thread_index_style == THRDINDX_SEP 			\
	 || ps_global->thread_index_style == THRDINDX_SEP_AUTO)

#define COLL_THRDS()							\
	(ps_global->thread_index_style == THRDINDX_COLL)

#define THRD_AUTO_VIEW()						\
	(ps_global->thread_index_style == THRDINDX_SEP_AUTO)

/* We are threading now, pay attention to all the other variables */
#define THREADING()							\
	(!ps_global->turn_off_threading_temporarily			\
	 && SORT_IS_THREADED(ps_global->msgmap)				\
	 && (SEP_THRDINDX()						\
	     || ps_global->thread_disp_style != THREAD_NONE))

/* If we were to view the folder, we would get a thread index */
#define THRD_INDX_ENABLED()						\
	(SEP_THRDINDX()							\
	 && THREADING())

/* We are in the thread index (or would be if we weren't in an index menu) */
#define THRD_INDX()							\
	(THRD_INDX_ENABLED()						\
	 && !sp_viewing_a_thread(ps_global->mail_stream))

/* The thread command ought to work now */
#define THRD_COLLAPSE_ENABLE()						\
	(THREADING()							\
	 && !THRD_INDX()						\
	 && ps_global->thread_disp_style != THREAD_NONE)


/* exported protoypes */
PINETHRD_S   *fetch_thread(MAILSTREAM *, unsigned long);
PINETHRD_S   *fetch_head_thread(MAILSTREAM *);
void	      set_flags_for_thread(MAILSTREAM *, MSGNO_S *, int, PINETHRD_S *, int);
void	      erase_threading_info(MAILSTREAM *, MSGNO_S *);
void	      sort_thread_callback(MAILSTREAM *, THREADNODE *);
void	      collapse_threads(MAILSTREAM *, MSGNO_S *, PINETHRD_S *);
PINETHRD_S   *msgno_thread_info(MAILSTREAM *, unsigned long, PINETHRD_S *, unsigned);
void	      collapse_or_expand(struct pine *, MAILSTREAM *, MSGNO_S *, unsigned long, int);
void	      select_thread_stmp(struct pine *, MAILSTREAM *, MSGNO_S *);
unsigned long count_flags_in_thread(MAILSTREAM *, PINETHRD_S *, long);
unsigned long count_lflags_in_thread(MAILSTREAM *, PINETHRD_S *, MSGNO_S *, int);
int	      thread_has_some_visible(MAILSTREAM *, PINETHRD_S *);
int	      mark_msgs_in_thread(MAILSTREAM *, PINETHRD_S *, MSGNO_S *);
void	      set_thread_lflags(MAILSTREAM *, PINETHRD_S *, MSGNO_S *, int, int);
char	      status_symbol_for_thread(MAILSTREAM *, PINETHRD_S *, IndexColType);
char	      to_us_symbol_for_thread(MAILSTREAM *, PINETHRD_S *, int);
void	      set_thread_subtree(MAILSTREAM *, PINETHRD_S *, MSGNO_S *, int, int);
int	      view_thread(struct pine *, MAILSTREAM *, MSGNO_S *, int);
int	      unview_thread(struct pine *, MAILSTREAM *, MSGNO_S *);
PINETHRD_S   *find_thread_by_number(MAILSTREAM *, MSGNO_S *, long, PINETHRD_S *);
void	      set_search_bit_for_thread(MAILSTREAM *, PINETHRD_S *, SEARCHSET **);
void	      find_msgmap(MAILSTREAM *, MSGNO_S *, int, SortOrder, unsigned);
void	      move_thread(struct pine *, MAILSTREAM *, MSGNO_S *, int);
void	      relink_threads(MAILSTREAM *, MSGNO_S *, long *);
long	      top_thread(MAILSTREAM *, long);
long	      top_this_thread(MAILSTREAM *, long);
long	      get_length_branch(MAILSTREAM *, long);
unsigned long get_next(MAILSTREAM *,PINETHRD_S *);
unsigned long get_branch(MAILSTREAM *,PINETHRD_S *);
int	      count_thread(struct pine *, MAILSTREAM *, MSGNO_S *, long);
int	      count_this_thread(MAILSTREAM *, unsigned long);
int	      this_thread_is_kolapsed(struct pine *, MAILSTREAM *, MSGNO_S *, long);
int	      thread_is_kolapsed(struct pine *, MAILSTREAM *, MSGNO_S *, long);
int	      move_prev_thread(struct pine *, MAILSTREAM  *, MSGNO_S *, int);
int	      move_next_thread(struct pine *, MAILSTREAM  *, MSGNO_S *, int);
int	      move_next_this_thread(struct pine *, MAILSTREAM  *, MSGNO_S *, int);
void	      move_top_thread(MAILSTREAM *, MSGNO_S *, long);
void	      move_top_this_thread(MAILSTREAM *, MSGNO_S *, long);
THREADNODE   *copy_tree(THREADNODE *);
int	      allowed_thread_key(SortOrder sort);

#endif /* PITH_THREAD_INCLUDED */
