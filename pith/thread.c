#if !defined(lint) && !defined(DOS)
static char rcsid[] = "$Id: thread.c 942 2008-03-04 18:21:33Z hubert@u.washington.edu $";
#endif

/*
 * ========================================================================
 * Copyright 2006-2008 University of Washington
 * Copyright 2013 Eduardo Chappa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 */

#include "../pith/headers.h"
#include "../pith/thread.h"
#include "../pith/flag.h"
#include "../pith/icache.h"
#include "../pith/mailindx.h"
#include "../pith/msgno.h"
#include "../pith/sort.h"
#include "../pith/pineelt.h"
#include "../pith/status.h"
#include "../pith/news.h"
#include "../pith/search.h"
#include "../pith/mailcmd.h"
#include "../pith/ablookup.h"

static int erase_thread_info = 1;

typedef struct sizethread_t {
   int   count;
   long  pos;
} SIZETHREAD_T;

/*
 * Internal prototypes
 */
long *sort_thread_flatten(THREADNODE *, MAILSTREAM *, long *,
			  char *, long, PINETHRD_S *, unsigned, int, long, long);
void		   make_thrdflags_consistent(MAILSTREAM *, MSGNO_S *, PINETHRD_S *, int);
THREADNODE	  *collapse_threadnode_tree(THREADNODE *);
THREADNODE	  *collapse_threadnode_tree_sorted(THREADNODE *);
THREADNODE	  *sort_threads_and_collapse(THREADNODE *);
THREADNODE        *insert_tree_in_place(THREADNODE *, THREADNODE *);
unsigned long      branch_greatest_num(THREADNODE *, int);
long		   calculate_visible_threads(MAILSTREAM *);
int		   pine_compare_size_thread(const qsort_t *, const qsort_t *);


PINETHRD_S *
fetch_thread(MAILSTREAM *stream, long unsigned int rawno)
{
    MESSAGECACHE *mc;
    PINELT_S     *pelt;
    PINETHRD_S   *thrd = NULL;

    if(stream && rawno > 0L && rawno <= stream->nmsgs
       && !sp_need_to_rethread(stream)){
	mc = (rawno > 0L && stream && rawno <= stream->nmsgs)
	        ? mail_elt(stream, rawno) : NULL;
	if(mc && (pelt = (PINELT_S *) mc->sparep))
	  thrd = pelt->pthrd;
    }

    return(thrd);
}


PINETHRD_S *
fetch_head_thread(MAILSTREAM *stream)
{
    unsigned long rawno;
    PINETHRD_S   *thrd = NULL;

    if(stream){
	/* first find any thread */
	for(rawno = 1L; !thrd && rawno <= stream->nmsgs; rawno++)
	  thrd = fetch_thread(stream, rawno);

	if(thrd && thrd->head)
	  thrd = fetch_thread(stream, thrd->head);
    }

    return(thrd);
}


/*
 * Set flag f to v for all messages in thrd.
 *
 * Watch out when calling this. The thrd->branch is not part of thrd.
 * Branch is a sibling to thrd, not a child. Zero out branch before calling
 * or call on thrd->next and worry about thrd separately.
 * Ok to call it on top-level thread which has no branch already.
 */
void
set_flags_for_thread(MAILSTREAM *stream, MSGNO_S *msgmap, int f, PINETHRD_S *thrd, int v)
{
    PINETHRD_S *nthrd, *bthrd;
    unsigned long next = 0L, branch = 0L;

    if(!(stream && thrd && msgmap))
      return;

    set_lflag(stream, msgmap, mn_raw2m(msgmap, thrd->rawno), f, v);

    if(next = get_next(stream,thrd)){
	nthrd = fetch_thread(stream, next);
	if(nthrd)
	  set_flags_for_thread(stream, msgmap, f, nthrd, v);
    }


    if(branch = get_branch(stream, thrd)){
	bthrd = fetch_thread(stream, branch);
	if(bthrd)
	  set_flags_for_thread(stream, msgmap, f, bthrd, v);
    }
}


void
erase_threading_info(MAILSTREAM *stream, MSGNO_S *msgmap)
{
    unsigned long n;
    MESSAGECACHE *mc;
    PINELT_S     *peltp;

    if(!(stream && stream->spare) || !erase_thread_info)
      return;
    
    ps_global->view_skipped_index = 0;
    sp_set_viewing_a_thread(stream, 0);
    
    if(THRD_INDX())
      setup_for_thread_index_screen();
    else
      setup_for_index_index_screen();

    stream->spare = 0;

    for(n = 1L; n <= stream->nmsgs; n++){
	set_lflag(stream, msgmap, mn_raw2m(msgmap, n),
		  MN_COLL | MN_CHID | MN_CHID2, 0);
	mc = mail_elt(stream, n);
	if(mc && mc->sparep){
	    peltp = (PINELT_S *) mc->sparep;
	    if(peltp->pthrd)
	      fs_give((void **) &peltp->pthrd);
	}
    }
}


void
sort_thread_callback(MAILSTREAM *stream, THREADNODE *tree)
{
    THREADNODE *collapsed_tree = NULL;
    PINETHRD_S   *thrd = NULL;
    unsigned long msgno, rawno;
    int           un_view_thread = 0;
    long          raw_current, branch;
    char         *dup_chk = NULL;


    dprint((2, "sort_thread_callback\n"));

    g_sort.msgmap->max_thrdno = 0L;

    /*
     * Eliminate dummy nodes from tree and collapse the tree in a logical
     * way. If the dummy node is at the top-level, then its children are
     * promoted to the top-level as separate threads.
     */
     collapsed_tree = F_ON(F_ENHANCED_THREAD, ps_global)
			? copy_tree(tree)
			: (F_ON(F_THREAD_SORTS_BY_ARRIVAL, ps_global)
			  ? collapse_threadnode_tree_sorted(tree)
			  : collapse_threadnode_tree(tree));

    /* dup_chk is like sort with an origin of 1 */
    dup_chk = (char *) fs_get((mn_get_nmsgs(g_sort.msgmap)+1) * sizeof(char));
    memset(dup_chk, 0, (mn_get_nmsgs(g_sort.msgmap)+1) * sizeof(char));

    memset(&g_sort.msgmap->sort[1], 0, mn_get_total(g_sort.msgmap) * sizeof(long));

    (void) sort_thread_flatten(collapsed_tree, stream,
			       &g_sort.msgmap->sort[1],
			       dup_chk, mn_get_nmsgs(g_sort.msgmap),
			       NULL, THD_TOP, 0, 1L, 0L);

    /* reset the inverse array */
    msgno_reset_isort(g_sort.msgmap);

    if(dup_chk)
      fs_give((void **) &dup_chk);

    if(collapsed_tree)
      mail_free_threadnode(&collapsed_tree);

    if(any_lflagged(g_sort.msgmap, MN_HIDE))
      g_sort.msgmap->visible_threads = calculate_visible_threads(stream);
    else
      g_sort.msgmap->visible_threads = g_sort.msgmap->max_thrdno;

    raw_current = mn_m2raw(g_sort.msgmap, mn_get_cur(g_sort.msgmap));

    sp_set_need_to_rethread(stream, 0);

    /*
     * Set appropriate bits to start out collapsed if desired. We use the
     * stream spare bit to tell us if we've done this before for this
     * stream.
     */
    if(!stream->spare
       && (COLL_THRDS() || SEP_THRDINDX())
       && mn_get_total(g_sort.msgmap) > 1L){

	collapse_threads(stream, g_sort.msgmap, NULL);
    }
    else if(stream->spare){
	
	/*
	 * If we're doing auto collapse then new threads need to have
	 * their collapse bit set. This happens below if we're in the
	 * thread index, but if we're in the regular index with auto
	 * collapse we have to look for these.
	 */
	if(any_lflagged(g_sort.msgmap, MN_USOR)){
	    if(COLL_THRDS()){
		for(msgno = 1L; msgno <= mn_get_total(g_sort.msgmap); msgno++){
		    rawno = mn_m2raw(g_sort.msgmap, msgno);
		    if(get_lflag(stream, NULL, rawno, MN_USOR)){
			thrd = fetch_thread(stream, rawno);

			/*
			 * Node is new, unsorted, top-level thread,
			 * and we're using auto collapse.
			 */
			if(thrd && !thrd->parent)
			  set_lflag(stream, g_sort.msgmap, msgno, MN_COLL, 1);
			
			/*
			 * If a parent is collapsed, clear that parent's
			 * index cache entry. This is only necessary if
			 * the parent's index display can depend on its
			 * children, of course.
			 */
			if(thrd && thrd->parent){
			    thrd = fetch_thread(stream, thrd->parent);
			    while(thrd){
				long t;

				if(get_lflag(stream, NULL, thrd->rawno, MN_COLL)
				   && (t = mn_raw2m(g_sort.msgmap,
						    (long) thrd->rawno)))
				  clear_index_cache_ent(stream, t, 0);

				if(thrd->parent)
				  thrd = fetch_thread(stream, thrd->parent);
				else
				  thrd = NULL;
			    }
			}

		    }
		}
	    }

	    set_lflags(stream, g_sort.msgmap, MN_USOR, 0);
	}

	if(sp_viewing_a_thread(stream)){
	    if(any_lflagged(g_sort.msgmap, MN_CHID2)){
		/* current should be part of viewed thread */
		if(get_lflag(stream, NULL, raw_current, MN_CHID2)){
		    thrd = fetch_thread(stream, raw_current);
		    if(thrd && thrd->top && thrd->top != thrd->rawno)
		      thrd = fetch_thread(stream, thrd->top);
		    
		    if(thrd){
			/*
			 * For messages that are part of thread set MN_CHID2
			 * and for messages that aren't part of the thread
			 * clear MN_CHID2. Easiest is to just do it instead
			 * of checking if it is true first.
			 */
			set_lflags(stream, g_sort.msgmap, MN_CHID2, 0);
			set_thread_lflags(stream, thrd, g_sort.msgmap,
					  MN_CHID2, 1);
			
			/*
			 * Outside of the viewed thread everything else
			 * should be collapsed at the top-levels.
			 */
			collapse_threads(stream, g_sort.msgmap, thrd);

			/*
			 * Inside of the thread, the top of the thread
			 * can't be hidden, the rest are hidden if a
			 * parent somewhere above them is collapsed.
			 * There can be collapse points that are hidden
			 * inside of the tree. They remain collapsed even
			 * if the parent above them uncollapses.
			 */
			msgno = mn_raw2m(g_sort.msgmap, (long) thrd->rawno);
			if(msgno)
			  set_lflag(stream, g_sort.msgmap, msgno, MN_CHID, 0);

			if(thrd->next){
			    PINETHRD_S *nthrd;

			    nthrd = fetch_thread(stream, thrd->next);
			    if(nthrd)
			      make_thrdflags_consistent(stream, g_sort.msgmap,
							nthrd,
							get_lflag(stream, NULL,
								  thrd->rawno,
								  MN_COLL));
			}
		    }
		    else
		      un_view_thread++;
		}
		else
		  un_view_thread++;
	    }
	    else
	      un_view_thread++;

	    if(un_view_thread){
		set_lflags(stream, g_sort.msgmap, MN_CHID2, 0);
		unview_thread(ps_global, stream, g_sort.msgmap);
	    }
	    else{
		mn_reset_cur(g_sort.msgmap,
			     mn_raw2m(g_sort.msgmap, raw_current));
		view_thread(ps_global, stream, g_sort.msgmap, 0);
	    }
	}
	else if(SEP_THRDINDX()){
	    set_lflags(stream, g_sort.msgmap, MN_CHID2, 0);
	    collapse_threads(stream, g_sort.msgmap, NULL);
	}
	else{
	    thrd = fetch_head_thread(stream);
	    while(thrd){
		unsigned long raw = thrd->rawno;
		unsigned long top = top_thread(stream, raw);
		/*
		 * The top-level threads aren't hidden by collapse.
		 */
		msgno = mn_raw2m(g_sort.msgmap, thrd->rawno);
		if(msgno && !get_lflag(stream, NULL,thrd->rawno, MN_COLL))
		   set_lflag(stream, g_sort.msgmap, msgno, MN_CHID, 0);

		if(thrd->next){
		    PINETHRD_S *nthrd;

		    nthrd = fetch_thread(stream, thrd->next);
		    if(nthrd)
		      make_thrdflags_consistent(stream, g_sort.msgmap,
						nthrd,
						get_lflag(stream, NULL,
							  thrd->rawno,
							  MN_COLL));
		}

		while (thrd && top_thread(stream, thrd->rawno) == top
				&& thrd->nextthd)
		thrd = fetch_thread(stream, thrd->nextthd);
		if (!(thrd && thrd->nextthd))
		  thrd = NULL;
	    }
	}
    }

    stream->spare = 1;

    dprint((2, "sort_thread_callback done\n"));
}


void
collapse_threads(MAILSTREAM *stream, MSGNO_S *msgmap, PINETHRD_S *not_this_thread)
{
    PINETHRD_S   *thrd = NULL, *nthrd;
    unsigned long msgno;

    dprint((9, "collapse_threads\n"));

    thrd = fetch_head_thread(stream);
    while(thrd){
	if(thrd != not_this_thread){
	    msgno = mn_raw2m(g_sort.msgmap, thrd->rawno);

	    /* set collapsed bit */
	    if(msgno){
		set_lflag(stream, g_sort.msgmap, msgno, MN_COLL, 1);
		set_lflag(stream, g_sort.msgmap, msgno, MN_CHID, 0);
	    }

	    /* hide its children */
	    if(thrd->next && (nthrd = fetch_thread(stream, thrd->next)))
	      set_thread_subtree(stream, nthrd, msgmap, 1, MN_CHID);
	}

	if(thrd->nextthd)
	  thrd = fetch_thread(stream, thrd->nextthd);
	else
	  thrd = NULL;
    }

    dprint((9, "collapse_threads done\n"));
}


void
make_thrdflags_consistent(MAILSTREAM *stream, MSGNO_S *msgmap, PINETHRD_S *thrd,
			  int a_parent_is_collapsed)
{
    PINETHRD_S *nthrd, *bthrd;
    unsigned long msgno, next, branch;

    if(!thrd)
      return;

    msgno = mn_raw2m(msgmap, thrd->rawno);

    if(a_parent_is_collapsed){
	/* if some parent is collapsed, we should be hidden */
	if(msgno)
	  set_lflag(stream, msgmap, msgno, MN_CHID, 1);
    }
    else{
	/* no parent is collapsed so we are not hidden */
	if(msgno)
	  set_lflag(stream, msgmap, msgno, MN_CHID, 0);
    }

    if(next = get_next(stream, thrd)){
	nthrd = fetch_thread(stream, next);
	if(nthrd)
	  make_thrdflags_consistent(stream, msgmap, nthrd,
				    a_parent_is_collapsed
				      ? a_parent_is_collapsed
				      : get_lflag(stream, NULL, thrd->rawno,
						  MN_COLL));
    }

    if(branch = get_branch(stream, thrd)){
	bthrd = fetch_thread(stream, branch);
	if(bthrd)
	  make_thrdflags_consistent(stream, msgmap, bthrd,
				    a_parent_is_collapsed);
    }
}


long
calculate_visible_threads(MAILSTREAM *stream)
{
    PINETHRD_S   *thrd = NULL;
    long          vis = 0L;

    thrd = fetch_head_thread(stream);
    while(thrd){
	vis += (thread_has_some_visible(stream, thrd) ? 1 : 0);

	if(thrd->nextthd)
	  thrd = fetch_thread(stream, thrd->nextthd);
	else
	  thrd = NULL;
    }

    return(vis);
}


/*
 * This routine does a couple things. The input is the THREADNODE node
 * that we get from c-client because of the THREAD command. The rest of
 * the arguments are used to help guide this function through its
 * recursive steps. One thing it does is to place the sort order in
 * the array initially pointed to by the entry argument. All it is doing
 * is walking the tree in the next then branch order you see below and
 * incrementing the entry number one for each node. The other thing it
 * is doing at the same time is to create a PINETHRD_S tree from the
 * THREADNODE tree. The two trees are completely equivalent but the
 * PINETHRD_S version has additional back pointers and parent pointers
 * and so on to make it easier for alpine to deal with it. Each node
 * of that tree is tied to the data associated with a particular message
 * by the msgno_thread_info() call, so that we can go from a message
 * number to the place in the thread tree that message sits.
 */
long *
sort_thread_flatten(THREADNODE *node, MAILSTREAM *stream,
		    long *entry, char *dup_chk, long maxno,
		    PINETHRD_S *thrd, unsigned int flags,
		    int adopted, long top, long threadno)
{
    PINETHRD_S *newthrd = NULL, *save_thread = NULL;

    if(node){
	if(node->num > 0L && node->num <= maxno){		/* holes happen */
	    if(!dup_chk[node->num]){				/* not a duplicate */
		*entry = node->num;
		dup_chk[node->num] = 1;

		if(adopted == 2)
		  top = node->num;

		/*
		 * Build a richer threading structure that will help us paint
		 * and operate on threads and subthreads.
		 */
		newthrd = msgno_thread_info(stream, node->num, thrd, flags);
		if(newthrd){
		  entry++;

		  if(adopted == 2)
		    threadno = newthrd->thrdno;
		  if(adopted){
		    newthrd->toploose = top;
		    newthrd->thrdno = threadno;
		  }
		  adopted = adopted ? 1 : 0;
		  if(node->next)
		    entry = sort_thread_flatten(node->next, stream,
						entry, dup_chk, maxno,
						newthrd, THD_NEXT, adopted, top, threadno);

		  if(node->branch)
		    entry = sort_thread_flatten(node->branch, stream,
						entry, dup_chk, maxno,
						newthrd,
						((flags == THD_TOP) ? THD_TOP
								   : THD_BRANCH),
						adopted, top, threadno);
		}
	    }
	}
	else{
	   adopted = 2;
	   if(node->next)
	     entry = sort_thread_flatten(node->next, stream, entry, dup_chk,
					  maxno, thrd, THD_TOP, adopted, top, threadno);
	   adopted = 0;
	   if(node->branch){
	     if(entry){
		long *last_entry = entry;

		do{ 
		  last_entry--;
		  save_thread = ((PINELT_S *)mail_elt(stream, *last_entry)->sparep)->pthrd;
		} while (save_thread->parent != 0L);
		entry = sort_thread_flatten(node->branch, stream, entry, dup_chk,
						maxno, save_thread, (flags == THD_TOP ? THD_TOP : THD_BRANCH),
						adopted, top, threadno);
	     }
	     else
		entry = sort_thread_flatten(node->branch, stream, entry, dup_chk,
					    maxno, NULL, THD_TOP, adopted, top, threadno);
	   }
	}
    }

    return(entry);
}


/*
 * Make a copy of c-client's THREAD tree while eliminating dummy nodes.
 */
THREADNODE *
collapse_threadnode_tree(THREADNODE *tree)
{
    THREADNODE *newtree = NULL;

    if(tree){
	if(tree->num){
	    newtree = mail_newthreadnode(NULL);
	    newtree->num  = tree->num;
	    if(tree->next)
	      newtree->next = collapse_threadnode_tree(tree->next);

	    if(tree->branch)
	      newtree->branch = collapse_threadnode_tree(tree->branch);
	}
	else{
	    if(tree->next)
	      newtree = collapse_threadnode_tree(tree->next);
	    
	    if(tree->branch){
		if(newtree){
		    THREADNODE *last_branch = NULL;

		    /*
		     * Next moved up to replace "tree" in the tree.
		     * If next has no branches, then we want to branch off
		     * of next. If next has branches, we want to branch off
		     * of the last of those branches instead.
		     */
		    last_branch = newtree;
		    while(last_branch->branch)
		      last_branch = last_branch->branch;
		    
		    last_branch->branch = collapse_threadnode_tree(tree->branch);
		}
		else
		  newtree = collapse_threadnode_tree(tree->branch);
	    }
	}
    }

    return(newtree);
}


/*
 * Like collapse_threadnode_tree, we collapse the dummy nodes.
 * In addition we rearrange the threads by order of arrival of
 * the last message in the thread, rather than the first message
 * in the thread.
 */
THREADNODE *
collapse_threadnode_tree_sorted(THREADNODE *tree)
{
    THREADNODE *sorted_tree = NULL;

    sorted_tree = sort_threads_and_collapse(tree);

    /* 
     * We used to eliminate top-level dummy nodes here so that
     * orphans would still get sorted together, but we changed
     * to sort the orphans themselves as top-level threads.
     *
     * It might be a matter of choice how they get sorted, but
     * we'll try doing it this way and not add another feature.
     */

    return(sorted_tree);
}

/*
 * Recurse through the tree, sorting each top-level branch by the
 * greatest num in the thread.
 */
THREADNODE *
sort_threads_and_collapse(THREADNODE *tree)
{
    THREADNODE *newtree = NULL, *newbranchtree = NULL, *newtreefree = NULL;

    if(tree){
	newtree = mail_newthreadnode(NULL);
	newtree->num  = tree->num;

	/* 
	 * Only sort at the top level.  Individual threads can
	 * rely on collapse_threadnode_tree 
	 */
	if(tree->next)
	  newtree->next = collapse_threadnode_tree(tree->next);

	if(tree->branch){
	    /*
	     * This recursive call returns an already re-sorted tree.
	     * With that, we can loop through and inject ourselves
	     * where we fit in with that sort, and pass back to the
	     * caller to inject themselves.
	     */
	    newbranchtree = sort_threads_and_collapse(tree->branch);
	}

	if(newtree->num)
	  newtree = insert_tree_in_place(newtree, newbranchtree);
	else{
	    /*
	     * If top node is a dummy, here is where we collapse it.
	     */
	    newtreefree = newtree;
	    newtree = insert_tree_in_place(newtree->next, newbranchtree);
	    newtreefree->next = NULL;
	    mail_free_threadnode(&newtreefree);
	}
    }

    return(newtree);
}

/*
 * Recursively insert each of the top-level nodes in newtree in their place
 * in tree according to which tree has the most recent arrival
 */
THREADNODE *
insert_tree_in_place(THREADNODE *newtree, THREADNODE *tree)
{
    THREADNODE *node = NULL;
    unsigned long newtree_greatest_num = 0;
    if(newtree->branch){
	node = newtree->branch;
	newtree->branch = NULL;
	tree = insert_tree_in_place(node, tree);
    }

    newtree_greatest_num = branch_greatest_num(newtree, 0);

    if(tree){
	/*
	 * Since tree is already sorted, we can insert when we find something
	 * newtree is less than
	 */
	if(newtree_greatest_num < branch_greatest_num(tree, 0))
	  newtree->branch = tree;
	else {
	    for(node = tree; node->branch; node = node->branch){
		if(newtree_greatest_num < branch_greatest_num(node->branch, 0)){
		    newtree->branch = node->branch;
		    node->branch = newtree;
		    break;
		}
	    }
	    if(!node->branch)
	      node->branch = newtree;

	    newtree = tree;
	}
    }

    return(newtree);
}

/*
 * Given a thread, return the greatest num in the tree.
 * is_subthread tells us not to recurse through branches, so
 * we can split the top level into threads.
 */
unsigned long
branch_greatest_num(THREADNODE *tree, int is_subthread)
{
    unsigned long ret, branch_ret;

    ret = tree->num;

    if(tree->next && (branch_ret = branch_greatest_num(tree->next, 1)) > ret)
      ret = branch_ret;
    if(is_subthread && tree->branch &&
       (branch_ret = branch_greatest_num(tree->branch, 1)) > ret)
      ret = branch_ret;

    return ret;
}


/*
 * Args      stream -- the usual
 *            rawno -- the raw msg num associated with this new node
 * attached_to_thrd -- the PINETHRD_S node that this is either a next or branch
 *                       off of
 *            flags --
 */
PINETHRD_S *
msgno_thread_info(MAILSTREAM *stream, long unsigned int rawno,
		  PINETHRD_S *attached_to_thrd, unsigned int flags)
{
    PINELT_S   **peltp;
    MESSAGECACHE *mc;

    if(!stream || rawno < 1L || rawno > stream->nmsgs)
      return NULL;

    /*
     * any private elt data yet?
     */
    if((mc = mail_elt(stream, rawno))
       && (*(peltp = (PINELT_S **) &mc->sparep) == NULL)){
	*peltp = (PINELT_S *) fs_get(sizeof(PINELT_S));
	memset(*peltp, 0, sizeof(PINELT_S));
    }

    if((*peltp)->pthrd == NULL)
      (*peltp)->pthrd = (PINETHRD_S *) fs_get(sizeof(PINETHRD_S));

    memset((*peltp)->pthrd, 0, sizeof(PINETHRD_S));

    (*peltp)->pthrd->rawno = rawno;

    if(attached_to_thrd)
      (*peltp)->pthrd->head = attached_to_thrd->head;
    else
      (*peltp)->pthrd->head = (*peltp)->pthrd->rawno;	/* it's me */

    if(flags == THD_TOP){
	/*
	 * We can tell this thread is a top-level thread because it doesn't
	 * have a parent.
	 */
	(*peltp)->pthrd->top = (*peltp)->pthrd->rawno;	/* I am a top */
	if(attached_to_thrd){
	    attached_to_thrd->nextthd = (*peltp)->pthrd->rawno;
	    (*peltp)->pthrd->prevthd  = attached_to_thrd->rawno;
	    (*peltp)->pthrd->thrdno   = attached_to_thrd->thrdno + 1L;
	}
	else
	    (*peltp)->pthrd->thrdno   = 1L;		/* 1st thread */

	g_sort.msgmap->max_thrdno = (*peltp)->pthrd->thrdno;
    }
    else if(flags == THD_NEXT){
	if(attached_to_thrd){
	    attached_to_thrd->next  = (*peltp)->pthrd->rawno;
	    (*peltp)->pthrd->parent = attached_to_thrd->rawno;
	    (*peltp)->pthrd->top    = attached_to_thrd->top;
	}
    }
    else if(flags == THD_BRANCH){
	if(attached_to_thrd){
	    attached_to_thrd->branch = (*peltp)->pthrd->rawno;
	    (*peltp)->pthrd->parent  = attached_to_thrd->parent;
	    (*peltp)->pthrd->top     = attached_to_thrd->top;
	}
    }

    return((*peltp)->pthrd);
}


/*
 * Collapse or expand a threading subtree. Not called from separate thread
 * index.
 */
void
collapse_or_expand(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap,
		   long unsigned int msgno, int display)
{
    int           collapsed, adjust_current = 0;
    PINETHRD_S   *thrd = NULL, *nthrd;
    unsigned long rawno;

    if(!stream)
      return;

    /*
     * If msgno is a good msgno, then we collapse or expand the subthread
     * which begins at msgno. If msgno is 0, we collapse or expand the
     * entire current thread.
     */

    if(msgno > 0L && msgno <= mn_get_total(msgmap)){
	rawno = mn_m2raw(msgmap, msgno);
	if(rawno)
	  thrd = fetch_thread(stream, rawno);
    }
    else if(msgno == 0L){
	rawno = mn_m2raw(msgmap, mn_get_cur(msgmap));
	if(rawno)
	  thrd = fetch_thread(stream, rawno);
	
	if(thrd && thrd->top != thrd->rawno){
	    adjust_current++;
	    thrd = fetch_thread(stream, thrd->top);
	    
	    /*
	     * Special case. If the user is collapsing the entire thread
	     * (msgno == 0), and we are in a Zoomed view, and the top of
	     * the entire thread is not part of the Zoomed view, then watch
	     * out. If we were to collapse the entire thread it would just
	     * disappear, because the top is not in the Zoom. Therefore,
	     * don't allow it. Do what the user probably wants, which is to
	     * collapse the thread at that point instead of the entire thread,
	     * leaving behind the top of the subthread to expand if needed.
	     * In other words, treat it as if they didn't have the
	     * F_SLASH_COLL_ENTIRE feature set.
	     */
	    collapsed = get_lflag(stream, NULL, thrd->rawno, MN_COLL)
			&& thrd->next;

	    if(!collapsed && get_lflag(stream, NULL, thrd->rawno, MN_HIDE))
	      thrd = fetch_thread(stream, rawno);
	}
    }


    if(!thrd)
      return;

    collapsed = this_thread_is_kolapsed(ps_global, stream, msgmap, thrd->rawno);

    if(collapsed){
	msgno = mn_raw2m(msgmap, thrd->rawno);
	if(msgno > 0L && msgno <= mn_get_total(msgmap)){
	    set_lflag(stream, msgmap, msgno, MN_COLL, 0);
	    if(thrd->next){
		if((nthrd = fetch_thread(stream, thrd->next)) != NULL)
		  set_thread_subtree(stream, nthrd, msgmap, 0, MN_CHID);

		clear_index_cache_ent(stream, msgno, 0);
	    }
	}
    }
    else if(thrd && thrd->next){
	msgno = mn_raw2m(msgmap, thrd->rawno);
	if(msgno > 0L && msgno <= mn_get_total(msgmap)){
	    set_lflag(stream, msgmap, msgno, MN_COLL, 1);
	    if((thrd->next) && ((nthrd = fetch_thread(stream, thrd->next)) != NULL))
	      set_thread_subtree(stream, nthrd, msgmap, 1, MN_CHID);

	    clear_index_cache_ent(stream, msgno, 0);
	}
    }
    else if(display)
      q_status_message(SM_ORDER, 0, 1,
		       _("No thread to collapse or expand on this line"));
    
    /* if current is hidden, adjust */
    if(adjust_current)
      adjust_cur_to_visible(stream, msgmap);
}


/*
 * Select the messages in a subthread. If all of the messages are already
 * selected, unselect them. This routine is a bit strange because it
 * doesn't set the MN_SLCT bit. Instead, it sets MN_STMP in apply_command
 * and then thread_command copies the MN_STMP messages back to MN_SLCT.
 */
void
select_thread_stmp(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap)
{
    PINETHRD_S   *thrd;
    unsigned long rawno, in_thread, set_in_thread, save_branch;

    /* ugly bit means the same thing as return of 1 from individual_select */
    state->ugly_consider_advancing_bit = 0;

    if(!(stream && msgmap))
      return;

    rawno = mn_m2raw(msgmap, mn_get_cur(msgmap));
    if(rawno)
      thrd = fetch_thread(stream, rawno);
    
    if(!thrd)
      return;
    
    /* run through thrd to see if it is all selected */
    save_branch = thrd->branch;
    thrd->branch = 0L;
    if((set_in_thread = count_lflags_in_thread(stream, thrd, msgmap, MN_STMP))
       == (in_thread = count_lflags_in_thread(stream, thrd, msgmap, MN_NONE))){
	/*
	 * If everything is selected, the first unselect should cause
	 * an autozoom. In order to trigger the right code in
	 *   thread_command()
	 *     copy_lflags()
	 * we set the MN_HIDE bit on the current message here.
	 */
	if(F_ON(F_AUTO_ZOOM, state) && !any_lflagged(msgmap, MN_HIDE)
	   && any_lflagged(msgmap, MN_STMP) == mn_get_total(msgmap))
	  set_lflag(stream, msgmap, mn_get_cur(msgmap), MN_HIDE, 1);
	set_thread_lflags(stream, thrd, msgmap, MN_STMP, 0);
    }
    else{
	set_thread_lflags(stream, thrd, msgmap, MN_STMP, 1);
	state->ugly_consider_advancing_bit = 1;
    }

    thrd->branch = save_branch;
    
    if(set_in_thread == in_thread)
      q_status_message1(SM_ORDER, 0, 3, _("Unselected %s messages in thread"),
			comatose((long) in_thread));
    else if(set_in_thread == 0)
      q_status_message1(SM_ORDER, 0, 3, _("Selected %s messages in thread"),
			comatose((long) in_thread));
    else
      q_status_message1(SM_ORDER, 0, 3,
			_("Selected %s more messages in thread"),
			comatose((long) (in_thread-set_in_thread)));
}


/*
 * Count how many of this system flag in this thread subtree.
 * If flags == 0 count the messages in the thread.
 *
 * Watch out when calling this. The thrd->branch is not part of thrd.
 * Branch is a sibling to thrd, not a child. Zero out branch before calling
 * or call on thrd->next and worry about thrd separately.
 * Ok to call it on top-level thread which has no branch already.
 */
unsigned long
count_flags_in_thread(MAILSTREAM *stream, PINETHRD_S *thrd, long int flags)
{
    unsigned long count = 0;
    PINETHRD_S *nthrd, *bthrd;
    MESSAGECACHE *mc;
    unsigned long next = 0L, branch = 0L;

    if(!thrd || !stream || thrd->rawno < 1L || thrd->rawno > stream->nmsgs)
      return count;
    
    if(next = get_next(stream, thrd)){
	nthrd = fetch_thread(stream, next);
	if(nthrd)
	  count += count_flags_in_thread(stream, nthrd, flags);
    }

    if(branch = get_branch(stream, thrd)){
	bthrd = fetch_thread(stream, branch);
	if(bthrd)
	  count += count_flags_in_thread(stream, bthrd, flags);
    }

    mc = (thrd && thrd->rawno > 0L && stream && thrd->rawno <= stream->nmsgs)
	  ? mail_elt(stream, thrd->rawno) : NULL;
    if(mc && mc->valid && FLAG_MATCH(flags, mc, stream))
      count++;

    return count;
}


/*
 * Count how many of this local flag in this thread subtree.
 * If flags == MN_NONE then we just count the messages instead of whether
 * the messages have a flag set.
 *
 * Watch out when calling this. The thrd->branch is not part of thrd.
 * Branch is a sibling to thrd, not a child. Zero out branch before calling
 * or call on thrd->next and worry about thrd separately.
 * Ok to call it on top-level thread which has no branch already.
 */
unsigned long
count_lflags_in_thread(MAILSTREAM *stream, PINETHRD_S *thrd, MSGNO_S *msgmap, int flags)
{
    unsigned long count = 0;
    PINETHRD_S *nthrd, *bthrd;

    if(!thrd || !stream || thrd->rawno < 1L || thrd->rawno > stream->nmsgs)
      return count;

    if(thrd->next){
	nthrd = fetch_thread(stream, thrd->next);
	if(nthrd)
	  count += count_lflags_in_thread(stream, nthrd, msgmap, flags);
    }

    if(thrd->branch){
	bthrd = fetch_thread(stream, thrd->branch);
	if(bthrd)
	  count += count_lflags_in_thread(stream, bthrd, msgmap,flags);
    }

    if(flags == MN_NONE)
      count++;
    else
      count += get_lflag(stream, msgmap, mn_raw2m(msgmap, thrd->rawno), flags);

    return count;
}


/*
 * Special-purpose for performance improvement.
 */
int
thread_has_some_visible(MAILSTREAM *stream, PINETHRD_S *thrd)
{
    PINETHRD_S *nthrd, *bthrd;

    if(!thrd || !stream || thrd->rawno < 1L || thrd->rawno > stream->nmsgs)
      return 0;

    if(get_lflag(stream, NULL, thrd->rawno, MN_HIDE) == 0)
      return 1;

    if(thrd->next){
	nthrd = fetch_thread(stream, thrd->next);
	if(nthrd && thread_has_some_visible(stream, nthrd))
	  return 1;
    }

    if(thrd->branch){
	bthrd = fetch_thread(stream, thrd->branch);
	if(bthrd && thread_has_some_visible(stream, bthrd))
	  return 1;
    }

    return 0;
}


int
mark_msgs_in_thread(MAILSTREAM *stream, PINETHRD_S *thrd, MSGNO_S *msgmap)
{
    int           count = 0;
    long          next, branch;
    PINETHRD_S   *nthrd, *bthrd;
    MESSAGECACHE *mc;

    if(!thrd || !stream || thrd->rawno < 1L || thrd->rawno > stream->nmsgs)
      return count;

    if(next = get_next(stream, thrd)){
	nthrd = fetch_thread(stream, next);
	if(nthrd)
	  count += mark_msgs_in_thread(stream, nthrd, msgmap);
    }

    if(branch = get_branch(stream, thrd)){
	bthrd = fetch_thread(stream, branch);
	if(bthrd)
	  count += mark_msgs_in_thread(stream, bthrd, msgmap);
    }

    if(stream && thrd->rawno >= 1L && thrd->rawno <= stream->nmsgs &&
       (mc = mail_elt(stream,thrd->rawno))
       && !mc->sequence
       && !mc->private.msg.env){
	mc->sequence = 1;
	count++;
    }

    return count;
}


/*
 * This sets or clears flags for the messages at this node and below in
 * a tree.
 *
 * Watch out when calling this. The thrd->branch is not part of thrd.
 * Branch is a sibling to thrd, not a child. Zero out branch before calling
 * or call on thrd->next and worry about thrd separately.
 * Ok to call it on top-level thread which has no branch already.
 */
void
set_thread_lflags(MAILSTREAM *stream, PINETHRD_S *thrd, MSGNO_S *msgmap, int flags, int v)
                       
                     
                       
                      		/* flags to set or clear */
                  		/* set or clear? */
{
    unsigned long msgno, next, branch;
    PINETHRD_S *nthrd, *bthrd;

    if(!thrd || !stream || thrd->rawno < 1L || thrd->rawno > stream->nmsgs)
      return;

    msgno = mn_raw2m(msgmap, thrd->rawno);

    set_lflag(stream, msgmap, msgno, flags, v);

    /*
     * Careful, performance hack. This should logically be a separate
     * operation on the thread but it is convenient to stick it in here.
     *
     * When we back out of viewing a thread to the separate-thread-index
     * we may leave behind some cached hlines that aren't quite right
     * because they were collapsed. In particular, the plus_col character
     * may be wrong. Instead of trying to figure out what it should be just
     * clear the cache entries for the this thread when we come back in
     * to view it again.
     */
    if(msgno > 0L && flags == MN_CHID2 && v == 1)
      clear_index_cache_ent(stream, msgno, 0);

    if(next = get_next(stream, thrd)){
	nthrd = fetch_thread(stream, next);
	if(nthrd)
	  set_thread_lflags(stream, nthrd, msgmap, flags, v);
    }

    if(branch = get_branch(stream,thrd)){
	bthrd = fetch_thread(stream, branch);
	if(bthrd)
	  set_thread_lflags(stream, bthrd, msgmap, flags, v);
    }
}


char
status_symbol_for_thread(MAILSTREAM *stream, PINETHRD_S *thrd, IndexColType type)
{
    char        status = ' ';
    unsigned long save_branch, cnt, tot_in_thrd;

    if(!thrd || !stream || thrd->rawno < 1L || thrd->rawno > stream->nmsgs)
      return status;

    save_branch = thrd->branch;
    thrd->branch = 0L;		/* branch is a sibling, not part of thread */
    
    /*
     * This is D if all of thread is deleted,
     * else A if all of thread is answered,
     * else F if all of thread is forwarded,
     * else N if any unseen and not deleted,
     * else blank.
     */
    if(type == iStatus){
	tot_in_thrd = count_flags_in_thread(stream, thrd, F_NONE);
	/* all deleted */
	if(count_flags_in_thread(stream, thrd, F_DEL) == tot_in_thrd)
	  status = 'D';
	/* all answered */
	else if(count_flags_in_thread(stream, thrd, F_ANS) == tot_in_thrd)
	  status = 'A';
	/* all forwarded */
	else if(count_flags_in_thread(stream, thrd, F_FWD) == tot_in_thrd)
	  status = 'F';
	/* or any new and not deleted */
	else if((!IS_NEWS(stream)
		 || F_ON(F_FAKE_NEW_IN_NEWS, ps_global))
		&& count_flags_in_thread(stream, thrd, F_UNDEL|F_UNSEEN))
	  status = 'N';
    }
    else if(type == iFStatus){
	if(!IS_NEWS(stream) || F_ON(F_FAKE_NEW_IN_NEWS, ps_global)){
	    tot_in_thrd = count_flags_in_thread(stream, thrd, F_NONE);
	    cnt = count_flags_in_thread(stream, thrd, F_UNSEEN);
	    if(cnt)
	      status = (cnt == tot_in_thrd) ? 'N' : 'n';
	}
    }
    else if(type == iIStatus || type == iSIStatus){
	tot_in_thrd = count_flags_in_thread(stream, thrd, F_NONE);

	/* unseen and recent */
	cnt = count_flags_in_thread(stream, thrd, F_RECENT|F_UNSEEN);
	if(cnt)
	  status = (cnt == tot_in_thrd) ? 'N' : 'n';
	else{
	    /* unseen and !recent */
	    cnt = count_flags_in_thread(stream, thrd, F_UNSEEN);
	    if(cnt)
	      status = (cnt == tot_in_thrd) ? 'U' : 'u';
	    else{
		/* seen and recent */
		cnt = count_flags_in_thread(stream, thrd, F_RECENT|F_SEEN);
		if(cnt)
		  status = (cnt == tot_in_thrd) ? 'R' : 'r';
	    }
	}
    }

    thrd->branch = save_branch;

    return status;
}


/*
 * Symbol is * if some message in thread is important,
 * + if some message is to us,
 * - if mark-for-cc and some message is cc to us, 
 * . if mark-for-group and some message is to us in a group, else blank.
 */
char
to_us_symbol_for_thread(MAILSTREAM *stream, PINETHRD_S *thrd, int consider_flagged)
{
    char        to_us = ' ';
    char        branch_to_us = ' ';
    PINETHRD_S *nthrd, *bthrd;
    unsigned long next = 0L, branch = 0L;
    MESSAGECACHE *mc;

    if(!thrd || !stream || thrd->rawno < 1L || thrd->rawno > stream->nmsgs)
      return to_us;

    if(next = get_next(stream,thrd)){
	nthrd = fetch_thread(stream, next);
	if(nthrd)
	  to_us = to_us_symbol_for_thread(stream, nthrd, consider_flagged);
    }

    if(((consider_flagged && to_us != '*') || (!consider_flagged && to_us != '+'))
       && (branch = get_branch(stream, thrd))){
	bthrd = fetch_thread(stream, thrd->branch);
	if(bthrd)
	  branch_to_us = to_us_symbol_for_thread(stream, bthrd, consider_flagged);

	/* use branch to_us symbol if it has higher priority than what we have so far */
	if(to_us == ' '){
	    if(branch_to_us == '-' || branch_to_us == '+' 
		|| branch_to_us == '.' || branch_to_us == '*')
	      to_us = branch_to_us;
	}
	else if(to_us == '-'){
	    if(branch_to_us == '+' || branch_to_us == '.' || branch_to_us == '*')
	      to_us = branch_to_us;
	}
	else if(to_us == '+' || to_us == '.'){
	    if(branch_to_us == '*')
	      to_us = branch_to_us;
	}
    }

    if((consider_flagged && to_us != '*') 
		|| (!consider_flagged && to_us != '+' && to_us != '.')){
	if(consider_flagged && thrd && thrd->rawno > 0L
	   && stream && thrd->rawno <= stream->nmsgs
	   && (mc = mail_elt(stream, thrd->rawno))
	   && FLAG_MATCH(F_FLAG, mc, stream))
	  to_us = '*';
	else if(to_us != '+' && to_us != '.' && !IS_NEWS(stream)){
	    INDEXDATA_S   idata;
	    MESSAGECACHE *mc;
	    ADDRESS      *addr;

	    memset(&idata, 0, sizeof(INDEXDATA_S));
	    idata.stream   = stream;
	    idata.rawno    = thrd->rawno;
	    idata.msgno    = mn_raw2m(sp_msgmap(stream), idata.rawno);
	    if(idata.rawno > 0L && stream && idata.rawno <= stream->nmsgs
	       && (mc = mail_elt(stream, idata.rawno))){
		idata.size = mc->rfc822_size;
		index_data_env(&idata,
			       pine_mail_fetchenvelope(stream, idata.rawno));
	    }
	    else
	      idata.bogus = 2;

	    for(addr = fetch_to(&idata); addr; addr = addr->next)
	      if(address_is_us(addr, ps_global)){
		  to_us = '+';
		  break;
	      }
	    
	    if(to_us != '+' && !idata.bogus && resent_to_us(&idata))
	      to_us = '+';

	    if(to_us == ' ' && F_ON(F_MARK_FOR_CC,ps_global))
	      for(addr = fetch_cc(&idata); addr; addr = addr->next)
		if(address_is_us(addr, ps_global)){
		    to_us = '-';
		    break;
		}
	}
    }

    return to_us;
}


/*
 * This sets or clears flags for the messages at this node and below in
 * a tree. It doesn't just blindly do it, perhaps it should. Instead,
 * when un-hiding a subtree it leaves the sub-subtree hidden if a node
 * is collapsed.
 *
 * Watch out when calling this. The thrd->branch is not part of thrd.
 * Branch is a sibling to thrd, not a child. Zero out branch before calling
 * or call on thrd->next and worry about thrd separately.
 * Ok to call it on top-level thread which has no branch already.
 */
void
set_thread_subtree(MAILSTREAM *stream, PINETHRD_S *thrd, MSGNO_S *msgmap, int v, int flags)
                       
                     
                       
                  		/* set or clear? */
                      		/* flags to set or clear */
{
    int hiding;
    unsigned long msgno;
    PINETHRD_S *nthrd, *bthrd;

    hiding = (flags == MN_CHID) && v;

    if(!thrd || !stream || thrd->rawno < 1L || thrd->rawno > stream->nmsgs)
      return;

    msgno = mn_raw2m(msgmap, thrd->rawno);

    set_lflag(stream, msgmap, msgno, flags, v);

    if(thrd->next
	 && (hiding || !get_lflag(stream,NULL,thrd->rawno,MN_COLL))){
	nthrd = fetch_thread(stream, thrd->next);
	if(nthrd)
	  set_thread_subtree(stream, nthrd, msgmap, v, flags);
    }

    if(thrd->branch){
	bthrd = fetch_thread(stream, thrd->branch);
	if(bthrd)
	  set_thread_subtree(stream, bthrd, msgmap, v, flags);
    }
}


/*
 * View a thread. Move from the thread index screen to a message index
 * screen for the current thread.
 *
 *      set_lflags - Set the local flags appropriately to start viewing
 *                   the thread. We would not want to set this if we are
 *                   already viewing the thread (and expunge or new mail
 *                   happened) and we want to preserve the collapsed state
 *                   of the subthreads.
 */
int
view_thread(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap, int set_lflags)
{
    PINETHRD_S   *thrd = NULL;
    unsigned long rawno, cur;

    if(!any_messages(msgmap, NULL, "to View"))
      return 0;

    if(!(stream && msgmap))
      return 0;

    rawno = mn_m2raw(msgmap, mn_get_cur(msgmap));
    if(rawno)
      thrd = fetch_thread(stream, rawno);

    if(thrd && thrd->top && top_thread(stream,thrd->top) != thrd->rawno)
      thrd = fetch_thread(stream, top_thread(stream,thrd->top));
    
    if(!thrd)
      return 0;
    
    /*
     * Clear hidden and collapsed flag for this thread.
     * And set CHID2.
     * Don't have to worry about there being a branch because
     * this is a toplevel thread.
     */
    if(set_lflags){
	set_thread_lflags(stream, thrd, msgmap, MN_COLL | MN_CHID, 0);
	set_thread_lflags(stream, thrd, msgmap, MN_CHID2, 1);
    }

    /*
     * If this is one of those wacky users who like to sort backwards
     * they would probably prefer that the current message be the last
     * one in the thread (the one highest up the screen).
     */
    if(mn_get_revsort(msgmap)){
	cur = mn_get_cur(msgmap);
	while(cur > 1L && get_lflag(stream, msgmap, cur-1L, MN_CHID2))
	  cur--;

	if(cur != mn_get_cur(msgmap))
	  mn_set_cur(msgmap, cur);
    }

    /* first message in thread might be hidden if zoomed */
    if(any_lflagged(msgmap, MN_HIDE)){
	cur = mn_get_cur(msgmap);
	while(get_lflag(stream, msgmap, cur, MN_HIDE))
          cur++;
	
	if(cur != mn_get_cur(msgmap))
	  mn_set_cur(msgmap, cur);
    }

    msgmap->top = mn_get_cur(msgmap);
    sp_set_viewing_a_thread(stream, 1);

    state->mangled_screen = 1;
    setup_for_index_index_screen();

    return 1;
}


int
unview_thread(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap)
{
    PINETHRD_S   *thrd = NULL, *topthrd = NULL;
    unsigned long rawno;

    if(!(stream && msgmap))
      return 0;

    rawno = mn_m2raw(msgmap, mn_get_cur(msgmap));
    if(rawno)
      thrd = fetch_thread(stream, rawno);
    
    if(thrd && thrd->top)
      topthrd = fetch_thread(stream, top_thread(stream,thrd->top));
    
    if(!topthrd)
      return 0;

    /* hide this thread */
    set_thread_lflags(stream, topthrd, msgmap, MN_CHID, 1);

    /* clear special CHID2 flags for this thread */
    set_thread_lflags(stream, topthrd, msgmap, MN_CHID2, 0);

    /* clear CHID for top-level message and set COLL */
    set_lflag(stream, msgmap, mn_raw2m(msgmap, topthrd->rawno), MN_CHID, 0);
    set_lflag(stream, msgmap, mn_raw2m(msgmap, topthrd->rawno), MN_COLL, 1);

    mn_set_cur(msgmap, mn_raw2m(msgmap, topthrd->rawno));
    sp_set_viewing_a_thread(stream, 0);
    setup_for_thread_index_screen();

    return 1;
}


PINETHRD_S *
find_thread_by_number(MAILSTREAM *stream, MSGNO_S *msgmap, long int target, PINETHRD_S *startthrd)
{
    PINETHRD_S *thrd = NULL;

    if(!(stream && msgmap))
      return(thrd);

    thrd = startthrd;
    
    if(!thrd || !(thrd->prevthd || thrd->nextthd))
      thrd = fetch_thread(stream, mn_m2raw(msgmap, mn_get_cur(msgmap)));

    if(thrd && !(thrd->prevthd || thrd->nextthd) && thrd->head)
      thrd = fetch_thread(stream, thrd->head);

    if(thrd){
	/* go forward from here */
	if(thrd->thrdno < target){
	    while(thrd){
		if(thrd->thrdno == target)
		  break;

		if(mn_get_revsort(msgmap) && thrd->prevthd)
		  thrd = fetch_thread(stream, thrd->prevthd);
		else if(!mn_get_revsort(msgmap) && thrd->nextthd)
		  thrd = fetch_thread(stream, thrd->nextthd);
		else
		  thrd = NULL;
	    }
	}
	/* back up from here */
	else if(thrd->thrdno > target
		&& (mn_get_revsort(msgmap)
		    || (thrd->thrdno - target) < (target - 1L))){
	    while(thrd){
		if(thrd->thrdno == target)
		  break;

		if(mn_get_revsort(msgmap) && thrd->nextthd)
		  thrd = fetch_thread(stream, thrd->nextthd);
		else if(!mn_get_revsort(msgmap) && thrd->prevthd)
		  thrd = fetch_thread(stream, thrd->prevthd);
		else
		  thrd = NULL;
	    }
	}
	/* go forward from head */
	else if(thrd->thrdno > target){
	    if(thrd->head){
		thrd = fetch_thread(stream, thrd->head);
		while(thrd){
		    if(thrd->thrdno == target)
		      break;

		    if(thrd->nextthd)
		      thrd = fetch_thread(stream, thrd->nextthd);
		    else
		      thrd = NULL;
		}
	    }
	}
    }

    return(thrd);
}


/*
 * Set search bit for every message in a thread.
 *
 * Watch out when calling this. The thrd->branch is not part of thrd.
 * Branch is a sibling to thrd, not a child. Zero out branch before calling
 * or call on thrd->next and worry about thrd separately. Top-level threads
 * already have a branch equal to zero.
 *
 *  If msgset is non-NULL, then only set the search bit for a message if that
 *  message is included in the msgset.
 */
void
set_search_bit_for_thread(MAILSTREAM *stream, PINETHRD_S *thrd, SEARCHSET **msgset)
{
    PINETHRD_S *nthrd, *bthrd;
    unsigned long next, branch;

    if(!(stream && thrd))
      return;

    if(thrd->rawno > 0L && thrd->rawno <= stream->nmsgs
       && (!(msgset && *msgset) || in_searchset(*msgset, thrd->rawno)))
      mm_searched(stream, thrd->rawno);

    if(next= get_next(stream, thrd)){
	nthrd = fetch_thread(stream, next);
	if(nthrd)
	  set_search_bit_for_thread(stream, nthrd, msgset);
    }

    if(branch = get_branch(stream, thrd)){
	bthrd = fetch_thread(stream, branch);
	if(bthrd)
	  set_search_bit_for_thread(stream, bthrd, msgset);
    }
}

/*
 * Make a copy of c-client's THREAD tree
 */
THREADNODE *
copy_tree(THREADNODE *tree)
{
    THREADNODE *newtree = NULL;

    if(tree){
        newtree = mail_newthreadnode(NULL);
        newtree->num  = tree->num;
        if(tree->next)
           newtree->next = copy_tree(tree->next);

        if(tree->branch)
           newtree->branch = copy_tree(tree->branch);
    }
    return(newtree);
}

long
top_thread(MAILSTREAM *stream, long rawmsgno)
{
     PINETHRD_S   *thrd = NULL;
     unsigned long rawno;

     if(!stream)
       return -1L;

     if(rawmsgno)
       thrd = fetch_thread(stream, rawmsgno);

     if(!thrd)
       return -1L;

     return F_ON(F_ENHANCED_THREAD, ps_global) 
		? (thrd->toploose ? thrd->toploose : thrd->top)
		: thrd->top;
}

void
move_top_thread(MAILSTREAM *stream, MSGNO_S *msgmap, long rawmsgno)
{
    mn_set_cur(msgmap,mn_raw2m(msgmap, top_thread(stream, rawmsgno)));
}

long
top_this_thread(MAILSTREAM *stream, long rawmsgno)
{
     PINETHRD_S   *thrd = NULL;
     unsigned long rawno;

     if(!stream)
       return -1L;

     if(rawmsgno)
       thrd = fetch_thread(stream, rawmsgno);

     if(!thrd)
       return -1L;

     return thrd->top;
}

void
move_top_this_thread(MAILSTREAM *stream, MSGNO_S *msgmap, long rawmsgno)
{
    mn_set_cur(msgmap,mn_raw2m(msgmap, top_this_thread(stream, rawmsgno)));
}

int
thread_is_kolapsed(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap, long rawmsgno)
{
    int          collapsed;
    PINETHRD_S   *thrd = NULL;
    unsigned long rawno, orig, orig_rawno;

    if(!stream)
      return -1;

    orig = mn_get_cur(msgmap);
    move_top_thread(stream, msgmap, rawmsgno);
    rawno = orig_rawno = mn_m2raw(msgmap, mn_get_cur(msgmap));
    if(rawno)
      thrd = fetch_thread(stream, rawno);

    if(!thrd)
      return -1;
    
    while(collapsed = this_thread_is_kolapsed(state, stream, msgmap, rawno))
       if (F_OFF(F_ENHANCED_THREAD, state)
          || (move_next_this_thread(state, stream, msgmap, 0) <= 0)
	  || !(rawno = mn_m2raw(msgmap, mn_get_cur(msgmap)))
	  || (orig_rawno != top_thread(stream, rawno)))
	break;

    mn_set_cur(msgmap,orig); /* return home */

    return collapsed;
}

/* this function tells us if the thread (or branch in the case of loose threads)
 * is collapsed
 */

int
this_thread_is_kolapsed(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap, long rawmsgno)
{
    int          collapsed;
    PINETHRD_S   *thrd = NULL;
    unsigned long rawno, orig;

    if(!stream)
      return -1;

    rawno = rawmsgno;
    if(rawno)
      thrd = fetch_thread(stream, rawno);

    if(!thrd)
      return -1;

    collapsed = get_lflag(stream, NULL, rawno, MN_COLL | MN_CHID);

    if (!thrd->next){
      if (thrd->rawno != top_thread(stream, thrd->rawno))
	collapsed = get_lflag(stream, NULL, rawno,  MN_CHID);
      else
	collapsed = get_lflag(stream, NULL, rawno,  MN_COLL);
    }

    return collapsed;
}

/* 
 * This function assumes that it is called at a top of a thread in its 
 * first call
 */

int
count_this_thread(MAILSTREAM *stream, unsigned long rawno)
{
    unsigned long top, orig_top, topnxt;
    PINETHRD_S   *thrd = NULL;
    int count = 1;

    if(!stream)
      return 0;

    if(rawno)
      thrd = fetch_thread(stream, rawno);

    if(!thrd)
      return 0;

    if (thrd->next)
       count += count_this_thread(stream, thrd->next);

    if (thrd->branch)
       count += count_this_thread(stream, thrd->branch);

    return count;
}

int
count_thread(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap, long rawno)
{
    unsigned long top, orig, orig_top;
    PINETHRD_S   *thrd = NULL;
    int done = 0, count = 0;

    if(!stream)
      return 0;

    orig = mn_m2raw(msgmap, mn_get_cur(msgmap));
    move_top_thread(stream, msgmap,rawno);
    top =  orig_top = top_thread(stream, rawno);
    if(top)
      thrd = fetch_thread(stream, top);

    if(!thrd)
      return 0;

    while (!done){
      count += count_this_thread(stream, top);
      if (F_OFF(F_ENHANCED_THREAD, state)
         || (move_next_this_thread(state, stream, msgmap, 0) <= 0)
	 || !(top = mn_m2raw(msgmap, mn_get_cur(msgmap)))
	 || (orig_top != top_thread(stream, top)))
	 done++;
    }
    mn_set_cur(msgmap,mn_raw2m(msgmap, orig));
    return count;
}

unsigned long
get_branch(MAILSTREAM *stream, PINETHRD_S *thrd)
{
  PINETHRD_S *nthrd = NULL;
  unsigned long top;
 
  if (thrd->toploose && thrd->nextthd)
    nthrd = fetch_thread(stream, thrd->nextthd);
  if (!nthrd)
    return thrd->branch;
  top = top_thread(stream, thrd->rawno);
  return thrd->branch 
	   ? thrd->branch 
	   : (F_ON(F_ENHANCED_THREAD, ps_global) 
		? (top == top_thread(stream, nthrd->rawno) ? thrd->nextthd : 0L)
		: 0L);
}

unsigned long
get_next(MAILSTREAM *stream, PINETHRD_S *thrd)
{
  return thrd->next;
}

long
get_length_branch(MAILSTREAM *stream, long rawno)
{
  int branchp = 0, done = 0;
  long top, count = 1L, raw;
  PINETHRD_S *thrd, *pthrd = NULL, *nthrd;

  thrd = fetch_thread(stream, rawno);

  if (!thrd)
    return -1L;

  top = thrd->top;

  if (thrd->parent)
    pthrd = fetch_thread(stream, thrd->parent);

  if (thrd->rawno == top)
     branchp++;

  if (!branchp && !pthrd){	/* what!!?? */
     raw = top;
     while (!done){
        pthrd = fetch_thread(stream, raw);
        if ((pthrd->next == rawno) || (pthrd->branch == rawno))
           done++;
        else{
	   if (pthrd->next)
	      raw = pthrd->next;
	   else if (pthrd->branch)
	      raw = pthrd->branch;
	}
     }
  }

  if (pthrd && pthrd->next == thrd->rawno && thrd->branch)
     branchp++;

  if (pthrd && pthrd->next && pthrd->next != thrd->rawno){
     nthrd = fetch_thread(stream, pthrd->next);
     while (nthrd && nthrd->branch && nthrd->branch != thrd->rawno)
	nthrd = fetch_thread(stream, nthrd->branch);
     if(nthrd && nthrd->branch && nthrd->branch == thrd->rawno)
	branchp++;
  }

  if(branchp){
    int entry = 0;
    while(thrd && thrd->next){
	entry = 1;
	count++;
	thrd = fetch_thread(stream, thrd->next);
	if (thrd->branch)
	   break;
    }
    if (entry && thrd->branch)
	count--;
  }
  return branchp ? (count ? count : 1L) : 0L;
}

int pine_compare_size_thread(const qsort_t *a, const qsort_t *b)
{
  SIZETHREAD_T *s = (SIZETHREAD_T *) a, *t = (SIZETHREAD_T *) b;

  return s->count == t->count ? s->pos - t->pos : s->count - t->count;
}



void
find_msgmap(MAILSTREAM *stream, MSGNO_S *msgmap, int flags, SortOrder ordersort, unsigned is_rev)
{
   long *old_arrival,*new_arrival;
   long init_thread, end_thread, current;
   long i, j, k;
   long tmsg, ntmsg, nthreads;
   SIZETHREAD_T *l;
   PINETHRD_S *thrd;
 
   erase_thread_info = 0;
   current = mn_m2raw(msgmap, mn_get_cur(msgmap));

   switch(ordersort){
	case SortSize:
	     sort_folder(stream, msgmap, SortThread, 0, SRT_VRB, 0);
	     tmsg = mn_get_total(msgmap) + 1;

	     if(tmsg <= 1)
		return;

	     for (i= 1L, k = 0L; i <= mn_get_total(msgmap); i += count_thread(ps_global, stream, msgmap, msgmap->sort[i]), k++);
	     l = (SIZETHREAD_T *) fs_get(k*sizeof(SIZETHREAD_T));
	     for (j = 0L, i=1L; j < k && i<= mn_get_total(msgmap); ){
		l[j].count = count_thread(ps_global, stream, msgmap, msgmap->sort[i]);
		l[j].pos   = i;
		i += l[j].count;
		j++;
	     }
	     qsort((void *)l, (size_t) k, sizeof(SIZETHREAD_T), pine_compare_size_thread);
	     old_arrival = (long *) fs_get(tmsg * sizeof(long));
	     for(i = 1L, j = 0; j < k; j++){	/* copy thread of length .count */
		int p;
		for(p = 0; p < l[j].count; p++)
		  old_arrival[i++] = msgmap->sort[l[j].pos + p]; 
	     }
	     fs_give((void **)&l);
	     break;
	default:
	     sort_folder(stream, msgmap, ordersort, 0, SRT_VRB, 0);
	     tmsg = mn_get_total(msgmap) + 1;

	     if (tmsg <= 1)
	       return;

	     old_arrival = (long *) fs_get(tmsg * sizeof(long));
	     for (i= 1L;(i <= mn_get_total(msgmap)) && (old_arrival[i] = msgmap->sort[i]); i++);
		   /* sort by thread */
	     sort_folder(stream, msgmap, SortThread, 0, SRT_VRB, 0);
	     break;

   }

   ntmsg = mn_get_total(msgmap) + 1;
   if (tmsg != ntmsg){	/* oh oh, something happened, we better try again */
	fs_give((void **)&old_arrival);
	find_msgmap(stream, msgmap, flags, ordersort, is_rev);
	return;
   }

   /* reconstruct the msgmap */

   new_arrival = (long *) fs_get(tmsg * sizeof(long));
   memset(new_arrival, 0, tmsg*sizeof(long));
   i = mn_get_total(msgmap);
   /* we copy from the bottom, the last one to be filled is new_arrival[1] */
   while (new_arrival[1] == 0){
        int done = 0;
	long n;

        init_thread = top_thread(stream, old_arrival[i]);
	thrd = fetch_thread(stream, init_thread);
        for (n = mn_get_total(msgmap); new_arrival[n] != 0 && !done; n--)
          done = (new_arrival[n] == init_thread);
        if (!done){
	   mn_set_cur(msgmap, mn_raw2m(msgmap, init_thread));
	   if(move_next_thread(ps_global, stream, msgmap, 0) <= 0)
	 	j = mn_get_total(msgmap) - mn_raw2m(msgmap, init_thread) + 1;
	   else
		j = mn_get_cur(msgmap) - mn_raw2m(msgmap, init_thread);
           end_thread = mn_raw2m(msgmap, init_thread) + j;
           for(k = 1L; k <= j; k++)
              new_arrival[tmsg - k] = msgmap->sort[end_thread - k];
           tmsg -= j;
       }
       i--;
   }
   relink_threads(stream, msgmap, new_arrival);
   for (i = 1; (i <= mn_get_total(msgmap)) 
		&&  (msgmap->sort[i] = new_arrival[i]); i++);
   msgno_reset_isort(msgmap);

   fs_give((void **)&new_arrival);
   fs_give((void **)&old_arrival);


   if(is_rev && (mn_get_total(msgmap) > 1L)){
      long *rev_sort;
      long i = 1L, l = mn_get_total(msgmap);

      rev_sort = (long *) fs_get((mn_get_total(msgmap)+1L) * sizeof(long));
      memset(rev_sort, 0, (mn_get_total(msgmap)+1L)*sizeof(long));
      while (l > 0L){
	 if (top_thread(stream, msgmap->sort[l]) == msgmap->sort[l]){
	    long init_thread = msgmap->sort[l];
	    long j, k;

	    mn_set_cur(msgmap, mn_raw2m(msgmap, init_thread));
	    if (move_next_thread(ps_global, stream, msgmap, 0) <= 0)
	 	j = mn_get_total(msgmap) - mn_raw2m(msgmap, init_thread) + 1;
	    else
		j = mn_get_cur(msgmap) - mn_raw2m(msgmap, init_thread);
	    for (k = 0L; (k < j) && (rev_sort[i+k] = msgmap->sort[l+k]); k++);
	    i += j;
	 }
	 l--;
      }
      relink_threads(stream, msgmap, rev_sort);
      for (i = 1L; i <=  mn_get_total(msgmap); i++)
        msgmap->sort[i] = rev_sort[i];
      msgno_reset_isort(msgmap);
      fs_give((void **)&rev_sort);
   }
   mn_reset_cur(msgmap, first_sorted_flagged(is_rev ? F_NONE : F_SRCHBACK,
			stream, mn_raw2m(msgmap, current), FSF_SKIP_CHID));
   msgmap->top = -1L;

   sp_set_unsorted_newmail(ps_global->mail_stream, 0);

   for(i = 1L; i <= ps_global->mail_stream->nmsgs; i++)
      mail_elt(ps_global->mail_stream, i)->spare7 = 0;

   mn_set_sort(msgmap, SortThread);
   mn_set_revsort(msgmap, is_rev);
   erase_thread_info = 1;
   clear_index_cache(stream, 0);
}

void
move_thread(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap, int direction)
{
  long new_cursor, old_cursor = mn_get_cur(msgmap);
  int rv;
  PINETHRD_S *thrd;

   rv = direction > 0 ? move_next_thread(state, stream, msgmap, 1):
			move_prev_thread(state, stream, msgmap, 1);
   if (rv > 0 && THRD_INDX_ENABLED()){
       new_cursor = mn_get_cur(msgmap);
       mn_set_cur(msgmap, old_cursor);
       unview_thread(state, stream, msgmap);
       thrd = fetch_thread(stream,mn_m2raw(msgmap, new_cursor));
       mn_set_cur(msgmap, new_cursor);
       view_thread(state, stream, msgmap, 1);
       state->next_screen = SCREEN_FUN_NULL;
   }
}

void
relink_threads(MAILSTREAM *stream, MSGNO_S *msgmap, long *new_arrival)
{
   long last_thread = 0L;
   long i = 0L, j = 1L, k;
   PINETHRD_S *thrd, *nthrd;

   while (j <= mn_get_total(msgmap)){ 
	i++;
	thrd = fetch_thread(stream, new_arrival[j]);
	if (!thrd)  /* sort failed!, better leave from here now!!! */
	   break;
	thrd->prevthd = last_thread;
	thrd->thrdno  = i;
	thrd->head    = new_arrival[1];
	last_thread = thrd->rawno;
	mn_set_cur(msgmap, mn_raw2m(msgmap,thrd->top));
	k = mn_get_cur(msgmap);
	if  (move_next_thread(ps_global, stream, msgmap, 0) <= 0)
	    j += mn_get_total(msgmap) + 1 - k;
	else
	    j += mn_get_cur(msgmap) - k;
	if (!thrd->toploose)
	   thrd->nextthd = (j <= mn_get_total(msgmap)) ? new_arrival[j] : 0L;
	else{
	  int done = 0;
	  while(thrd->nextthd && !done){
	      thrd->thrdno = i;
	      thrd->head    = new_arrival[1];
	      if (thrd->nextthd)
		 nthrd = fetch_thread(stream, thrd->nextthd);
	      else
		done++;
	      if(top_thread(stream, thrd->rawno) == top_thread(stream, nthrd->rawno))
		thrd = nthrd;
	      else
		done++;
	  }
	  thrd->nextthd = (j <= mn_get_total(msgmap)) ? new_arrival[j] : 0L;
	  last_thread = thrd->rawno;
	}
   }
}

int
move_next_this_thread(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap, int display)
{
    PINETHRD_S   *thrd = NULL, *thrdnxt;
    unsigned long rawno, top;
    int       rv = 1;

    if(!stream)
       return -1;

    rawno = mn_m2raw(msgmap, mn_get_cur(msgmap));
    if(rawno)
      thrd = fetch_thread(stream, rawno);

    if(!thrd)
      return -1;

   top = top_thread(stream, rawno);

   thrdnxt = (top == rawno) ? fetch_thread(stream, top) : thrd;
   if (thrdnxt->nextthd)
       mn_set_cur(msgmap,mn_raw2m(msgmap, thrdnxt->nextthd));
   else{
       rv = 0;
       if (display)
         q_status_message(SM_ORDER, 0, 1, "No more Threads to advance");
   }
   return rv;
}

int
move_next_thread(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap, int display)
{
    int collapsed, rv = 1, done = 0;
    PINETHRD_S   *thrd = NULL;
    unsigned long orig, orig_top, top;

    if(!stream)
      return 0;

    orig = mn_m2raw(msgmap, mn_get_cur(msgmap));
    move_top_thread(stream, msgmap,orig);
    top = orig_top = mn_m2raw(msgmap, mn_get_cur(msgmap));

    if(top)
      thrd = fetch_thread(stream, top);

    if(!thrd)
      return 0;

    while (rv > 0 && !done){
      rv = move_next_this_thread(state, stream, msgmap, display);
      if (F_OFF(F_ENHANCED_THREAD, state)
         || !(top = mn_m2raw(msgmap, mn_get_cur(msgmap)))
         || (orig_top != top_thread(stream, top)))
         done++;
    }
    if (display){
        if (rv > 0 && SEP_THRDINDX())
           q_status_message(SM_ORDER, 0, 2, "Viewing next thread");
        if (!rv)
           q_status_message(SM_ORDER, 0, 2, "No more threads to advance");
    }
    if(rv <= 0){
       rv = 0;
       mn_set_cur(msgmap, mn_raw2m(msgmap, orig));
    }

   return rv;
}

int
move_prev_thread(struct pine *state, MAILSTREAM *stream, MSGNO_S *msgmap, int display)
{
    PINETHRD_S   *thrd = NULL;
    unsigned long rawno, top;
    int rv = 1;

    if(!stream)
      return -1;

    rawno = mn_m2raw(msgmap, mn_get_cur(msgmap));
    if(rawno)
      thrd = fetch_thread(stream, rawno);

    if(!thrd)
       return -1;

    top = top_thread(stream, rawno);

    if (top != rawno)
       mn_set_cur(msgmap,mn_raw2m(msgmap, top));
    else if (thrd->prevthd)
       mn_set_cur(msgmap,mn_raw2m(msgmap, top_thread(stream,thrd->prevthd)));
    else
      rv = 0;
    if (display){
        if (rv && SEP_THRDINDX())
           q_status_message(SM_ORDER, 0, 2, "Viewing previous thread");
        if (!rv)
           q_status_message(SM_ORDER, 0, 2, "No more threads to go back");
    }

    return rv;
}

/* add more keys to this list */
int
allowed_thread_key(SortOrder sort)
{
  return sort == SortArrival || sort == SortDate
	  || sort == SortScore || sort == SortThread
	  || sort == SortSize;
}

