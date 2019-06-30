/* This file is part of GNU Rush.
   Copyright (C) 2006-2019 Sergey Poznyakoff.
   (using my implementation for the GNU tar).

   GNU Rush is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GNU Rush is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Rush.  If not, see <http://www.gnu.org/licenses/>. */

#include <rush.h>

enum transform_type
  {
    transform_first,
    transform_global
  };

enum replace_segm_type
  {
    segm_literal,   /* Literal segment */
    segm_backref,   /* Back-reference segment */
    segm_case_ctl   /* Case control segment (GNU extension) */
  };

enum case_ctl_type
  {
    ctl_stop,       /* Stop case conversion */ 
    ctl_upcase_next,/* Turn the next character to uppercase */ 
    ctl_locase_next,/* Turn the next character to lowercase */
    ctl_upcase,     /* Turn the replacement to uppercase until ctl_stop */
    ctl_locase      /* Turn the replacement to lowercase until ctl_stop */
  };

struct replace_segm
{
  struct replace_segm *next;
  enum replace_segm_type type;
  union
  {
    struct
    {
      char *ptr;
      size_t size;
    } literal;                /* type == segm_literal */   
    size_t ref;               /* type == segm_backref */
    enum case_ctl_type ctl;   /* type == segm_case_ctl */ 
  } v;
};

struct transform
{
  struct transform *next;
  enum transform_type transform_type;
  unsigned match_number;
  regex_t regex;
  /* Compiled replacement expression */
  struct replace_segm *repl_head, *repl_tail;
  size_t segm_count; /* Number of elements in the above list */
};

struct transform_list
{
  struct transform *head, *tail;
};
	

static struct transform *
new_transform (struct transform_list *tlist)
{
  struct transform *p = xzalloc (sizeof *p);
  if (tlist->tail)
    tlist->tail->next = p;
  else
    tlist->head = p;
  tlist->tail = p;
  return p;
}

static struct replace_segm *
add_segment (struct transform *tf)
{
  struct replace_segm *segm = xmalloc (sizeof *segm);
  segm->next = NULL;
  if (tf->repl_tail)
    tf->repl_tail->next = segm;
  else
    tf->repl_head = segm;
  tf->repl_tail = segm;
  tf->segm_count++;
  return segm;
}

static void
add_literal_segment (struct transform *tf, char *str, char *end)
{
  size_t len = end - str;
  if (len)
    {
      struct replace_segm *segm = add_segment (tf);
      segm->type = segm_literal;
      segm->v.literal.ptr = xmalloc (len + 1);
      memcpy (segm->v.literal.ptr, str, len);
      segm->v.literal.ptr[len] = 0;
      segm->v.literal.size = len;
    }
}

static void
add_char_segment (struct transform *tf, int chr)
{
  struct replace_segm *segm = add_segment (tf);
  segm->type = segm_literal;
  segm->v.literal.ptr = xmalloc (2);
  segm->v.literal.ptr[0] = chr;
  segm->v.literal.ptr[1] = 0;
  segm->v.literal.size = 1;
}

static void
add_backref_segment (struct transform *tf, size_t ref)
{
  struct replace_segm *segm = add_segment (tf);
  segm->type = segm_backref;
  segm->v.ref = ref;
}

static void
add_case_ctl_segment (struct transform *tf, enum case_ctl_type ctl)
{
  struct replace_segm *segm = add_segment (tf);
  segm->type = segm_case_ctl;
  segm->v.ctl = ctl;
}

static const char *
parse_transform_expr (struct transform_list *tlist, const char *expr,
                      int cflags, struct cfloc *loc)
{
  int delim;
  int i, j, rc;
  char *str, *beg, *cur;
  const char *p;
  struct transform *tf = new_transform (tlist);

  if (expr[0] != 's')
    die_usage (loc, "%s",
	       _("Transform expression must start with 's' followed by a punctuation character"));
  
  delim = expr[1];

  /* Scan regular expression */
  for (i = 2; expr[i] && expr[i] != delim; i++)
    if (expr[i] == '\\' && expr[i+1])
      i++;

  if (expr[i] != delim)
    die_usage (loc,
	       _("Missing 2nd delimiter in position %d of expression %s"),
	       i, expr);
  
  /* Scan replacement expression */
  for (j = i + 1; expr[j] && expr[j] != delim; j++)
    if (expr[j] == '\\' && expr[j+1])
      j++;

  if (expr[j] != delim)
    die_usage (loc,
	       _("Missing trailing delimiter in position %d of expression %s"), 
	       j, expr);

  /* Check flags */
  tf->transform_type = transform_first;
  for (p = expr + j + 1; *p && *p != ';'; p++)
    switch (*p)
      {
      case 'g':
	tf->transform_type = transform_global;
	break;

      case 'i':
	cflags |= REG_ICASE;
	break;

      case 'x':
	cflags |= REG_EXTENDED;
	break;
	
      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
	tf->match_number = strtoul (p, (char**) &p, 0);
	p--;
	break;

      default:
	die_usage (loc, _("Unknown flag in transform expression: %c"), *p);
      }

  if (*p == ';')
    p++;
  
  /* Extract and compile regex */
  str = xmalloc (i - 1);
  memcpy (str, expr + 2, i - 2);
  str[i - 2] = 0;

  rc = regcomp (&tf->regex, str, cflags);
  
  if (rc)
    {
      char errbuf[512];
      regerror (rc, &tf->regex, errbuf, sizeof (errbuf));
      die_usage (loc, _("Invalid transform expression: %s"), errbuf);
    }

  if (str[0] == '^' || str[strlen (str) - 1] == '$')
    tf->transform_type = transform_first;
  
  free (str);

  /* Extract and compile replacement expr */
  i++;
  str = xmalloc (j - i + 1);
  memcpy (str, expr + i, j - i);
  str[j - i] = 0;

  for (cur = beg = str; *cur;)
    {
      if (*cur == '\\')
	{
	  size_t n;
	  
	  add_literal_segment (tf, beg, cur);
	  switch (*++cur)
	    {
	    case '0': case '1': case '2': case '3': case '4':
	    case '5': case '6': case '7': case '8': case '9':
	      n = strtoul (cur, &cur, 10);
	      if (n > tf->regex.re_nsub)
		die_usage (loc,
			   _("Invalid transform replacement: "
			     "back reference out of range"));
	      add_backref_segment (tf, n);
	      break;

	    case '\\':
	      add_char_segment (tf, '\\');
	      cur++;
	      break;

	    case 'a':
	      add_char_segment (tf, '\a');
	      cur++;
	      break;
	      
	    case 'b':
	      add_char_segment (tf, '\b');
	      cur++;
	      break;
	      
	    case 'f':
	      add_char_segment (tf, '\f');
	      cur++;
	      break;
	      
	    case 'n':
	      add_char_segment (tf, '\n');
	      cur++;
	      break;
	      
	    case 'r':
	      add_char_segment (tf, '\r');
	      cur++;
	      break;
	      
	    case 't':
	      add_char_segment (tf, '\t');
	      cur++;
	      break;
	      
	    case 'v':
	      add_char_segment (tf, '\v');
	      cur++;
	      break;

	    case '&':
	      add_char_segment (tf, '&');
	      cur++;
	      break;
	      
	    case 'L':
	      /* Turn the replacement to lowercase until a `\U' or `\E'
		 is found, */
	      add_case_ctl_segment (tf, ctl_locase);
	      cur++;
	      break;
 
	    case 'l':
	      /* Turn the next character to lowercase, */
	      add_case_ctl_segment (tf, ctl_locase_next);
	      cur++;
	      break;
	      
	    case 'U':
	      /* Turn the replacement to uppercase until a `\L' or `\E'
		 is found, */
	      add_case_ctl_segment (tf, ctl_upcase);
	      cur++;
	      break;
	      
	    case 'u':
	      /* Turn the next character to uppercase, */
	      add_case_ctl_segment (tf, ctl_upcase_next);
	      cur++;
	      break;
	      
	    case 'E':
	      /* Stop case conversion started by `\L' or `\U'. */
	      add_case_ctl_segment (tf, ctl_stop);
	      cur++;
	      break;
  
	    default:
	      /* Try to be nice */
	      {
		char buf[2];
		buf[0] = '\\';
		buf[1] = *cur;
		add_literal_segment (tf, buf, buf + 2);
	      }
	      cur++;
	      break;
	    }
	  beg = cur;
	}
      else if (*cur == '&')
	{
	  add_literal_segment (tf, beg, cur);
	  add_backref_segment (tf, 0);
	  beg = ++cur;
	}
      else
	cur++;
    }
  add_literal_segment (tf, beg, cur);

  return p;
}

transform_t 
compile_transform_expr (const char *expr, int cflags, struct cfloc *loc)
{
  struct transform_list tlist = { NULL, NULL };
  while (*expr)
    expr = parse_transform_expr (&tlist, expr, cflags, loc);
  return tlist.head;
}

/* Run case conversion specified by CASE_CTL on array PTR of SIZE
   characters. Returns pointer to statically allocated storage. */
static const char *
run_case_conv (enum case_ctl_type case_ctl, const char *ptr, size_t size)
{
  static char *case_ctl_buffer;
  static size_t case_ctl_bufsize;
  char *p;
  
  if (case_ctl_bufsize < size)
    {
      case_ctl_bufsize = size;
      case_ctl_buffer = xrealloc (case_ctl_buffer, case_ctl_bufsize);
    }
  memcpy (case_ctl_buffer, ptr, size);
  switch (case_ctl)
    {
    case ctl_upcase_next:
      case_ctl_buffer[0] = c_toupper (case_ctl_buffer[0]);
      break;
      
    case ctl_locase_next:
      case_ctl_buffer[0] = c_tolower (case_ctl_buffer[0]);
      break;
      
    case ctl_upcase:
      for (p = case_ctl_buffer; p < case_ctl_buffer + size; p++)
	*p = c_toupper (*p);
      break;
      
    case ctl_locase:
      for (p = case_ctl_buffer; p < case_ctl_buffer + size; p++)
	*p = c_tolower (*p);
      break;

    case ctl_stop:
      break;
    }
  return case_ctl_buffer;
}


void
_single_transform_name_to_slist (struct transform *tf, slist_t slist,
				 const char *input)
{
  regmatch_t *rmp;
  int rc;
  size_t nmatches = 0;
  enum case_ctl_type case_ctl = ctl_stop,  /* Current case conversion op */
                     save_ctl = ctl_stop;  /* Saved case_ctl for \u and \l */
  
  /* Reset case conversion after a single-char operation */
#define CASE_CTL_RESET()  if (case_ctl == ctl_upcase_next     \
			      || case_ctl == ctl_locase_next) \
                            {                                 \
                              case_ctl = save_ctl;            \
                              save_ctl = ctl_stop;            \
			    }
  
  rmp = xmalloc ((tf->regex.re_nsub + 1) * sizeof (*rmp));

  while (*input)
    {
      size_t disp;
      const char *ptr;
      
      rc = regexec (&tf->regex, input, tf->regex.re_nsub + 1, rmp, 0);
      
      if (rc == 0)
	{
	  struct replace_segm *segm;
	  
	  disp = rmp[0].rm_eo;

	  if (rmp[0].rm_so)
	    slist_append (slist, input, rmp[0].rm_so);

	  nmatches++;
	  if (tf->match_number && nmatches < tf->match_number)
	    {
	      slist_append (slist, input, disp);
	      input += disp;
	      continue;
	    }

	  for (segm = tf->repl_head; segm; segm = segm->next)
	    {
	      switch (segm->type)
		{
		case segm_literal:    /* Literal segment */
		  if (case_ctl == ctl_stop)
		    ptr = segm->v.literal.ptr;
		  else
		    {
		      ptr = run_case_conv (case_ctl,
					   segm->v.literal.ptr,
					   segm->v.literal.size);
		      CASE_CTL_RESET();
		    }
		  slist_append (slist, ptr, segm->v.literal.size);
		  break;
	      
		case segm_backref:    /* Back-reference segment */
		  if (rmp[segm->v.ref].rm_so != -1
		      && rmp[segm->v.ref].rm_eo != -1)
		    {
		      size_t size = rmp[segm->v.ref].rm_eo
			              - rmp[segm->v.ref].rm_so;
		      ptr = input + rmp[segm->v.ref].rm_so;
		      if (case_ctl != ctl_stop)
			{
			  ptr = run_case_conv (case_ctl, ptr, size);
			  CASE_CTL_RESET();
			}
		      
		      slist_append (slist, ptr, size);
		    }
		  break;

		case segm_case_ctl:
		  switch (segm->v.ctl)
		    {
		    case ctl_upcase_next:
		    case ctl_locase_next:
		      switch (save_ctl)
			{
			case ctl_stop:
			case ctl_upcase:
			case ctl_locase:
			  save_ctl = case_ctl;
			default:
			  break;
			}
		      /*FALL THROUGH*/
		      
		    case ctl_upcase:
		    case ctl_locase:
		    case ctl_stop:
		      case_ctl = segm->v.ctl;
		    }
		}
	    }
	}
      else
	{
	  disp = strlen (input);
	  slist_append (slist, input, disp);
	}

      input += disp;

      if (tf->transform_type == transform_first)
	{
	  slist_append (slist, input, strlen (input));
	  break;
	}
    }

  free (rmp);
}

char *
transform_string (transform_t tf, const char *input)
{
  if (tf) 
    {
      slist_t slist = slist_create ();
      char *buf = NULL;
      size_t size = 0;
      
      for (; tf; tf = tf->next)
	{
	  _single_transform_name_to_slist (tf, slist, input);
	  input = slist_reduce (slist, &buf, &size);
	}
      slist_free(slist);
    }
  return xstrdup (input);
}
  

