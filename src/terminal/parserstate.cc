/* -*- c-basic-offset:2; tab-width:8 -*- */
/*
    Mosh: the mobile shell
    Copyright 2012 Keith Winstein

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations including
    the two.

    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do
    so, delete this exception statement from your version. If you delete
    this exception statement from all source files in the program, then
    also delete it here.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> /* STDOUT_FILENO */
#include "config.h"
#ifndef USE_WINSOCK
#include <sys/ioctl.h> /* struct winsize */
#endif

#include "parserstate.h"
#include "parserstatefamily.h"

pass_seq_t *cur_ps;

#ifndef USE_WINSOCK
static struct winsize window_size;

/*
 * mosh-server calls set_window_size() but mosh-client doesn't, because
 * mosh-client doesn't parse DRCS-Sixel.
 */
void set_window_size(struct winsize ws) {
#if 0
  FILE *fp = fopen("moshlog.txt", "a");
  fprintf(fp, "Winsize x %d col %d y %d row %d\n",
	  ws.ws_xpixel, ws.ws_col, ws.ws_ypixel, ws.ws_row);
  fclose(fp);
#endif

  window_size = ws;
}
#endif

static int get_cell_size(void) {
#ifndef USE_WINSOCK
  if (window_size.ws_col > 0 && window_size.ws_xpixel > window_size.ws_col &&
      window_size.ws_row > 0 && window_size.ws_ypixel > window_size.ws_row) {
    cur_ps->col_width = window_size.ws_xpixel / window_size.ws_col;
    cur_ps->line_height = window_size.ws_ypixel / window_size.ws_row;

    /* Pcmw >= 5 in DECDLD */
    if (cur_ps->col_width < 5 || 99 < cur_ps->col_width || 99 < cur_ps->line_height) {
      return 0;
    }
  } else {
    cur_ps->col_width = 8;
    cur_ps->line_height = 16;
  }

#if 0
  FILE *fp = fopen("moshlog.txt", "a");
  fprintf(fp, "cell size: col width %d line height %d\n",
	  cur_ps->col_width, cur_ps->line_height);
  fclose(fp);
#endif

  return 1;
#else
  cur_ps->col_width = 8;
  cur_ps->line_height = 16;

  return 1;
#endif
}

static inline void switch_94_96_cs(char *charset, int *is_96cs) {
  if (*is_96cs == 0) {
    *is_96cs = 1;
  } else {
    *is_96cs = 0;
  }
  *charset = '0';
}

static unsigned char *pua_to_utf8(unsigned char *utf8, unsigned int ucs) {
  *(utf8++) = ((ucs >> 18) & 0x07) | 0xf0;
  *(utf8++) = ((ucs >> 12) & 0x3f) | 0x80;
  *(utf8++) = ((ucs >> 6) & 0x3f) | 0x80;
  *(utf8++) = (ucs & 0x3f) | 0x80;

  return utf8;
}

/*
 * Parse DRCS-Sixel and return UTF-8 characters which represent image
 * pieces of sixel graphics.
 * DCS Pfn; Pcn; Pe; Pcmw; Pss; 3; Pcmh; Pcss { SP Dscs <SIXEL> ST
 */
static char* drcs_sixel_from_data(char *sixel, /* DCS P1;P2;P3;q...ST */ size_t sixel_len,
				  char *charset /* Dscs (in/out) */,
				  int *is_96cs /* Pcss (in/out) */) {
  char *sixel_p = sixel;

  if (sixel_p[0] == '\x1b' && sixel_p[1] == 'P') {
    sixel_p += 2;
  } else if (sixel_p[0] == '\x90') {
    sixel_p ++;
  }

  while ('0' <= *sixel_p && *sixel_p <= ';') { sixel_p++; }

  if (*sixel_p != 'q') {
    return NULL;
  }
  sixel_p ++;

  int x;
  int y;
  int width;
  int height;
  if (sscanf(sixel_p, "\"%d;%d;%d;%d", &x, &y, &width, &height) != 4 ||
      width == 0 || height == 0) {
    return NULL;
  }

  if (sixel + sixel_len <= sixel_p) {
    return NULL;
  }
  sixel_len -= (sixel_p - sixel);

  if (cur_ps->col_width == 0 && !get_cell_size()) {
    return NULL;
  }

  int num_cols = (width + cur_ps->col_width - 1) / cur_ps->col_width;
  int num_rows = (height + cur_ps->line_height - 1) / cur_ps->line_height;

#if 0
  /*
   * XXX
   * The way of drcs_charset increment from 0x7e character set may be different
   * between terminal emulators.
   */
  if (*charset > '0' &&
      (num_cols * num_rows + 0x5f) / 0x60 > 0x7e - *charset + 1) {
    switch_94_96_cs(charset, is_96cs);
  }
#endif

  unsigned char *buf;
  if ((buf = (unsigned char*)malloc((4 * num_cols + 1 + num_cols) * num_rows + 1))) {
    /*
     * \x1bP1;0;0;%d;1;3;%d;%d{ %c
     *            2      2  1   1
     */
    char seq[16 + 2 + 2 + 1 + 1 + 1]; /* 23 */

    sprintf(seq, "\x1bP1;0;0;%d;1;3;%d;%d{ %c",
	    cur_ps->col_width, cur_ps->line_height, *is_96cs, *charset);
    size_t len = strlen(seq);
    memmove(sixel + len, sixel_p, sixel_len);
    memcpy(sixel, seq, len);
    sixel[len + sixel_len] = '\0';

    unsigned char *buf_p = buf;
    int col;
    int row;
    unsigned int code = 0x100020 + (*is_96cs ? 0x80 : 0) + *charset * 0x100;

    for(row = 0; row < num_rows; row++) {
      for(col = 0; col < num_cols; col++) {
	buf_p = pua_to_utf8(buf_p, code++);

	if ((code & 0x7f) == 0x0) {
	  if (*charset == 0x7e) {
	    switch_94_96_cs(charset, is_96cs);
	  } else {
	    (*charset)++;
	  }

	  code = 0x100020 + (*is_96cs ? 0x80 : 0) + *charset * 0x100;
	}
      }
      *(buf_p++) = '\n';
      memset(buf_p, '\x08', num_cols);
      buf_p += num_cols;
    }
    *buf_p = '\0';

    if (*charset == 0x7e) {
      switch_94_96_cs(charset, is_96cs);
    } else {
      (*charset)++;
    }

    return (char*)buf;
  }

  return NULL;
}

static int check_pass_seq_len(size_t len) {
  static int max_pass_seq_len = 0;

  if (cur_ps->s.pass_seq_len >= cur_ps->s.pass_seq_cur - cur_ps->s.pass_seq + len) {
    return 1;
  }

  if (max_pass_seq_len == 0) {
    char *env;

    if ((env = getenv("MOSH_PASS_SEQ_MAX")) == NULL || (max_pass_seq_len = atoi(env)) < 102400) {
      max_pass_seq_len = 10240000; /* around 10MB */
    }
  }

  if (cur_ps->s.pass_seq_len >= max_pass_seq_len) {
    return 0;
  }

  if (len < 102400) {
    len = 102400;
  }

  void *p;
  if (!(p = realloc(cur_ps->s.pass_seq, cur_ps->s.pass_seq_len + len))) {
    return 0;
  }

  cur_ps->s.pass_seq_beg = ((char*)p) + (cur_ps->s.pass_seq_beg - cur_ps->s.pass_seq);
  cur_ps->s.pass_seq_cur = ((char*)p) + (cur_ps->s.pass_seq_cur - cur_ps->s.pass_seq);
  cur_ps->s.pass_seq = (char*)p;
  cur_ps->s.pass_seq_len += len;

  return 1;
}

void append_str_to_pass_seq(const char *seq, size_t len) {
  if (check_pass_seq_len(len)) {
    cur_ps->s.pass_seq_cur = (char*)memcpy(cur_ps->s.pass_seq_cur, seq, len) + len;
  }
}

static void append_char_to_pass_seq(char ch) {
  if (check_pass_seq_len(1)) {
    *(cur_ps->s.pass_seq_cur++) = ch;
  }
}

void establish_tcp_connection(int port);

void pass_seq_end(void) {
  cur_ps->s.pass_seq_beg = cur_ps->s.pass_seq_cur;
  cur_ps->s.pass_seq_ready = true;

  if (cur_ps->s.has_zpacket) {
    establish_tcp_connection(-1);
  }
}

/* If *(pass_seq_cur - 1) is '\x18', it is counted. */
static int get_byte_in_zbinhdr(int back_count) {
  char *p = cur_ps->s.pass_seq_cur - 1;

  while (1) {
    if (--back_count == 0) {
      if (*(p - 1) == '\x18') {
	return *p - 0x40;
      } else {
	return *p;
      }
    } else if (*(--p) == '\x18') {
      p--;
    }
  }
}

using namespace Parser;

Transition State::anywhere_rule( wchar_t ch ) const
{
  if ( (ch == 0x18) || (ch == 0x1A)
       || ((0x80 <= ch) && (ch <= 0x8F))
       || ((0x91 <= ch) && (ch <= 0x97))
       || (ch == 0x99) || (ch == 0x9A) ) {
    return Transition( new Execute, &family->s_Ground );
  } else if ( ch == 0x9C ) {
    return Transition( &family->s_Ground );
  } else if ( ch == 0x1B ) {
    return Transition( &family->s_Escape );
  } else if ( (ch == 0x98) || (ch == 0x9E) || (ch == 0x9F) ) {
    return Transition( &family->s_SOS_PM_APC_String );
  } else if ( ch == 0x90 ) {
    return Transition( &family->s_DCS_Entry );
  } else if ( ch == 0x9D ) {
    return Transition( &family->s_OSC_String );
  } else if ( ch == 0x9B ) {
    return Transition( &family->s_CSI_Entry );
  }

  return Transition(( State * )NULL, NULL ); /* don't allocate an Ignore action */
}

#if 0
#define __DEBUG
#endif

Transition State::input( wchar_t ch ) const
{
#ifdef __DEBUG
  if (ps->cur_state_idx == 0) {
    FILE *fp = fopen("moshlog.txt", "a");
    fprintf(fp, "%c (%x, %d)\n", ch, cur_ps->s.zhdr_stat, cur_ps->s.zhdr_left);
    fclose(fp);
  }
#endif

  if (cur_ps->s.zhdr_stat) {
    if (cur_ps->s.zhdr_stat < 0x10) {
      if (cur_ps->s.zhdr_stat == 1) {
	if (ch == '*') {
	  cur_ps->s.zhdr_stat = 3; /* HEX */
	} else if (ch == '\x18') {
	  cur_ps->s.zhdr_stat = 2; /* BIN or BIN32 */
	} else {
	  cur_ps->s.zhdr_stat = 0;
	}
      } else if (cur_ps->s.zhdr_stat == 2) {
	if (ch == 'A') {
	  append_str_to_pass_seq("*" "\x18" "A", 3);
	  cur_ps->s.zhdr_left = 7; /* BIN */
	  cur_ps->s.zhdr_stat = 0x10;
	} else if (ch == 'C') {
	  append_str_to_pass_seq("*" "\x18" "C", 3);
	  cur_ps->s.zhdr_left = 9; /* BIN32 */
	  cur_ps->s.zhdr_stat = 0x20;
	} else {
	  cur_ps->s.zhdr_stat = 0;

	  goto skip_pass_seq;
	}

	cur_ps->s.pass_seq_ready = false;
	cur_ps->processing_zmodem = true;

	return Transition();
      } else if (cur_ps->s.zhdr_stat == 3) {
	if (ch == '*') {
	  /* cur_ps->s.zhdr_stat is not changed. */
	} else
	if (ch == '\x18') {
	  cur_ps->s.zhdr_stat = 4;
	} else {
	  cur_ps->s.zhdr_stat = 0;
	}
      } else if (cur_ps->s.zhdr_stat == 4) {
	if (ch == 'A') {
	  append_str_to_pass_seq("*" "\x18" "A", 3);
	  cur_ps->s.zhdr_left = 7; /* BIN */
	  cur_ps->s.zhdr_stat = 0x10;
	} else if (ch == 'C') {
	  append_str_to_pass_seq("*" "\x18" "C", 3);
	  cur_ps->s.zhdr_left = 9; /* BIN32 */
	  cur_ps->s.zhdr_stat = 0x20;
	} else if (ch == 'B') {
	  append_str_to_pass_seq("**" "\x18" "B", 4);
	  cur_ps->s.zhdr_left = 14; /* HEX */
	  cur_ps->s.zhdr_stat = 0x40;
	} else {
	  cur_ps->s.zhdr_stat = 0;

	  goto skip_pass_seq;
	}

	cur_ps->s.pass_seq_ready = false;
	cur_ps->processing_zmodem = true;

	return Transition();
      } else if (cur_ps->s.zhdr_stat == 5) {
	if (ch == '\x18') {
	  append_str_to_pass_seq("\x18\x18", 2);
	  cur_ps->s.zhdr_stat = 6;

	  return Transition();
	} else {
	  cur_ps->s.zhdr_stat = 0;
	}
      } else if (cur_ps->s.zhdr_stat == 6) {
	if (ch == '\x18' || ch == '\x08') {
	  append_char_to_pass_seq(ch);

	  return Transition();
	} else {
	  /* Cancel */
	  cur_ps->processing_zmodem = false;
	  cur_ps->s.has_zpacket = true; /* Don't set after pass_seq_end() */
	  cur_ps->s.zhdr_stat = 0;
	  pass_seq_end();
	}
      }
    } else {
      append_char_to_pass_seq(ch);

      if (cur_ps->s.zhdr_stat & 0x80) {
	if (*(cur_ps->s.pass_seq_cur - 2) == '\x18') {
	  if ('h' <= ch && ch <= 'k') {
	    if (cur_ps->s.zhdr_stat & 0x10) {
	      cur_ps->s.zhdr_left = 2;
	    } else /* if (cur_ps->s.zhdr_stat & 0x20) */ {
	      cur_ps->s.zhdr_left = 4;
	    }

	    if (ch == 'h' || ch == 'k') {
	      cur_ps->s.zhdr_stat &= ~(0x10|0x20|0x80);
	      cur_ps->s.zhdr_stat |= 0x100; /* No trailing data subpacket. */
	    } else {
	      cur_ps->s.zhdr_stat &= ~0x80;
	      cur_ps->s.zhdr_stat |= 0x200;
	    }
	  }
	}
      } else if (ch != '\x18' /* \x18 escapes the next char */ && --cur_ps->s.zhdr_left == 0) {
	if (cur_ps->s.zhdr_stat & 0x200) {
	  cur_ps->s.pass_seq_beg = cur_ps->s.pass_seq_cur;

	  cur_ps->s.zhdr_left = 1;
	  cur_ps->s.zhdr_stat &= ~0x200;
	  cur_ps->s.zhdr_stat |= 0x80; /* Data subpacket continues. */
	} else if (cur_ps->s.zhdr_stat & (0x10|0x20)) {
	  int frame_type = get_byte_in_zbinhdr((cur_ps->s.zhdr_stat & 0x10) ? 7 : 9);

	  if (frame_type == 4 /* ZFILE */ || frame_type == 0x0a /* ZDATA */) {
	    cur_ps->s.zhdr_left = 1;
	    cur_ps->s.zhdr_stat |= 0x80; /* Data subpacket continues. */
	  } else {
	    if (frame_type == 8) { /* ZFIN */
	      cur_ps->processing_zmodem = false;
	    }

	    goto packet_end;
	  }
	} else if (cur_ps->s.zhdr_stat & 0x40) {
	  if (strncmp(cur_ps->s.pass_seq_cur - 14, "03", 2) == 0 /* ZACK */) {
	    cur_ps->s.zhdr_left = 2; /* CR LF(8A) */
	  } else if (strncmp(cur_ps->s.pass_seq_cur - 14, "08", 2) == 0 /* ZFIN */) {
	    cur_ps->s.zhdr_left = 2; /* CR LF(8A) */
	    cur_ps->processing_zmodem = false;
	  } else {
	    cur_ps->s.zhdr_left = 3; /* CR LF(8A) XON */
	  }
	  cur_ps->s.zhdr_stat &= ~0x40;
	  cur_ps->s.zhdr_stat |= 0x100;
	} else {
	  goto packet_end;
	}
      }

      return Transition();

    packet_end:
      cur_ps->s.has_zpacket = true; /* Don't set after pass_seq_end() */
      cur_ps->s.zhdr_stat = 0;
      pass_seq_end();

      return Transition();
    }
  } else if (ch == '*') {
    cur_ps->s.zhdr_stat = 1;
  } else if (ch == '\x18') {
    cur_ps->s.zhdr_stat = 5;
  }

skip_pass_seq:
  /* Check for immediate transitions. */
  Transition anywhere = anywhere_rule( ch );
  if ( anywhere.next_state ) {
    anywhere.action->char_present = true;
    anywhere.action->ch = ch;
    return anywhere;
  }
  /* Normal X.364 state machine. */
  /* Parse high Unicode codepoints like 'A'. */
  Transition ret = this->input_state_rule( ch >= 0xA0 ? 0x41 : ch );
  ret.action->char_present = true;
  ret.action->ch = ch;
  return ret;
}

static bool C0_prime( wchar_t ch )
{
  return ( (ch <= 0x17)
	   || (ch == 0x19)
	   || ( (0x1C <= ch) && (ch <= 0x1F) ) );
}

static bool GLGR ( wchar_t ch )
{
  return ( ( (0x20 <= ch) && (ch <= 0x7F) ) /* GL area */
	   || ( (0xA0 <= ch) && (ch <= 0xFF) ) ); /* GR area */
}

Transition Ground::input_state_rule( wchar_t ch ) const
{
  if ( C0_prime( ch ) ) {
    return Transition( new Execute );
  }

  if ( GLGR( ch ) ) {
    return Transition( new Print );
  }

  return Transition();
}

Action *Escape::enter( void ) const
{
  return new Clear;
}

Transition Escape::input_state_rule( wchar_t ch ) const
{
  if ( C0_prime( ch ) ) {
    return Transition( new Execute );
  }

  if ( (0x20 <= ch) && (ch <= 0x2F) ) {
    return Transition( new Collect, &family->s_Escape_Intermediate );
  }

  if ( ( (0x30 <= ch) && (ch <= 0x4F) )
       || ( (0x51 <= ch) && (ch <= 0x57) )
       || ( ch == 0x59 )
       || ( ch == 0x5A )
       || ( ch == 0x5C )
       || ( (0x60 <= ch) && (ch <= 0x7E) ) ) {
    return Transition( new Esc_Dispatch, &family->s_Ground );
  }

  if ( ch == 0x5B ) {
    return Transition( &family->s_CSI_Entry );
  }

  if ( ch == 0x5D ) {
    return Transition( &family->s_OSC_String );
  }

  if ( ch == 0x50 ) {
    return Transition( &family->s_DCS_Entry );
  }

  if ( (ch == 0x58) || (ch == 0x5E) || (ch == 0x5F) ) {
    return Transition( &family->s_SOS_PM_APC_String );
  }

  return Transition();
}

Transition Escape_Intermediate::input_state_rule( wchar_t ch ) const
{
  if ( C0_prime( ch ) ) {
    return Transition( new Execute );
  }

  if ( (0x20 <= ch) && (ch <= 0x2F) ) {
    return Transition( new Collect );
  }

  if ( (0x30 <= ch) && (ch <= 0x7E) ) {
    return Transition( new Esc_Dispatch, &family->s_Ground );
  }

  return Transition();
}

Action *CSI_Entry::enter( void ) const
{
  return new Clear;
}

Transition CSI_Entry::input_state_rule( wchar_t ch ) const
{
  if ( C0_prime( ch ) ) {
    return Transition( new Execute );
  }

  if ( (0x40 <= ch) && (ch <= 0x7E) ) {
    return Transition( new CSI_Dispatch, &family->s_Ground );
  }

  if ( ( (0x30 <= ch) && (ch <= 0x39) )
       || ( ch == 0x3B ) ) {
    return Transition( new Param, &family->s_CSI_Param );
  }

  if ( (0x3C <= ch) && (ch <= 0x3F) ) {
    return Transition( new Collect, &family->s_CSI_Param );
  }

  if ( ch == 0x3A ) {
    return Transition( &family->s_CSI_Ignore );
  }

  if ( (0x20 <= ch) && (ch <= 0x2F) ) {
    return Transition( new Collect, &family->s_CSI_Intermediate );
  }

  return Transition();
}

Transition CSI_Param::input_state_rule( wchar_t ch ) const
{
  if ( C0_prime( ch ) ) {
    return Transition( new Execute );
  }

  if ( ( (0x30 <= ch) && (ch <= 0x39) ) || ( ch == 0x3B ) ) {
    return Transition( new Param );
  }

  if ( ( ch == 0x3A ) || ( (0x3C <= ch) && (ch <= 0x3F) ) ) {
    return Transition( &family->s_CSI_Ignore );
  }

  if ( (0x20 <= ch) && (ch <= 0x2F) ) {
    return Transition( new Collect, &family->s_CSI_Intermediate );
  }

  if ( (0x40 <= ch) && (ch <= 0x7E) ) {
    return Transition( new CSI_Dispatch, &family->s_Ground );
  }

  return Transition();
}

Transition CSI_Intermediate::input_state_rule( wchar_t ch ) const
{
  if ( C0_prime( ch ) ) {
    return Transition( new Execute );
  }

  if ( (0x20 <= ch) && (ch <= 0x2F) ) {
    return Transition( new Collect );
  }

  if ( (0x40 <= ch) && (ch <= 0x7E) ) {
    return Transition( new CSI_Dispatch, &family->s_Ground );
  }

  if ( (0x30 <= ch) && (ch <= 0x3F) ) {
    return Transition( &family->s_CSI_Ignore );
  }

  return Transition();
}

Transition CSI_Ignore::input_state_rule( wchar_t ch ) const
{
  if ( C0_prime( ch ) ) {
    return Transition( new Execute );
  }

  if ( (0x40 <= ch) && (ch <= 0x7E) ) {
    return Transition( &family->s_Ground );
  }

  return Transition();
}

Action *DCS_Entry::enter( void ) const
{
  return new Clear;
}

Transition DCS_Entry::input_state_rule( wchar_t ch ) const
{
  append_str_to_pass_seq("\x1bP", 2);
  append_char_to_pass_seq(ch);
  cur_ps->s.pass_seq_ready = false;

  if ( (0x20 <= ch) && (ch <= 0x2F) ) {
    return Transition( new Collect, &family->s_DCS_Intermediate );
  }

  if ( ch == 0x3A ) {
    return Transition( &family->s_DCS_Ignore );
  }

  if ( ( (0x30 <= ch) && (ch <= 0x39) ) || ( ch == 0x3B ) ) {
    return Transition( new Param, &family->s_DCS_Param );
  }

  if ( (0x3C <= ch) && (ch <= 0x3F) ) {
    return Transition( new Collect, &family->s_DCS_Param );
  }

  if ( (0x40 <= ch) && (ch <= 0x7E) ) {
    return Transition( &family->s_DCS_Passthrough );
  }

  return Transition();
}

Transition DCS_Param::input_state_rule( wchar_t ch ) const
{
  if (cur_ps->s.pass_seq_cur > cur_ps->s.pass_seq_beg) {
    append_char_to_pass_seq(ch);
  }

  if ( ( (0x30 <= ch) && (ch <= 0x39) ) || ( ch == 0x3B ) ) {
    return Transition( new Param );
  }

  if ( ( ch == 0x3A ) || ( (0x3C <= ch) && (ch <= 0x3F) ) ) {
    return Transition( &family->s_DCS_Ignore );
  }

  if ( (0x20 <= ch) && (ch <= 0x2F) ) {
    return Transition( new Collect, &family->s_DCS_Intermediate );
  }

  if ( (0x40 <= ch) && (ch <= 0x7E) ) {
    return Transition( &family->s_DCS_Passthrough );
  }

  return Transition();
}

Transition DCS_Intermediate::input_state_rule( wchar_t ch ) const
{
  if (cur_ps->s.pass_seq_cur > cur_ps->s.pass_seq_beg) {
    append_char_to_pass_seq(ch);
  }

  if ( (0x20 <= ch) && (ch <= 0x2F) ) {
    return Transition( new Collect );
  }

  if ( (0x40 <= ch) && (ch <= 0x7E) ) {
    return Transition( &family->s_DCS_Passthrough );
  }

  if ( (0x30 <= ch) && (ch <= 0x3F) ) {
    return Transition( &family->s_DCS_Ignore );
  }

  return Transition();
}

Action *DCS_Passthrough::enter( void ) const
{
  return new Hook;
}

Action *DCS_Passthrough::exit( void ) const
{
  if (cur_ps->s.pass_seq_cur > cur_ps->s.pass_seq_beg) {
    static char charset = '0';
    static int is_96cs = 0;

    append_str_to_pass_seq("\x1b\\", 3); /* append NULL for strlen(cur_ps->s.pass_seq_beg) below */

    if (check_pass_seq_len(23)) { /* 23: see drcs_sixel_from_data() */
      cur_ps->s.sixel_chars = drcs_sixel_from_data(cur_ps->s.pass_seq_beg,
						   strlen(cur_ps->s.pass_seq_beg),
						   &charset, &is_96cs);
      cur_ps->s.pass_seq_cur = cur_ps->s.pass_seq_beg + strlen(cur_ps->s.pass_seq_beg);
    }

    pass_seq_end();
  }

  return new Unhook;
}

Transition DCS_Passthrough::input_state_rule( wchar_t ch ) const
{
  append_char_to_pass_seq(ch);

  if ( C0_prime( ch ) || ( (0x20 <= ch) && (ch <= 0x7E) ) ) {
    return Transition( new Put );
  }

  if ( ch == 0x9C ) {
    return Transition( &family->s_Ground );
  }

  return Transition();
}

Transition DCS_Ignore::input_state_rule( wchar_t ch ) const
{
  if ( ch == 0x9C ) {
    return Transition( &family->s_Ground );
  }

  return Transition();
}

Action *OSC_String::enter( void ) const
{
  return new OSC_Start;
}

Action *OSC_String::exit( void ) const
{
  if (cur_ps->s.osc_len == -1 /* == cur_ps->s.pass_seq_cur > cur_ps->s.pass_seq_beg */) {
    pass_seq_end();
  }

  cur_ps->s.osc_len = 0;

  return new OSC_End;
}

Transition OSC_String::input_state_rule( wchar_t ch ) const
{
  if (cur_ps->s.osc_len >= 0) {
    cur_ps->s.osc_buf[cur_ps->s.osc_len++] = ch;

    if (cur_ps->s.osc_len == 5) {
      if (*cur_ps->s.osc_buf == '5' &&
	  (memcmp(cur_ps->s.osc_buf + 1, "379;", 4) == 0 || memcmp(cur_ps->s.osc_buf + 1, "380;", 4) == 0 ||
	   memcmp(cur_ps->s.osc_buf + 1, "381;", 4) == 0 || memcmp(cur_ps->s.osc_buf + 1, "383;", 4) == 0)) {
	append_str_to_pass_seq("\x1b]", 2);
	append_str_to_pass_seq(cur_ps->s.osc_buf, 5);

	cur_ps->s.osc_len = -1;
	cur_ps->s.pass_seq_ready = false;
      } else {
	cur_ps->s.osc_len = -2;
      }
    }
  } else if (cur_ps->s.osc_len == -1) {
    append_char_to_pass_seq(ch);
  }

  if ( (0x20 <= ch) && (ch <= 0x7F) ) {
    return Transition( new OSC_Put );
  }

  if ( (ch == 0x9C) || (ch == 0x07) ) { /* 0x07 is xterm non-ANSI variant */
    if (cur_ps->s.pass_seq_cur == cur_ps->s.pass_seq_beg + 24 &&
	strncmp(cur_ps->s.pass_seq_beg, "\x1b]5379;tcp_connect ", 19) == 0) {
      *(cur_ps->s.pass_seq_cur - 1) = '\0'; /* replace '\x07' by '\0' */
      int port = atoi(cur_ps->s.pass_seq_beg + 19);

      cur_ps->s.osc_len = -2;
      cur_ps->s.pass_seq_cur = cur_ps->s.pass_seq_beg; /* remove it */

      establish_tcp_connection(port);
    }

    return Transition( &family->s_Ground );
  }

  return Transition();
}

Transition SOS_PM_APC_String::input_state_rule( wchar_t ch ) const
{
  if ( ch == 0x9C ) {
    return Transition( &family->s_Ground );
  }

  return Transition();
}

char *sixel_get_chars(void) {
  if (cur_ps->s.pass_seq_ready) {
    return cur_ps->s.sixel_chars;
  } else {
    return NULL;
  }
}

void sixel_reset_chars(void) {
  free(cur_ps->s.sixel_chars);
  cur_ps->s.sixel_chars = NULL;
}

/* True until ZFIN packet is received. */
bool zmodem_processing(pass_seq_t *ps) {
  if (ps == NULL) {
    ps = cur_ps;
  }

  /*
   * zhdr_stat == 2: ZPAD ZDLE (BIN or BIN32)
   * zhdr_stat == 4: ZPAD ZPAD ZDLE (HEX)
   */
  return ps->processing_zmodem || (ps->s.zhdr_stat == 2 || ps->s.zhdr_stat >= 4);
}

char *pass_seq_get(pass_seq_t *ps, size_t *len) {
  if (ps->cur_state_idx == 1) {
    return NULL;
  } else if (ps->s.pass_seq_ready) {
    *len = ps->s.pass_seq_cur - ps->s.pass_seq;

#ifdef __DEBUG
    FILE *fp = fopen("moshlog.txt", "a");
    fprintf(fp, "PASSSEQ GET %d\n", *len);
    fclose(fp);
#endif
  } else if (ps->s.pass_seq_beg > ps->s.pass_seq) {
    *len = ps->s.pass_seq_beg - ps->s.pass_seq;

#ifdef __DEBUG
    FILE *fp = fopen("moshlog.txt", "a");
    fprintf(fp, "PASSSEQ GET %d\n", *len);
    fclose(fp);
#endif
  } else {
    return NULL;
  }

  return ps->s.pass_seq;
}

#ifdef __DEBUG
static bool overlay;
#endif

static void reset(pass_seq_t *ps) {
#ifdef __DEBUG
  FILE *fp = fopen(overlay ? "overlay.txt" : "moshlog.txt", "a");
  fprintf(fp, "PASSSEQ RESET %d\n", ps->s.pass_seq_cur - ps->s.pass_seq);
  for (int i = 0; i < ps->s.pass_seq_cur - ps->s.pass_seq; i++) {
    fprintf(fp, "%c", ps->s.pass_seq[i]);
  }
  fprintf(fp, "\n");
  fclose(fp);
#endif

  ps->s.zhdr_stat = 0;
  ps->s.pass_seq_ready = false;
  ps->s.has_zpacket = false;
  ps->s.pass_seq_beg = ps->s.pass_seq_cur = ps->s.pass_seq;
}

void pass_seq_reset(pass_seq_t *ps) {
  if (ps->s.pass_seq_ready) {
    reset(ps);
  } else if (ps->s.pass_seq_beg > ps->s.pass_seq) {
#ifdef __DEBUG
    FILE *fp = fopen(overlay ? "overlay.txt" : "moshlog.txt", "a");
    fprintf(fp, "PASSSEQ RESET %d\n", ps->s.pass_seq_beg - ps->s.pass_seq);
    for (int i = 0; i < ps->s.pass_seq_beg - ps->s.pass_seq; i++) {
      fprintf(fp, "%c", ps->s.pass_seq[i]);
    }
    fprintf(fp, "\n");
    fclose(fp);
#endif

    memmove(ps->s.pass_seq, ps->s.pass_seq_beg, ps->s.pass_seq_cur - ps->s.pass_seq_beg);
    ps->s.pass_seq_cur -= (ps->s.pass_seq_beg - ps->s.pass_seq);
    ps->s.pass_seq_beg = ps->s.pass_seq;
  }
}

/*
 * Because this function doesn't consider ps->cur_state_idx,
 * use this function after pass_seq_get() which returns NULL if ps->cur_state_idx == 1.
 */
bool pass_seq_has_zmodem(pass_seq_t *ps) {
  return (ps->s.zhdr_stat != 0) || ps->s.has_zpacket;
}

void pass_seq_change_buf(pass_seq_t *ps, int idx, bool reset_cur_state) {
  if (reset_cur_state) {
#ifdef __DEBUG
    overlay = true;
#endif

    sixel_reset_chars();
    reset(ps);

#ifdef __DEBUG
    overlay = false;
#endif
  }

  ps->s_back[ps->cur_state_idx] = ps->s;
  ps->s = ps->s_back[idx];
  ps->cur_state_idx = idx;
}

void pass_seq_full_reset(pass_seq_t *ps) {
  ps->processing_zmodem = false;

  int idx = ps->cur_state_idx;
  pass_seq_change_buf(ps, idx == 0 ? 1 : 0, true);
  pass_seq_change_buf(ps, idx, true);
}
