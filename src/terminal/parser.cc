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

#include <assert.h>
#include <typeinfo>
#include <errno.h>
#include <wchar.h>
#include <stdint.h>

#include "parser.h"
#include "config.h"

/*
 * Return value
 * -1: utf8_ch is invalid.
 * -2: utf8_ch is insufficient.
 */
size_t convert_utf8_to_ucs(unsigned int *ucs_ch, unsigned char *utf8_ch, size_t len) {
  if ((utf8_ch[0] & 0xc0) == 0x80) {
    goto invalid;
  } else if ((utf8_ch[0] & 0x80) == 0) {
    *ucs_ch = utf8_ch[0];

    return 1;
  } else if ((utf8_ch[0] & 0xe0) == 0xc0) {
    if (len < 2) {
      return (size_t) -2;
    }

    if (utf8_ch[1] < 0x80) {
      goto invalid;
    }

    *ucs_ch = (((utf8_ch[0] & 0x1f) << 6) & 0xffffffc0) | (utf8_ch[1] & 0x3f);

    if (*ucs_ch < 0x80) {
      goto invalid;
    }

    return 2;
  } else if ((utf8_ch[0] & 0xf0) == 0xe0) {
    if (len < 3) {
      return (size_t) -2;
    }

    if (utf8_ch[1] < 0x80 || utf8_ch[2] < 0x80) {
      goto invalid;
    }

    *ucs_ch = (((utf8_ch[0] & 0x0f) << 12) & 0xffff000) |
              (((utf8_ch[1] & 0x3f) << 6) & 0xffffffc0) | (utf8_ch[2] & 0x3f);

    if (*ucs_ch < 0x800) {
      goto invalid;
    }

    return 3;
  } else if ((utf8_ch[0] & 0xf8) == 0xf0) {
    if (len < 4) {
      return (size_t) -2;
    }

    if (utf8_ch[1] < 0x80 || utf8_ch[2] < 0x80 || utf8_ch[3] < 0x80) {
      goto invalid;
    }

    *ucs_ch = (((utf8_ch[0] & 0x07) << 18) & 0xfffc0000) |
              (((utf8_ch[1] & 0x3f) << 12) & 0xffff000) |
              (((utf8_ch[2] & 0x3f) << 6) & 0xffffffc0) | (utf8_ch[3] & 0x3f);

    if (*ucs_ch < 0x10000) {
      goto invalid;
    }

    return 4;
  } else if ((utf8_ch[0] & 0xfc) == 0xf8) {
    if (len < 5) {
      return (size_t) -2;
    }

    if (utf8_ch[1] < 0x80 || utf8_ch[2] < 0x80 || utf8_ch[3] < 0x80 || utf8_ch[4] < 0x80) {
      goto invalid;
    }

    *ucs_ch = (((utf8_ch[0] & 0x03) << 24) & 0xff000000) |
              (((utf8_ch[1] & 0x3f) << 18) & 0xfffc0000) |
              (((utf8_ch[2] & 0x3f) << 12) & 0xffff000) |
              (((utf8_ch[3] & 0x3f) << 6) & 0xffffffc0) | (utf8_ch[4] & 0x3f);

    if (*ucs_ch < 0x200000) {
      goto invalid;
    }

    return 5;
  } else if ((utf8_ch[0] & 0xfe) == 0xfc) {
    if (len < 6) {
      return (size_t) -2;
    }

    if (utf8_ch[1] < 0x80 || utf8_ch[2] < 0x80 || utf8_ch[3] < 0x80 || utf8_ch[4] < 0x80 ||
        utf8_ch[5] < 0x80) {
      goto invalid;
    }

    *ucs_ch =
        (((utf8_ch[0] & 0x01 << 30) & 0xc0000000)) | (((utf8_ch[1] & 0x3f) << 24) & 0xff000000) |
        (((utf8_ch[2] & 0x3f) << 18) & 0xfffc0000) | (((utf8_ch[3] & 0x3f) << 12) & 0xffff000) |
        (((utf8_ch[4] & 0x3f) << 6) & 0xffffffc0) | (utf8_ch[4] & 0x3f);

    if (*ucs_ch < 0x4000000) {
      goto invalid;
    }

    return 6;
  }

invalid:
  errno = EILSEQ; /* For assert( errno == EILSEQ ) in UTF8Parser::input() */

  return (size_t) -1;
}

/*
 * Return value
 * -1: ucs_ch is invalid.
 * -2: utf8_ch is insufficient.
 */
size_t convert_ucs_to_utf8(unsigned char *utf8, size_t len, unsigned int ucs_ch) {
  if (/* 0x00 <= ucs_ch && */ ucs_ch <= 0x7f) {
    utf8[0] = ucs_ch;

    return 1;
  } else if (ucs_ch <= 0x07ff) {
    if (len < 2) {
      return (size_t) -2;
    }

    utf8[0] = ((ucs_ch >> 6) & 0xff) | 0xc0;
    utf8[1] = (ucs_ch & 0x3f) | 0x80;

    return 2;
  } else if (ucs_ch <= 0xffff) {
    if (len < 3) {
      return (size_t) -2;
    }

    utf8[0] = ((ucs_ch >> 12) & 0x0f) | 0xe0;
    utf8[1] = ((ucs_ch >> 6) & 0x3f) | 0x80;
    utf8[2] = (ucs_ch & 0x3f) | 0x80;

    return 3;
  } else if (ucs_ch <= 0x1fffff) {
    if (len < 4) {
      return (size_t) -2;
    }

    utf8[0] = ((ucs_ch >> 18) & 0x07) | 0xf0;
    utf8[1] = ((ucs_ch >> 12) & 0x3f) | 0x80;
    utf8[2] = ((ucs_ch >> 6) & 0x3f) | 0x80;
    utf8[3] = (ucs_ch & 0x3f) | 0x80;

    return 4;
  } else if (ucs_ch <= 0x03ffffff) {
    if (len < 5) {
      return (size_t) -2;
    }

    utf8[0] = ((ucs_ch >> 24) & 0x03) | 0xf8;
    utf8[1] = ((ucs_ch >> 18) & 0x3f) | 0x80;
    utf8[2] = ((ucs_ch >> 12) & 0x3f) | 0x80;
    utf8[4] = ((ucs_ch >> 6) & 0x3f) | 0x80;
    utf8[5] = (ucs_ch & 0x3f) | 0x80;

    return 5;
  } else if (ucs_ch <= 0x7fffffff) {
    if (len < 6) {
      return (size_t) -2;
    }

    utf8[0] = ((ucs_ch >> 30) & 0x01) | 0xfc;
    utf8[1] = ((ucs_ch >> 24) & 0x3f) | 0x80;
    utf8[2] = ((ucs_ch >> 18) & 0x3f) | 0x80;
    utf8[3] = ((ucs_ch >> 12) & 0x3f) | 0x80;
    utf8[4] = ((ucs_ch >> 6) & 0x3f) | 0x80;
    utf8[5] = (ucs_ch & 0x3f) | 0x80;

    return 6;
  } else {
    return (size_t) -1;
  }
}

const Parser::StateFamily Parser::family;

static void append_or_delete( Parser::Action *act,
			      Parser::Actions &vec )
{
  assert( act );

  if ( !act->ignore() ) {
    vec.push_back( act );
  } else {
    delete act;
  }
}

void Parser::Parser::input( wchar_t ch, Actions &ret )
{
  Transition tx = state->input( ch );

  if ( tx.next_state != NULL ) {
    append_or_delete( state->exit(), ret );
  }

  append_or_delete( tx.action, ret );
  tx.action = NULL;

  if ( tx.next_state != NULL ) {
    append_or_delete( tx.next_state->enter(), ret );
    state = tx.next_state;
  }
}

Parser::UTF8Parser::UTF8Parser()
  : parser(), buf_len( 0 )
{
  assert( BUF_SIZE >= (size_t)MB_CUR_MAX );
  buf[0] = '\0';
}

void Parser::UTF8Parser::input( char c, Actions &ret )
{
  assert( buf_len < BUF_SIZE );

  /* 1-byte UTF-8 character, aka ASCII?  Cheat. */
  if ( buf_len == 0 && static_cast<unsigned char>(c) <= 0x7f ) {
    parser.input( static_cast<wchar_t>(c), ret );
    return;
  }

  buf[ buf_len++ ] = c;

  /* This function will only work in a UTF-8 locale. */
  wchar_t pwc;
#ifndef USE_WINSOCK
  mbstate_t ps;
  if (sizeof(wchar_t) == 4) {
    ps = mbstate_t();
  }
#endif

  size_t total_bytes_parsed = 0;
  size_t orig_buf_len = buf_len;

  /* this routine is somewhat complicated in order to comply with
     Unicode 6.0, section 3.9, "Best Practices for using U+FFFD" */

  while ( total_bytes_parsed != orig_buf_len ) {
    assert( total_bytes_parsed < orig_buf_len );
    assert( buf_len > 0 );

    size_t bytes_parsed;

    /*
     * XXX
     * pass_seq_has_zmodem() can unexpectedly return true if zmodem
     * sequence ends but it remains in parserstate.cc (ps.has_zpacket is true).
     *
     * XXX zmodem_processing(NULL) uses cur_ps.
     */
    if (zmodem_processing(NULL)) {
      bytes_parsed = 1;
      pwc = (unsigned char)buf[0];
    } else
#ifndef USE_WINSOCK
    if (sizeof(wchar_t) == 4) {
      bytes_parsed = mbrtowc( &pwc, buf, buf_len, &ps );
    } else
#endif
    {
      uint32_t ch;
      bytes_parsed = convert_utf8_to_ucs(&ch, (unsigned char*)buf, buf_len);

      if (sizeof(wchar_t) == 2 && bytes_parsed > 0 && 0x10000 <= ch && ch <= 0x10ffff) {
	ch -= 0x10000;
	parser.input(ch / 0x400 + 0xd800, ret);
	pwc = ch % 0x400 + 0xdc00;
      } else {
	pwc = ch;
      }
    }

    /* this returns 0 when n = 0! */

    if ( bytes_parsed == 0 ) {
      /* character was NUL, accept and clear buffer */
      assert( buf_len == 1 );
      buf_len = 0;
      pwc = L'\0';
      bytes_parsed = 1;
    } else if ( bytes_parsed == (size_t) -1 ) {
#ifndef USE_WINSOCK
      /* invalid sequence, use replacement character and try again with last char */
      assert( errno == EILSEQ );
#endif
      if ( buf_len > 1 ) {
	buf[ 0 ] = buf[ buf_len - 1 ];
	bytes_parsed = buf_len - 1;
	buf_len = 1;
      } else {
	buf_len = 0;
	bytes_parsed = 1;
      }
      pwc = (wchar_t) 0xFFFD;
    } else if ( bytes_parsed == (size_t) -2 ) {
      /* can't parse incomplete multibyte character */
      total_bytes_parsed += buf_len;
      continue;
    } else {
      /* parsed into pwc, accept */
      assert( bytes_parsed <= buf_len );
      memmove( buf, buf + bytes_parsed, buf_len - bytes_parsed );
      buf_len = buf_len - bytes_parsed;
    }

    /* Cast to unsigned for checks, because some
       platforms (e.g. ARM) use uint32_t as wchar_t,
       causing compiler warning on "pwc > 0" check. */
    const uint32_t pwcheck = pwc;

    if ( pwcheck > 0x10FFFF ) { /* outside Unicode range */
      pwc = (wchar_t) 0xFFFD;
    }

    if ( sizeof(wchar_t) == 4 &&
	 (pwcheck >= 0xD800) && (pwcheck <= 0xDFFF) ) { /* surrogate code point */
      /*
	OS X unfortunately allows these sequences without EILSEQ, but
	they are ill-formed UTF-8 and we shouldn't repeat them to the
	user's terminal.
      */
      pwc = (wchar_t) 0xFFFD;
    }

    parser.input( pwc, ret );

    total_bytes_parsed += bytes_parsed;
  }
}

Parser::Parser::Parser( const Parser &other )
  : state( other.state )
{}

Parser::Parser & Parser::Parser::operator=( const Parser &other )
{
  state = other.state;
  return *this;
}
