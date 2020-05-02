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

#ifndef PARSERSTATE_HPP
#define PARSERSTATE_HPP

#include "parsertransition.h"

namespace Parser {
  class StateFamily;

  class State
  {
  protected:
    virtual Transition input_state_rule( wchar_t ch ) const = 0;
    StateFamily *family;

  private:
    Transition anywhere_rule( wchar_t ch ) const;

  public:
    void setfamily( StateFamily *s_family ) { family = s_family; }
    Transition input( wchar_t ch ) const;
    virtual Action *enter( void ) const { return new Ignore; }
    virtual Action *exit( void ) const { return new Ignore; }

    State() : family( NULL ) {};
    virtual ~State() {};

    State( const State & );
    State & operator=( const State & );
  };

  class Ground : public State {
    Transition input_state_rule( wchar_t ch ) const;
  };

  class Escape : public State {
    Action *enter( void ) const;
    Transition input_state_rule( wchar_t ch ) const;
  };

  class Escape_Intermediate : public State {
    Transition input_state_rule( wchar_t ch ) const;
  };

  class CSI_Entry : public State {
    Action *enter( void ) const;
    Transition input_state_rule( wchar_t ch ) const;
  };
  class CSI_Param : public State {
    Transition input_state_rule( wchar_t ch ) const;
  };
  class CSI_Intermediate : public State {
    Transition input_state_rule( wchar_t ch ) const;
  };
  class CSI_Ignore : public State {
    Transition input_state_rule( wchar_t ch ) const;
  };
  
  class DCS_Entry : public State {
    Action *enter( void ) const;
    Transition input_state_rule( wchar_t ch ) const;
  };
  class DCS_Param : public State {
    Transition input_state_rule( wchar_t ch ) const;
  };
  class DCS_Intermediate : public State {
    Transition input_state_rule( wchar_t ch ) const;
  };
  class DCS_Passthrough : public State {
    Action *enter( void ) const;
    Transition input_state_rule( wchar_t ch ) const;
    Action *exit( void ) const;
  };
  class DCS_Ignore : public State {
    Transition input_state_rule( wchar_t ch ) const;
  };

  class OSC_String : public State {
    Action *enter( void ) const;
    Transition input_state_rule( wchar_t ch ) const;
    Action *exit( void ) const;
  };
  class SOS_PM_APC_String : public State {
    Transition input_state_rule( wchar_t ch ) const;
  };
}

extern "C" {
typedef struct pass_seq {
  int col_width;
  int line_height;

  struct state {
    char *pass_seq;
    size_t pass_seq_len;
    char *pass_seq_beg;
    char *pass_seq_cur;
    bool pass_seq_ready;
    char osc_buf[5];
    int osc_len;
    char *sixel_chars;
    int zhdr_stat;
    int zhdr_left;
    bool has_zpacket;
  } s, s_back[2];

  int cur_state_idx;
  bool processing_zmodem; /* true until ZFIN or Cancel */

} pass_seq_t;

extern pass_seq_t *cur_ps;

void set_window_size(struct winsize ws);

char *sixel_get_chars(void);

void sixel_reset_chars(void);

bool zmodem_processing(pass_seq_t *ps);

char *pass_seq_get(pass_seq_t *ps, size_t *len);

void pass_seq_reset(pass_seq_t *ps);

bool pass_seq_has_zmodem(pass_seq_t *ps);

void pass_seq_change_buf(pass_seq_t *ps, int idx, bool reset_cur_state);

void pass_seq_full_reset(pass_seq_t *ps);
}

#endif
