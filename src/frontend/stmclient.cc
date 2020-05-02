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

#include "config.h"

#include <err.h>
#include <errno.h>
#include <locale.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>

#if HAVE_PTY_H
#include <pty.h>
#elif HAVE_UTIL_H
#include <util.h>
#endif

#include "stmclient.h"
#include "swrite.h"
#include "completeterminal.h"
#include "user.h"
#include "fatal_assert.h"
#include "locale_utils.h"
#include "pty_compat.h"
#include "select.h"
#include "timestamp.h"

#include "networktransport-impl.h"

/* for establish_tcp_connection */
static Network::Transport< Network::UserStream, Terminal::Complete > *cur_network;

static bool zmodem_on_tcp = false;

void establish_tcp_connection(int port) {
  if (port <= 0 || cur_network->tcp_sock >= 0) {
    return;
  }

  cur_network->tcp_sock = tcp_connect(cur_network->get_remote_addr().sin.sin_addr.s_addr, port);
}

void STMClient::resume( void )
{
  /* Restore termios state */
  if ( tcsetattr( STDIN_FILENO, TCSANOW, &raw_termios ) < 0 ) {
      perror( "tcsetattr" );
      exit( 1 );
  }

  /* Put terminal in application-cursor-key mode */
  swrite( STDOUT_FILENO, display.open().c_str() );

  /* Flag that outer terminal state is unknown */
  repaint_requested = true;
}

void STMClient::init( void )
{
  if ( !is_utf8_locale() ) {
    LocaleVar native_ctype = get_ctype();
    string native_charset( locale_charset() );

    fprintf( stderr, "mosh-client needs a UTF-8 native locale to run.\n\n" );
    fprintf( stderr, "Unfortunately, the client's environment (%s) specifies\nthe character set \"%s\".\n\n", native_ctype.str().c_str(), native_charset.c_str() );
    int unused __attribute((unused)) = system( "locale" );
    exit( 1 );
  }

  /* Verify terminal configuration */
  if ( tcgetattr( STDIN_FILENO, &saved_termios ) < 0 ) {
    perror( "tcgetattr" );
    exit( 1 );
  }

  /* Put terminal driver in raw mode */
  raw_termios = saved_termios;

#ifdef HAVE_IUTF8
  if ( !(raw_termios.c_iflag & IUTF8) ) {
    //    fprintf( stderr, "Warning: Locale is UTF-8 but termios IUTF8 flag not set. Setting IUTF8 flag.\n" );
    /* Probably not really necessary since we are putting terminal driver into raw mode anyway. */
    raw_termios.c_iflag |= IUTF8;
  }
#endif /* HAVE_IUTF8 */

  cfmakeraw( &raw_termios );

  if ( tcsetattr( STDIN_FILENO, TCSANOW, &raw_termios ) < 0 ) {
      perror( "tcsetattr" );
      exit( 1 );
  }

  /* Put terminal in application-cursor-key mode */
  swrite( STDOUT_FILENO, display.open().c_str() );

  /* Add our name to window title */
  if ( !getenv( "MOSH_TITLE_NOPREFIX" ) ) {
    overlays.set_title_prefix( wstring( L"[mosh] " ) );
  }

  /* Set terminal escape key. */
  const char *escape_key_env;
  if ( (escape_key_env = getenv( "MOSH_ESCAPE_KEY" )) != NULL ) {
    if ( strlen( escape_key_env ) == 1 ) {
      escape_key = (int)escape_key_env[0];
      if ( escape_key > 0 && escape_key < 128 ) {
	if ( escape_key < 32 ) {
	  /* If escape is ctrl-something, pass it with repeating the key without ctrl. */
	  escape_pass_key = escape_key + (int)'@';
	} else {
	  /* If escape is something else, pass it with repeating the key itself. */
	  escape_pass_key = escape_key;
	}
	if ( escape_pass_key >= 'A' && escape_pass_key <= 'Z' ) {
	  /* If escape pass is an upper case character, define optional version
	     as lower case of the same. */
	  escape_pass_key2 = escape_pass_key + (int)'a' - (int)'A';
	} else {
	  escape_pass_key2 = escape_pass_key;
	}
      } else {
	escape_key = 0x1E;
	escape_pass_key = '^';
	escape_pass_key2 = '^';
      }
    } else if ( strlen( escape_key_env ) == 0 ) {
      escape_key = -1;
    } else {
      escape_key = 0x1E;
      escape_pass_key = '^';
      escape_pass_key2 = '^';
    }
  } else {
    escape_key = 0x1E;
    escape_pass_key = '^';
    escape_pass_key2 = '^';
  }

  /* There are so many better ways to shoot oneself into leg than
     setting escape key to Ctrl-C, Ctrl-D, NewLine, Ctrl-L or CarriageReturn
     that we just won't allow that. */
  if ( escape_key == 0x03 || escape_key == 0x04 || escape_key == 0x0A || escape_key == 0x0C || escape_key == 0x0D ) {
    escape_key = 0x1E;
    escape_pass_key = '^';
    escape_pass_key2 = '^';
  }

  /* Adjust escape help differently if escape is a control character. */
  if ( escape_key > 0 ) {
    char escape_pass_name_buf[16];
    char escape_key_name_buf[16];
    snprintf(escape_pass_name_buf, sizeof escape_pass_name_buf, "\"%c\"", escape_pass_key);
    if (escape_key < 32) {
      snprintf(escape_key_name_buf, sizeof escape_key_name_buf, "Ctrl-%c", escape_pass_key);
      escape_requires_lf = false;
    } else {
      snprintf(escape_key_name_buf, sizeof escape_key_name_buf, "\"%c\"", escape_key);
      escape_requires_lf = true;
    }
    string tmp;
    tmp = string( escape_pass_name_buf );
    wstring escape_pass_name = std::wstring(tmp.begin(), tmp.end());
    tmp = string( escape_key_name_buf );
    wstring escape_key_name = std::wstring(tmp.begin(), tmp.end());
    escape_key_help = L"Commands: Ctrl-Z suspends, \".\" quits, \".\" resets, " + escape_pass_name + L" gives literal " + escape_key_name;
    overlays.get_notification_engine().set_escape_key_string( tmp );
  }
  wchar_t tmp[ 128 ];
  swprintf( tmp, 128, L"Nothing received from server on UDP port %s.", port.c_str() );
  connecting_notification = wstring( tmp );
}

void STMClient::shutdown( void )
{
  /* Restore screen state */
  overlays.get_notification_engine().set_notification_string( wstring( L"" ) );
  overlays.get_notification_engine().server_heard( timestamp() );
  overlays.set_title_prefix( wstring( L"" ) );
  output_new_frame();

  /* Restore terminal and terminal-driver state */
  swrite( STDOUT_FILENO, display.close().c_str() );
  
  if ( tcsetattr( STDIN_FILENO, TCSANOW, &saved_termios ) < 0 ) {
    perror( "tcsetattr" );
    exit( 1 );
  }

  if ( still_connecting() ) {
    fprintf( stderr, "\nmosh did not make a successful connection to %s:%s.\n", ip.c_str(), port.c_str() );
    fprintf( stderr, "Please verify that UDP port %s is not firewalled and can reach the server.\n\n", port.c_str() );
    fprintf( stderr, "(By default, mosh uses a UDP port between 60000 and 61000. The -p option\nselects a specific UDP port number.)\n" );
  } else if ( network ) {
    if ( !clean_shutdown ) {
      fprintf( stderr, "\n\nmosh did not shut down cleanly. Please note that the\nmosh-server process may still be running on the server.\n" );
    }
  }
}

void STMClient::main_init( void )
{
  Select &sel = Select::get_instance();
  sel.add_signal( SIGWINCH );
  sel.add_signal( SIGTERM );
  sel.add_signal( SIGINT );
  sel.add_signal( SIGHUP );
  sel.add_signal( SIGPIPE );
  sel.add_signal( SIGCONT );

  /* get initial window size */
  if ( ioctl( STDIN_FILENO, TIOCGWINSZ, &window_size ) < 0 ) {
    perror( "ioctl TIOCGWINSZ" );
    return;
  }  

  /* local state */
  local_framebuffer = Terminal::Framebuffer( window_size.ws_col, window_size.ws_row );
  new_state = Terminal::Framebuffer( 1, 1 );

  /* initialize screen */
  string init = display.new_frame( false, local_framebuffer, local_framebuffer );
  swrite( STDOUT_FILENO, init.data(), init.size() );

  /* open network */
  Network::UserStream blank;
  Terminal::Complete local_terminal( window_size.ws_col, window_size.ws_row );
  network = new Network::Transport< Network::UserStream, Terminal::Complete >( blank, local_terminal,
									       key.c_str(), ip.c_str(), port.c_str() );

  network->set_send_delay( 1 ); /* minimal delay on outgoing keystrokes */

  /* tell server the size of the terminal */
  network->get_current_state().push_back( Parser::Resize( window_size.ws_col, window_size.ws_row ) );

  /* be noisy as necessary */
  network->set_verbose( verbose );
  Select::set_verbose( verbose );
}

void STMClient::output_new_frame( void )
{
  if ( !network ) { /* clean shutdown even when not initialized */
    return;
  }

  size_t seq_len;
  char *seq = pass_seq_get(&network->ps, &seq_len);

  if (seq) {
    if (!pass_seq_has_zmodem(&network->ps) && memcmp(seq, "\x1bP", 2) == 0) {
      swrite( STDOUT_FILENO, "\x1b[?8800h", 8 ); /* for DRCS-Sixel */
    }

#ifdef __DEBUG
    FILE *fp = fopen("moshlog.txt", "a");
    fprintf(fp, "Mosh client -> Terminal (len %d)\n", seq_len);
    for (int i = 0; i < seq_len; i++) {
      fprintf(fp, "%c", seq[i]);
    }
    fprintf(fp, "\n");
    fclose(fp);
#endif

    swrite( STDOUT_FILENO, seq, seq_len );
    pass_seq_reset(&network->ps);

    return;
  } else if (zmodem_processing(&network->ps)) {
    return;
  }

  /* fetch target state */
  new_state = network->get_latest_remote_state().state.get_fb();

  /* apply local overlays */
  overlays.apply( new_state );

  /* calculate minimal difference from where we are */
  const string diff( display.new_frame( !repaint_requested,
					local_framebuffer,
					new_state ) );
  swrite( STDOUT_FILENO, diff.data(), diff.size() );

  repaint_requested = false;

  local_framebuffer = new_state;
}

void STMClient::process_network_input( void )
{
  cur_network = network; /* for establish_tcp_connection() which can be called by network->recv() */
  cur_ps = &network->ps; /* for network->recv() */
  network->recv();
  
  /* Now give hints to the overlays */
  overlays.get_notification_engine().server_heard( network->get_latest_remote_state().timestamp );
  overlays.get_notification_engine().server_acked( network->get_sent_state_acked_timestamp() );

  overlays.get_prediction_engine().set_local_frame_acked( network->get_sent_state_acked() );
  overlays.get_prediction_engine().set_send_interval( network->send_interval() );
  overlays.get_prediction_engine().set_local_frame_late_acked( network->get_latest_remote_state().state.get_echo_ack() );
}

bool STMClient::process_user_input( int fd )
{
  const int buf_size = 16384;
  char buf[ buf_size ];

  /* fill buffer if possible */
  ssize_t bytes_read = read( fd, buf, buf_size );
  if ( bytes_read == 0 ) { /* EOF */
    return false;
  } else if ( bytes_read < 0 ) {
    perror( "read" );
    return false;
  }

#ifdef __DEBUG
  FILE *fp = fopen("moshlog.txt", "a");
  fprintf(fp, "Terminal => Mosh client (len %d)\n", bytes_read);
  for (int i = 0; i < bytes_read; i++) {
    fprintf(fp, "%c", buf[i]);
  }
  fprintf(fp, "\n");
  fclose(fp);
#endif

  if ( !network->shutdown_in_progress() ) {
    /* XXX */
    bool zmodem_cancel = (strstr(buf, "**\x18\x18\x18\x18\x18\x18\x18\x18"
			              "\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08") != NULL);

    if (network->tcp_sock >= 0 && tcp_send(network->tcp_sock, buf, bytes_read)) {
      if (zmodem_cancel) {
        pass_seq_full_reset(&network->ps);

	if (zmodem_on_tcp) {
	  zmodem_on_tcp = false;
	  closesocket(network->tcp_sock);
	  network->tcp_sock = -1;
	}
      }

      return true;
    } else {
      if (zmodem_cancel) {
	pass_seq_full_reset(&network->ps);
      }
    }

    pass_seq_change_buf(&network->ps, 1, false);

    overlays.get_prediction_engine().set_local_frame_sent( network->get_sent_state_last() );

    /* for overlays.get_prediction_engine().new_user_byte() */
    cur_ps = &network->ps;

    for ( int i = 0; i < bytes_read; i++ ) {
      char the_byte = buf[ i ];

      overlays.get_prediction_engine().new_user_byte( the_byte, local_framebuffer );

      if (pass_seq_has_zmodem(&network->ps) || zmodem_processing(&network->ps)) {
	goto skip;
      }

      if ( quit_sequence_started ) {
	if ( the_byte == '.' ) { /* Quit sequence is Ctrl-^ . */
	  if ( network->has_remote_addr() && (!network->shutdown_in_progress()) ) {
	    overlays.get_notification_engine().set_notification_string( wstring( L"Exiting on user request..." ), true );
	    network->start_shutdown();
	    return true;
	  } else {
	    return false;
	  }
	} else if ( the_byte == ',') {
	  pass_seq_full_reset(&network->ps);
	} else if ( the_byte == 0x1a ) { /* Suspend sequence is escape_key Ctrl-Z */
	  /* Restore terminal and terminal-driver state */
	  swrite( STDOUT_FILENO, display.close().c_str() );

	  if ( tcsetattr( STDIN_FILENO, TCSANOW, &saved_termios ) < 0 ) {
	    perror( "tcsetattr" );
	    exit( 1 );
	  }

	  printf( "\n\033[37;44m[mosh is suspended.]\033[m\n" );

	  fflush( NULL );

	  /* actually suspend */
	  kill( 0, SIGSTOP );

	  resume();
	} else if ( (the_byte == escape_pass_key) || (the_byte == escape_pass_key2) ) {
	  /* Emulation sequence to type escape_key is escape_key +
	     escape_pass_key (that is escape key without Ctrl) */
	  network->get_current_state().push_back( Parser::UserByte( escape_key ) );
	} else {
	  /* Escape key followed by anything other than . and ^ gets sent literally */
	  network->get_current_state().push_back( Parser::UserByte( escape_key ) );
	  network->get_current_state().push_back( Parser::UserByte( the_byte ) );	  
	}

	quit_sequence_started = false;

	if ( overlays.get_notification_engine().get_notification_string() == escape_key_help ) {
	  overlays.get_notification_engine().set_notification_string( L"" );
	}

	continue;
      }

      quit_sequence_started = (escape_key > 0) && (the_byte == escape_key) && (lf_entered || (! escape_requires_lf));
      if ( quit_sequence_started ) {
	lf_entered = false;
	overlays.get_notification_engine().set_notification_string( escape_key_help, true, false );
	continue;
      }

      lf_entered = ( (the_byte == 0x0A) || (the_byte == 0x0D) ); /* LineFeed, Ctrl-J, '\n' or CarriageReturn, Ctrl-M, '\r' */

      if ( the_byte == 0x0C ) { /* Ctrl-L */
	repaint_requested = true;
      }

    skip:
      network->get_current_state().push_back( Parser::UserByte( the_byte ) );
    }

    pass_seq_change_buf(&network->ps, 0, true);
  }

  return true;
}

bool STMClient::process_resize( void )
{
  /* get new size */
  if ( ioctl( STDIN_FILENO, TIOCGWINSZ, &window_size ) < 0 ) {
    perror( "ioctl TIOCGWINSZ" );
    return false;
  }
  
  /* tell remote emulator */
  Parser::Resize res( window_size.ws_col, window_size.ws_row );
  
  if ( !network->shutdown_in_progress() ) {
    network->get_current_state().push_back( res );
  }

  /* note remote emulator will probably reply with its own Resize to adjust our state */
  
  /* tell prediction engine */
  overlays.get_prediction_engine().reset();

  return true;
}

bool STMClient::main( void )
{
  /* initialize signal handling and structures */
  main_init();

  /* Drop unnecessary privileges */
#ifdef HAVE_PLEDGE
  /* OpenBSD pledge() syscall */
  if ( pledge( "stdio inet tty", NULL )) {
    perror( "pledge() failed" );
    exit( 1 );
  }
#endif

  /* prepare to poll for events */
  Select &sel = Select::get_instance();

  while ( 1 ) {
    try {
      output_new_frame();

      int wait_time = min( network->wait_time(), overlays.wait_time() );

      /* Handle startup "Connecting..." message */
      if ( still_connecting() ) {
	wait_time = min( 250, wait_time );
      }

      /* poll for events */
      /* network->fd() can in theory change over time */
      sel.clear_fds();

      std::vector< int > fd_list( network->fds() );

      if (!zmodem_on_tcp) {
	for ( std::vector< int >::const_iterator it = fd_list.begin();
	      it != fd_list.end();
	      it++ ) {
	  sel.add_fd( *it );
	}
      }

      sel.add_fd( STDIN_FILENO );

      if (network->tcp_sock >= 0) {
	sel.add_fd( network->tcp_sock );
      }

      int active_fds = sel.select( wait_time );
      if ( active_fds < 0 ) {
	perror( "select" );
	break;
      }

      bool network_ready_to_read = false;

      if (network->tcp_sock >= 0) {
	if (sel.read(network->tcp_sock)) {
	  cur_ps = &network->ps; /* for tcp_recv_from_server */
	  bool close_socket = !tcp_recv_from_server(network->tcp_sock);

	  if (zmodem_processing(&network->ps)) {
	    zmodem_on_tcp = true;
	  } else if (zmodem_on_tcp) {
	    zmodem_on_tcp = false;
	    close_socket = true;
	  }

	  if (close_socket) {
	    closesocket(network->tcp_sock);
	    network->tcp_sock = -1;
	  }

	  goto skip_udp;
	} else if (zmodem_on_tcp) {
	  if (!zmodem_processing(&network->ps)) {
	    zmodem_on_tcp = false;
	    closesocket(network->tcp_sock);
	    network->tcp_sock = -1;
	  }

	  goto skip_udp;
	}
      }

      for ( std::vector< int >::const_iterator it = fd_list.begin();
	    it != fd_list.end();
	    it++ ) {
	if ( sel.read( *it ) ) {
	  /* packet received from the network */
	  /* we only read one socket each run */
	  network_ready_to_read = true;
	}
      }

      /*
       * Don't call process_network_input() while reading from network->tcp_sock.
       * DRCS-Sixel: UTF-8 characters is transfered via UDP while
       *             DRCS-Sixel sequence is transferred via TCP.
       *             DRCS-Sixel must be transferred before UTF-8 sequence.
       */
      if ( network_ready_to_read ) {
	process_network_input();
      }

    skip_udp:
      if ( sel.read( STDIN_FILENO ) ) {
	/* input from the user needs to be fed to the network */
	if ( !process_user_input( STDIN_FILENO ) ) {
	  if ( !network->has_remote_addr() ) {
	    break;
	  } else if ( !network->shutdown_in_progress() ) {
	    overlays.get_notification_engine().set_notification_string( wstring( L"Exiting..." ), true );
	    network->start_shutdown();
	  }
	}
      }

      if ( sel.signal( SIGWINCH ) ) {
        /* resize */
        if ( !process_resize() ) { return false; }
      }

      if ( sel.signal( SIGCONT ) ) {
	resume();
      }

      if ( sel.signal( SIGTERM )
           || sel.signal( SIGINT )
           || sel.signal( SIGHUP )
           || sel.signal( SIGPIPE ) ) {
        /* shutdown signal */
        if ( !network->has_remote_addr() ) {
          break;
        } else if ( !network->shutdown_in_progress() ) {
          overlays.get_notification_engine().set_notification_string( wstring( L"Signal received, shutting down..." ), true );
          network->start_shutdown();
        }
      }

      /* quit if our shutdown has been acknowledged */
      if ( network->shutdown_in_progress() && network->shutdown_acknowledged() ) {
	clean_shutdown = true;
	break;
      }

      /* quit after shutdown acknowledgement timeout */
      if ( network->shutdown_in_progress() && network->shutdown_ack_timed_out() ) {
	break;
      }

      /* quit if we received and acknowledged a shutdown request */
      if ( network->counterparty_shutdown_ack_sent() ) {
	clean_shutdown = true;
	break;
      }

      /* write diagnostic message if can't reach server */
      if ( still_connecting()
	   && (!network->shutdown_in_progress())
	   && (timestamp() - network->get_latest_remote_state().timestamp > 250) ) {
	if ( timestamp() - network->get_latest_remote_state().timestamp > 15000 ) {
	  if ( !network->shutdown_in_progress() ) {
	    overlays.get_notification_engine().set_notification_string( wstring( L"Timed out waiting for server..." ), true );
	    network->start_shutdown();
	  }
	} else {
	  overlays.get_notification_engine().set_notification_string( connecting_notification );
	}
      } else if ( (network->get_remote_state_num() != 0)
		  && (overlays.get_notification_engine().get_notification_string()
		      == connecting_notification) ) {
	overlays.get_notification_engine().set_notification_string( L"" );
      }

      pass_seq_change_buf(&network->ps, 1, false);
      network->tick();
      pass_seq_change_buf(&network->ps, 0, false);

      string & send_error = network->get_send_error();
      if ( !send_error.empty() ) {
        overlays.get_notification_engine().set_network_error( send_error );
	send_error.clear();
      } else {
        overlays.get_notification_engine().clear_network_error();
      }
    } catch ( const Network::NetworkException &e ) {
      if ( !network->shutdown_in_progress() ) {
        overlays.get_notification_engine().set_network_error( e.what() );
      }

      struct timespec req;
      req.tv_sec = 0;
      req.tv_nsec = 200000000; /* 0.2 sec */
      nanosleep( &req, NULL );
      freeze_timestamp();
    } catch ( const Crypto::CryptoException &e ) {
      if ( e.fatal ) {
        throw;
      } else {
        wchar_t tmp[ 128 ];
        swprintf( tmp, 128, L"Crypto exception: %s", e.what() );
        overlays.get_notification_engine().set_notification_string( wstring( tmp ) );
      }
    }
  }

  if (network->tcp_sock >= 0) {
    closesocket(network->tcp_sock);
    network->tcp_sock = -1;
  }

  return clean_shutdown;
}

