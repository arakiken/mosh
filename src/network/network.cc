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

#include <sys/types.h>
#ifndef USE_WINSOCK
#include <sys/socket.h>
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#endif

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#ifndef USE_WINSOCK
#include <arpa/inet.h>
#endif

#include "dos_assert.h"
#include "fatal_assert.h"
#include "byteorder.h"
#include "network.h"
#include "crypto.h"

#include "timestamp.h"

#ifndef MSG_NONBLOCK
#define MSG_NONBLOCK 0
#endif

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT MSG_NONBLOCK
#endif

#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif

using namespace std;
using namespace Network;
using namespace Crypto;

const uint64_t DIRECTION_MASK = uint64_t(1) << 63;
const uint64_t SEQUENCE_MASK = uint64_t(-1) ^ DIRECTION_MASK;

int tcp_connect(in_addr_t a, int port) {
  int sock;

  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
#ifdef __DEBUG
    FILE *fp = fopen("moshlog.txt", "a");
    fprintf(fp, "socket failed.\n");
    fclose(fp);
#endif
    perror("socket");

    return -1;
  }

  struct sockaddr_in addr;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = PF_INET;
  addr.sin_addr.s_addr = a;
  addr.sin_port = htons(port);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
#ifdef __DEBUG
    FILE *fp = fopen("moshlog.txt", "a");
    fprintf(fp, "connect failed.\n");
    fclose(fp);
#endif
    perror("connect");

    closesocket(sock);

    return -1;
  }

#ifdef USE_WINSOCK
  u_long val = 1;
  ioctlsocket(sock, FIONBIO, &val);
#else
  fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
#endif

  return sock;
}

int tcp_start_server(int *port) {
  int sock;

  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");

    return -1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = PF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  for (*port = 8010; *port < 8100; (*port)++) {
    addr.sin_port = htons(*port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
	listen(sock, 1) == 0) {
      return sock;
    }
  }

  closesocket(sock);

  return -1;
}

int tcp_client_connected(int sock) {
  int consock;
  struct sockaddr_in addr;
  socklen_t len;

  if ((consock = accept(sock, (struct sockaddr *)&addr, &len)) < 0) {
    perror("accept");
  } else {
#ifdef USE_WINSOCK
    u_long val = 1;
    ioctlsocket(consock, FIONBIO, &val);
#else
    fcntl(consock, F_SETFL, fcntl(consock, F_GETFL, 0) | O_NONBLOCK);
#endif
  }

  closesocket(sock);

  return consock;
}


/* Read in packet */
Packet::Packet( const Message & message )
  : seq( message.nonce.val() & SEQUENCE_MASK ),
    direction( (message.nonce.val() & DIRECTION_MASK) ? TO_CLIENT : TO_SERVER ),
    timestamp( -1 ),
    timestamp_reply( -1 ),
    payload()
{
  dos_assert( message.text.size() >= 2 * sizeof( uint16_t ) );

  const uint16_t *data = (uint16_t *)message.text.data();
  timestamp = be16toh( data[ 0 ] );
  timestamp_reply = be16toh( data[ 1 ] );

  payload = string( message.text.begin() + 2 * sizeof( uint16_t ), message.text.end() );
}

/* Output from packet */
Message Packet::toMessage( void )
{
  uint64_t direction_seq = (uint64_t( direction == TO_CLIENT ) << 63) | (seq & SEQUENCE_MASK);

  uint16_t ts_net[ 2 ] = { static_cast<uint16_t>( htobe16( timestamp ) ),
                           static_cast<uint16_t>( htobe16( timestamp_reply ) ) };

  string timestamps = string( (char *)ts_net, 2 * sizeof( uint16_t ) );

  return Message( Nonce( direction_seq ), timestamps + payload );
}

Packet Connection::new_packet( const string &s_payload )
{
  uint16_t outgoing_timestamp_reply = -1;

  uint64_t now = timestamp();

  if ( now - saved_timestamp_received_at < 1000 ) { /* we have a recent received timestamp */
    /* send "corrected" timestamp advanced by how long we held it */
    outgoing_timestamp_reply = saved_timestamp + (now - saved_timestamp_received_at);
    saved_timestamp = -1;
    saved_timestamp_received_at = 0;
  }

  Packet p( direction, timestamp16(), outgoing_timestamp_reply, s_payload );

  return p;
}

void Connection::hop_port( void *ps )
{
  assert( !server );

  setup();
  assert( remote_addr_len != 0 );
  socks.push_back( Socket( remote_addr.sa.sa_family ) );

  prune_sockets(ps);
}

extern "C" {
/* defined in parserstate.h */
bool zmodem_processing( void *ps );
}

void Connection::prune_sockets( void *ps )
{
  if (zmodem_processing(ps)) {
    /* do nothing */
    return;
  }

  /* don't keep old sockets if the new socket has been working for long enough */
  if ( socks.size() > 1 ) {
    if ( timestamp() - last_port_choice > MAX_OLD_SOCKET_AGE ) {
      int num_to_kill = socks.size() - 1;
      for ( int i = 0; i < num_to_kill; i++ ) {
	socks.pop_front();
      }
    }
  } else {
    return;
  }

  /* make sure we don't have too many receive sockets open */
  if ( socks.size() > MAX_PORTS_OPEN ) {
    int num_to_kill = socks.size() - MAX_PORTS_OPEN;
    for ( int i = 0; i < num_to_kill; i++ ) {
      socks.pop_front();
    }
  }
}

Connection::Socket::Socket( int family )
  : _fd( socket( family, SOCK_DGRAM, 0 ) )
{
  if ( _fd < 0 ) {
    throw NetworkException( "socket", errno );
  }

  /* Disable path MTU discovery */
#ifdef HAVE_IP_MTU_DISCOVER
  int flag = IP_PMTUDISC_DONT;
  if ( setsockopt( _fd, IPPROTO_IP, IP_MTU_DISCOVER, &flag, sizeof flag ) < 0 ) {
    throw NetworkException( "setsockopt", errno );
  }
#endif

  //  int dscp = 0x92; /* OS X does not have IPTOS_DSCP_AF42 constant */
  int dscp = 0x02; /* ECN-capable transport only */
  if ( setsockopt( _fd, IPPROTO_IP, IP_TOS, (const char*)&dscp, sizeof dscp ) < 0 ) {
    //    perror( "setsockopt( IP_TOS )" );
  }

  /* request explicit congestion notification on received datagrams */
#ifdef HAVE_IP_RECVTOS
  int tosflag = true;
  if ( setsockopt( _fd, IPPROTO_IP, IP_RECVTOS, &tosflag, sizeof tosflag ) < 0 ) {
    /* FreeBSD disallows this option on IPv6 sockets. */
    if ( family == IPPROTO_IP ) {
      perror( "setsockopt( IP_RECVTOS )" );
    }
  }
#endif

#ifdef USE_WINSOCK
  int optval = 1;
  if ( setsockopt( _fd, IPPROTO_IP, IP_PKTINFO, (const char*)&optval, sizeof(optval)) < 0) {
    perror( "setsockopt( IP_PKTINFO )" );
  }
#endif
}

void Connection::setup( void )
{
  last_port_choice = timestamp();
}

const std::vector< int > Connection::fds( void ) const
{
  std::vector< int > ret;

  for ( std::deque< Socket >::const_iterator it = socks.begin();
	it != socks.end();
	it++ ) {
    ret.push_back( it->fd() );
  }

  return ret;
}

void Connection::set_MTU( int family )
{
  switch ( family ) {
  case AF_INET:
    MTU = DEFAULT_IPV4_MTU - IPV4_HEADER_LEN;
    break;
  case AF_INET6:
    MTU = DEFAULT_IPV6_MTU - IPV6_HEADER_LEN;
    break;
  default:
    throw NetworkException( "Unknown address family", 0 );
  }
}

class AddrInfo {
public:
  struct addrinfo *res;
  AddrInfo( const char *node, const char *service,
	    const struct addrinfo *hints ) :
    res( NULL ) {
    int errcode = getaddrinfo( node, service, hints, &res );
    if ( errcode != 0 ) {
      throw NetworkException( std::string( "Bad IP address (" ) + (node != NULL ? node : "(null)") + "): " + gai_strerror( errcode ), 0 );
    }
  }
  ~AddrInfo() { freeaddrinfo(res); }
private:
  AddrInfo(const AddrInfo &);
  AddrInfo &operator=(const AddrInfo &);
};

Connection::Connection( const char *desired_ip, const char *desired_port ) /* server */
  : socks(),
    has_remote_addr( false ),
    remote_addr(),
    remote_addr_len( 0 ),
    server( true ),
    MTU( DEFAULT_SEND_MTU ),
    key(),
    session( key ),
    direction( TO_CLIENT ),
    saved_timestamp( -1 ),
    saved_timestamp_received_at( 0 ),
    expected_receiver_seq( 0 ),
    last_heard( -1 ),
    last_port_choice( -1 ),
    last_roundtrip_success( -1 ),
    RTT_hit( false ),
    SRTT( 1000 ),
    RTTVAR( 500 ),
    send_error()
{
  setup();

  /* The mosh wrapper always gives an IP request, in order
     to deal with multihomed servers. The port is optional. */

  /* If an IP request is given, we try to bind to that IP, but we also
     try INADDR_ANY. If a port request is given, we bind only to that port. */

  /* convert port numbers */
  int desired_port_low = -1;
  int desired_port_high = -1;

  if ( desired_port && !parse_portrange( desired_port, desired_port_low, desired_port_high ) ) {
    throw NetworkException("Invalid port range", 0);
  }

  /* try to bind to desired IP first */
  if ( desired_ip ) {
    try {
      if ( try_bind( desired_ip, desired_port_low, desired_port_high ) ) { return; }
    } catch ( const NetworkException &e ) {
      fprintf( stderr, "Error binding to IP %s: %s\n",
	       desired_ip,
	       e.what() );
    }
  }

  /* now try any local interface */
  try {
    if ( try_bind( NULL, desired_port_low, desired_port_high ) ) { return; }
  } catch ( const NetworkException &e ) {
    fprintf( stderr, "Error binding to any interface: %s\n",
	     e.what() );
    throw; /* this time it's fatal */
  }

  assert( false );
  throw NetworkException( "Could not bind", errno );
}

bool Connection::try_bind( const char *addr, int port_low, int port_high )
{
  struct addrinfo hints;
  memset( &hints, 0, sizeof( hints ) );
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;
  AddrInfo ai( addr, "0", &hints );

  Addr local_addr;
  socklen_t local_addr_len = ai.res->ai_addrlen;
  memcpy( &local_addr.sa, ai.res->ai_addr, local_addr_len );

  int search_low = PORT_RANGE_LOW, search_high = PORT_RANGE_HIGH;

  if ( port_low != -1 ) { /* low port preference */
    search_low = port_low;
  }
  if ( port_high != -1 ) { /* high port preference */
    search_high = port_high;
  }

  socks.push_back( Socket( local_addr.sa.sa_family ) );
  for ( int i = search_low; i <= search_high; i++ ) {
    switch (local_addr.sa.sa_family) {
    case AF_INET:
      local_addr.sin.sin_port = htons( i );
      break;
    case AF_INET6:
      local_addr.sin6.sin6_port = htons( i );
      break;
    default:
      throw NetworkException( "Unknown address family", 0 );
    }

    if ( local_addr.sa.sa_family == AF_INET6
      && memcmp(&local_addr.sin6.sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0 ) {
      const int off = 0;
      if ( setsockopt( sock(), IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof(off) ) ) {
        perror( "setsockopt( IPV6_V6ONLY, off )" );
      }
    }

    if ( bind( sock(), &local_addr.sa, local_addr_len ) == 0 ) {
      set_MTU( local_addr.sa.sa_family );
      return true;
    } else if ( i == search_high ) { /* last port to search */
      int saved_errno = errno;
      socks.pop_back();
      char host[ NI_MAXHOST ], serv[ NI_MAXSERV ];
      int errcode = getnameinfo( &local_addr.sa, local_addr_len,
				 host, sizeof( host ), serv, sizeof( serv ),
				 NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV );
      if ( errcode != 0 ) {
	throw NetworkException( std::string( "bind: getnameinfo: " ) + gai_strerror( errcode ), 0 );
      }
      fprintf( stderr, "Failed binding to %s:%s\n",
	       host, serv );
      throw NetworkException( "bind", saved_errno );
    }
  }

  assert( false );
  return false;
}

Connection::Connection( const char *key_str, const char *ip, const char *port ) /* client */
  : socks(),
    has_remote_addr( false ),
    remote_addr(),
    remote_addr_len( 0 ),
    server( false ),
    MTU( DEFAULT_SEND_MTU ),
    key( key_str ),
    session( key ),
    direction( TO_SERVER ),
    saved_timestamp( -1 ),
    saved_timestamp_received_at( 0 ),
    expected_receiver_seq( 0 ),
    last_heard( -1 ),
    last_port_choice( -1 ),
    last_roundtrip_success( -1 ),
    RTT_hit( false ),
    SRTT( 1000 ),
    RTTVAR( 500 ),
    send_error()
{
  setup();

  /* associate socket with remote host and port */
  struct addrinfo hints;
  memset( &hints, 0, sizeof( hints ) );
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  AddrInfo ai( ip, port, &hints );
  fatal_assert( static_cast<size_t>( ai.res->ai_addrlen ) <= sizeof( remote_addr ) );
  remote_addr_len = ai.res->ai_addrlen;
  memcpy( &remote_addr.sa, ai.res->ai_addr, remote_addr_len );

  has_remote_addr = true;

  socks.push_back( Socket( remote_addr.sa.sa_family ) );

  set_MTU( remote_addr.sa.sa_family );
}

void Connection::send( const string & s, void *ps )
{
  if ( !has_remote_addr ) {
    return;
  }

  Packet px = new_packet( s );

  string p = session.encrypt( px.toMessage() );

#ifdef __DEBUG
  FILE *fp = fopen("moshlog.txt", "a");
  fprintf(fp, "Socket status (send): size %d fd %d bytes %d port %d\n",
	  (int)socks.size(), sock(), (int)p.size(), (int)remote_addr.sin.sin_port);
  fclose(fp);
#endif

#ifdef USE_WINSOCK
  u_long val = 1;
  ioctlsocket(sock(), FIONBIO, &val);
#endif

  ssize_t bytes_sent = sendto( sock(), p.data(), p.size(), MSG_DONTWAIT,
			       &remote_addr.sa, remote_addr_len );

#ifdef USE_WINSOCK
  val = 0;
  ioctlsocket(sock(), FIONBIO, &val);
#endif

  if ( bytes_sent != static_cast<ssize_t>( p.size() ) ) {
    /* Make sendto() failure available to the frontend. */
    send_error = "sendto: ";
    send_error += strerror( errno );

    if ( errno == EMSGSIZE ) {
      MTU = DEFAULT_SEND_MTU; /* payload MTU of last resort */
    }

#ifdef __DEBUG
    FILE *fp = fopen("moshlog.txt", "a");
    fprintf(fp, "sendto() fails. [errno %d]\n", errno);
    fclose(fp);
#endif
  }

  uint64_t now = timestamp();
  if ( server ) {
    if ( now - last_heard > SERVER_ASSOCIATION_TIMEOUT ) {
      has_remote_addr = false;
      fprintf( stderr, "Server now detached from client.\n" );
    }
  } else { /* client */
    if ( ( now - last_port_choice > PORT_HOP_INTERVAL )
	 && ( now - last_roundtrip_success > PORT_HOP_INTERVAL ) ) {
      hop_port(ps);
    }
  }
}

string Connection::recv( void *ps )
{
  assert( !socks.empty() );

#ifdef __DEBUG
  FILE *fp = fopen("moshlog.txt", "a");
  fprintf(fp, "Socket status (recv): size %d\n", (int)socks.size());
  fclose(fp);
#endif

  for ( std::deque< Socket >::const_iterator it = socks.begin();
	it != socks.end();
	it++ ) {
#ifdef __DEBUG
    FILE *fp = fopen("moshlog.txt", "a");
    fprintf(fp, "  fd %d\n", it->fd());
    fclose(fp);
#endif

    bool islast = (it + 1) == socks.end();
    string payload;
    try {
      payload = recv_one( it->fd(), !islast );
    } catch ( NetworkException & e ) {
      if (
#ifdef USE_WINSOCK
           WSAGetLastError() == WSAEWOULDBLOCK ||
#endif
           (e.the_errno == EAGAIN)
	   || (e.the_errno == EWOULDBLOCK) ) {
	assert( !islast );
	continue;
      } else {
	throw;
      }
    }

    /* succeeded */
    prune_sockets(ps);
    return payload;
  }
  assert( false );
  return "";
}

string Connection::recv_one( int sock_to_recv, bool nonblocking )
{
  /* receive source address, ECN, and payload in msghdr structure */
  Addr packet_remote_addr;
#ifndef USE_WINSOCK
  struct msghdr header;
  struct iovec msg_iovec;
#else
  WSAMSG header;
  WSABUF msg_iovec;
#endif

  char msg_payload[ Session::RECEIVE_MTU ];
  char msg_control[ Session::RECEIVE_MTU ];

  /* receive source address */
#ifndef USE_WINSOCK
  header.msg_name = &packet_remote_addr;
  header.msg_namelen = sizeof packet_remote_addr;
#else
  header.name = &packet_remote_addr.sa;
  header.namelen = sizeof packet_remote_addr.sin;
#endif

  /* receive payload */
#ifndef USE_WINSOCK
  msg_iovec.iov_base = msg_payload;
  msg_iovec.iov_len = sizeof msg_payload;
  header.msg_iov = &msg_iovec;
  header.msg_iovlen = 1;
#else
  msg_iovec.buf = msg_payload;
  msg_iovec.len = sizeof msg_payload;
  header.lpBuffers = &msg_iovec;
  header.dwBufferCount = 1;
#endif

  /* receive explicit congestion notification */
#ifndef USE_WINSOCK
  header.msg_control = msg_control;
  header.msg_controllen = sizeof msg_control;
#else
  header.Control.buf = msg_control;
  header.Control.len = sizeof msg_control;
#endif

  /* receive flags */
#ifndef USE_WINSOCK
  header.msg_flags = 0;
#else
  header.dwFlags = 0;
#endif

#ifndef USE_WINSOCK
  ssize_t received_len = recvmsg( sock_to_recv, &header, nonblocking ? MSG_DONTWAIT : 0 );

  if ( received_len < 0 ) {
    throw NetworkException( "recvmsg", errno );
  }
#else
  static GUID guid = WSAID_WSARECVMSG;
  static LPFN_WSARECVMSG func;
  static DWORD nbytes;
  if ( !func &&
       WSAIoctl( sock_to_recv, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid), &func, sizeof(func), &nbytes, NULL, NULL ) == SOCKET_ERROR ) {
    throw NetworkException( "WSAIoctl", 1 );
  }

  DWORD received_len;
  u_long val = 1;
  ioctlsocket(sock_to_recv, FIONBIO, &val);
  while ( (*func)( sock_to_recv, &header, &received_len, NULL, NULL ) == SOCKET_ERROR ||
       received_len < 0 ) {
    throw NetworkException( "WSARecvMsg", 1 );
  }
  val = 0;
  ioctlsocket(sock_to_recv, FIONBIO, &val);
#endif

#ifndef USE_WINSOCK
  if ( header.msg_flags & MSG_TRUNC )
#else
  if ( header.dwFlags & MSG_TRUNC )
#endif
  {
    throw NetworkException( "Received oversize datagram", errno );
  }

  /* receive ECN */
  bool congestion_experienced = false;

#ifndef USE_WINSOCK
  struct cmsghdr *ecn_hdr = CMSG_FIRSTHDR( &header );
#else
  WSACMSGHDR *ecn_hdr = WSA_CMSG_FIRSTHDR( &header );
#endif

  if ( ecn_hdr
       && (ecn_hdr->cmsg_level == IPPROTO_IP)
       && ((ecn_hdr->cmsg_type == IP_TOS)
#ifdef IP_RECVTOS
	   || (ecn_hdr->cmsg_type == IP_RECVTOS)
#endif
	   )) {
    /* got one */
#ifndef USE_WINSOCK
    uint8_t *ecn_octet_p = (uint8_t *)CMSG_DATA( ecn_hdr );
#else
    uint8_t *ecn_octet_p = (uint8_t *)WSA_CMSG_DATA( ecn_hdr );
#endif
    assert( ecn_octet_p );

    if ( (*ecn_octet_p & 0x03) == 0x03 ) {
      congestion_experienced = true;
    }
  }

  Packet p( session.decrypt( msg_payload, received_len ) );

  dos_assert( p.direction == (server ? TO_SERVER : TO_CLIENT) ); /* prevent malicious playback to sender */

  if ( p.seq >= expected_receiver_seq ) { /* don't use out-of-order packets for timestamp or targeting */
    expected_receiver_seq = p.seq + 1; /* this is security-sensitive because a replay attack could otherwise
					  screw up the timestamp and targeting */

    if ( p.timestamp != uint16_t(-1) ) {
      saved_timestamp = p.timestamp;
      saved_timestamp_received_at = timestamp();

      if ( congestion_experienced ) {
	/* signal counterparty to slow down */
	/* this will gradually slow the counterparty down to the minimum frame rate */
	saved_timestamp -= CONGESTION_TIMESTAMP_PENALTY;
	if ( server ) {
	  fprintf( stderr, "Received explicit congestion notification.\n" );
	}
      }
    }

    if ( p.timestamp_reply != uint16_t(-1) ) {
      uint16_t now = timestamp16();
      double R = timestamp_diff( now, p.timestamp_reply );

      if ( R < 5000 ) { /* ignore large values, e.g. server was Ctrl-Zed */
	if ( !RTT_hit ) { /* first measurement */
	  SRTT = R;
	  RTTVAR = R / 2;
	  RTT_hit = true;
	} else {
	  const double alpha = 1.0 / 8.0;
	  const double beta = 1.0 / 4.0;
	  
	  RTTVAR = (1 - beta) * RTTVAR + ( beta * fabs( SRTT - R ) );
	  SRTT = (1 - alpha) * SRTT + ( alpha * R );
	}
      }
    }

    /* auto-adjust to remote host */
    has_remote_addr = true;
    last_heard = timestamp();

    if ( server ) { /* only client can roam */
      if (
#ifndef USE_WINSOCK
	remote_addr_len != header.msg_namelen ||
#else
	remote_addr_len != header.namelen ||
#endif
	   memcmp( &remote_addr, &packet_remote_addr, remote_addr_len ) != 0 ) {
	remote_addr = packet_remote_addr;
#ifndef USE_WINSOCK
	remote_addr_len = header.msg_namelen;
#else
	remote_addr_len = header.namelen;
#endif
	char host[ NI_MAXHOST ], serv[ NI_MAXSERV ];
	int errcode = getnameinfo( &remote_addr.sa, remote_addr_len,
				   host, sizeof( host ), serv, sizeof( serv ),
				   NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV );
	if ( errcode != 0 ) {
	  throw NetworkException( std::string( "recv_one: getnameinfo: " ) + gai_strerror( errcode ), 0 );
	}
	fprintf( stderr, "Server now attached to client at %s:%s\n",
		 host, serv );
      }
    }
  }

  return p.payload; /* we do return out-of-order or duplicated packets to caller */
}

std::string Connection::port( void ) const
{
  Addr local_addr;
  socklen_t addrlen = sizeof( local_addr );

  if ( getsockname( sock(), &local_addr.sa, &addrlen ) < 0 ) {
    throw NetworkException( "getsockname", errno );
  }

  char serv[ NI_MAXSERV ];
  int errcode = getnameinfo( &local_addr.sa, addrlen,
			     NULL, 0, serv, sizeof( serv ),
			     NI_DGRAM | NI_NUMERICSERV );
  if ( errcode != 0 ) {
    throw NetworkException( std::string( "port: getnameinfo: " ) + gai_strerror( errcode ), 0 );
  }

  return std::string( serv );
}

uint64_t Network::timestamp( void )
{
  return frozen_timestamp();
}

uint16_t Network::timestamp16( void )
{
  uint16_t ts = timestamp() % 65536;
  if ( ts == uint16_t(-1) ) {
    ts++;
  }
  return ts;
}

uint16_t Network::timestamp_diff( uint16_t tsnew, uint16_t tsold )
{
  int diff = tsnew - tsold;
  if ( diff < 0 ) {
    diff += 65536;
  }
  
  assert( diff >= 0 );
  assert( diff <= 65535 );

  return diff;
}

uint64_t Connection::timeout( void ) const
{
  uint64_t RTO = lrint( ceil( SRTT + 4 * RTTVAR ) );
  if ( RTO < MIN_RTO ) {
    RTO = MIN_RTO;
  } else if ( RTO > MAX_RTO ) {
    RTO = MAX_RTO;
  }
  return RTO;
}

#ifdef USE_WINSOCK
/*
 * XXX
 * socks.push_back(Socket(...))
 * => A) Socket(...)
 *    B) Socket(A) in push_back() ... Copy _fd from A to B (See Socket(const Socket &))
 *    C) A::~Socket() => Don't closesocket()
 * socks.pop_back(B)
 * => D) B::~Socket() => Do closesocket()
 */
static int dup_fds[16];
static int num_dup_fds;
#endif

Connection::Socket::~Socket()
{
#ifndef USE_WINSOCK
  fatal_assert ( close( _fd ) == 0 );
#else
  for (int i = 0; i < num_dup_fds; i++) {
    if (_fd == dup_fds[i]) {
      dup_fds[i] = dup_fds[--num_dup_fds];
      return;
    }
  }

  closesocket( _fd );
#endif
}

Connection::Socket::Socket( const Socket & other )
#ifndef USE_WINSOCK
  : _fd( dup( other._fd ) )
#endif
{
#ifndef USE_WINSOCK
  if ( _fd < 0 ) {
    throw NetworkException( "socket", errno );
  }
#elif 0
  HANDLE dupsock;
  if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)other._fd, GetCurrentProcess(), &dupsock,
       0, FALSE, 0)) {
    throw NetworkException( "socket", errno );
  }

  _fd = (int)dupsock;
#else
  _fd = other._fd;

  if (num_dup_fds == sizeof(dup_fds) / sizeof(dup_fds[0])) {
    throw NetworkException( "dup_fds", 0 );
  }

  dup_fds[num_dup_fds++] = _fd;
#endif
}

Connection::Socket & Connection::Socket::operator=( const Socket & other )
{
  if ( dup2( other._fd, _fd ) < 0 ) {
    throw NetworkException( "socket", errno );
  }

  return *this;
}

bool Connection::parse_portrange( const char * desired_port, int & desired_port_low, int & desired_port_high )
{
  /* parse "port" or "portlow:porthigh" */
  desired_port_low = desired_port_high = 0;
  char *end;
  long value;

  /* parse first (only?) port */
  errno = 0;
  value = strtol( desired_port, &end, 10 );
  if ( (errno != 0) || (*end != '\0' && *end != ':') ) {
    fprintf( stderr, "Invalid (low) port number (%s)\n", desired_port );
    return false;
  }
  if ( (value < 0) || (value > 65535) ) {
    fprintf( stderr, "(Low) port number %ld outside valid range [0..65535]\n", value );
    return false;
  }

  desired_port_low = (int)value;
  if (*end == '\0') { /* not a port range */
    desired_port_high = desired_port_low;
    return true;
  }
  /* port range; parse high port */
  const char * cp = end + 1;
  errno = 0;
  value = strtol( cp, &end, 10 );
  if ( (errno != 0) || (*end != '\0') ) {
    fprintf( stderr, "Invalid high port number (%s)\n", cp );
    return false;
  }
  if ( (value < 0) || (value > 65535) ) {
    fprintf( stderr, "High port number %ld outside valid range [0..65535]\n", value );
    return false;
  }

  desired_port_high = (int)value;
  if ( desired_port_low > desired_port_high ) {
    fprintf( stderr, "Low port %d greater than high port %d\n", desired_port_low, desired_port_high );
    return false;
  }

  if ( desired_port_low == 0 ) {
    fprintf( stderr, "Low port 0 incompatible with port ranges\n" );
    return false;
  }


  return true;
}
