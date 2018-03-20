//------------------------------------------------------------------------------
// Copyright (c) 2011-2012 by European Organization for Nuclear Research (CERN)
// Author: Michal Simon <simonm@cern.ch>
//------------------------------------------------------------------------------
// XRootD is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// XRootD is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with XRootD.  If not, see <http://www.gnu.org/licenses/>.
//------------------------------------------------------------------------------

#include "XrdCl/XrdClTls.hh"

namespace XrdCl
{

  Tls::Tls( int sfd ) : hsDone( false )
  {
    sbio = BIO_new_socket( sfd, BIO_NOCLOSE );
    BIO_set_nbio( sbio, 1 );
    ssl  = SSL_new( XrdTls::Context::Instance() );
    SSL_set_connect_state( ssl ); /* ssl client mode */
    SSL_set_bio( ssl, sbio, sbio );
  }

  Tls::~Tls()
  {
    SSL_free( ssl );   /* free the SSL object and its BIO's */
  }

  Status Tls::Read( char *buffer, size_t size, int &bytesRead )
  {
    //------------------------------------------------------------------------
    // If necessary, SSL_read() will negotiate a TLS/SSL session, so we don't
    // have to explicitly call SSL_connect or SSL_do_handshake.
    //------------------------------------------------------------------------
    int rc = SSL_read( ssl, buffer, size );
    if( rc > 0 ) bytesRead = rc;
    else hsDone = bool( SSL_is_init_finished( ssl ) );
    return ToStatus( rc );
  }

  Status Tls::Write( char *buffer, size_t size, int &bytesWritten )
  {
    //------------------------------------------------------------------------
    // If necessary, SSL_write() will negotiate a TLS/SSL session, so we don't
    // have to explicitly call SSL_connect or SSL_do_handshake.
    //------------------------------------------------------------------------
    int rc = SSL_write( ssl, buffer, size );
    if( rc > 0 ) bytesWritten = rc;
    else hsDone = bool( SSL_is_init_finished( ssl ) );
    return ToStatus( rc );
  }

  Status Tls::ToStatus( int rc )
  {
    int error = SSL_get_error( ssl, rc );

    switch( error )
    {
      case SSL_ERROR_NONE: return Status();

      case SSL_ERROR_WANT_WRITE:
      case SSL_ERROR_WANT_READ: return Status( stOK, suRetry );

      case SSL_ERROR_ZERO_RETURN:
      case SSL_ERROR_SYSCALL:
      default:
        return Status( stError, errTlsError, error );
    }
  }

  //----------------------------------------------------------------------------
  // Read from TLS layer helper
  //----------------------------------------------------------------------------
  Status ReadFrom( Tls *tls, char *buffer, size_t size, int &bytesRead )
  {
    return tls->Read( buffer, size, bytesRead );
  }

}
