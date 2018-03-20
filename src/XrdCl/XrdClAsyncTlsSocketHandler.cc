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

#include "XrdCl/XrdClAsyncTlsSocketHandler.hh"
#include "XrdCl/XrdClXRootDMsgHandler.hh"
#include "XrdCl/XrdClXRootDTransport.hh"
#include "XrdCl/XrdClTls.hh"
#include "XrdCl/XrdClStream.hh"
#include "XrdCl/XrdClLog.hh"

namespace XrdCl
{
  //----------------------------------------------------------------------------
  // Constructor
  //----------------------------------------------------------------------------
  AsyncTlsSocketHandler::AsyncTlsSocketHandler( Poller           *poller,
                                                TransportHandler *transport,
                                                AnyObject        *channelData,
                                                uint16_t          subStreamNum ):
    AsyncSocketHandler( poller, transport, channelData, subStreamNum ),
    pXrdTransport( dynamic_cast<XRootDTransport*>( transport ) ),
    pXrdHandler( 0 )
  {

  }

  //----------------------------------------------------------------------------
  // Destructor
  //----------------------------------------------------------------------------
  AsyncTlsSocketHandler::~AsyncTlsSocketHandler()
  {

  }

  //----------------------------------------------------------------------------
  // Connect returned
  //----------------------------------------------------------------------------
  void AsyncTlsSocketHandler::OnConnectionReturn()
  {
    AsyncSocketHandler::OnConnectionReturn();

    //--------------------------------------------------------------------------
    // Initialize the TLS layer
    //--------------------------------------------------------------------------
    pTls.reset( new Tls( pSocket->GetFD() ) );
  }

  //----------------------------------------------------------------------------
  // Got a write readiness event
  //----------------------------------------------------------------------------
  void AsyncTlsSocketHandler::OnWrite()
  {
    //--------------------------------------------------------------------------
    // Pick up a message if we're not in process of writing something
    //--------------------------------------------------------------------------
    if( !pOutgoing )
    {
      pOutMsgDone = false;
      std::pair<Message *, OutgoingMsgHandler *> toBeSent;
      toBeSent = pStream->OnReadyToWrite( pSubStreamNum );
      pOutgoing = toBeSent.first; pOutHandler = toBeSent.second;

      if( !pOutgoing )
        return;

      pOutgoing->SetCursor( 0 );
      pOutMsgSize = pOutgoing->GetSize();
    }

    uint32_t outSize = pOutgoing->GetSize();

    ChunkList *chunks = 0;
    uint32_t  *asyncOffset = 0;

    if( pOutHandler->IsRaw() ) // TODO do it only once
    {
      if( pXrdHandler != pOutHandler )
        pXrdHandler = dynamic_cast<XRootDMsgHandler*>( pOutHandler );

      if( !pXrdHandler )
      {
        OnFault( Status( stError, errNotSupported ) );
        return;
      }

      chunks = pXrdHandler->GetMessageBody( asyncOffset );
      Log    *log = DefaultEnv::GetLog();
      log->Dump( AsyncSockMsg, "[%s] Will write the payload in one go with "
                 "the header for message: %s (0x%x).", pStreamName.c_str(),
                 pOutgoing->GetDescription().c_str(), pOutgoing );

      for( auto itr = chunks->begin(); itr != chunks->end(); ++itr )
      {
        outSize += itr->length;
        asyncOffset += itr->length;
      }

      if( outSize > pOutgoing->GetSize() )
      {
        uint32_t cursor = pOutgoing->GetSize();
        pOutgoing->ReAllocate( outSize );
        pOutgoing->SetCursor( cursor );
        for( auto itr = chunks->begin(); itr != chunks->end(); ++itr )
          pOutgoing->Append( (char*)itr->buffer, itr->length );
        pOutgoing->SetCursor( 0 );
      }
    }

    //--------------------------------------------------------------------------
    // Try to write the outgoing message
    //--------------------------------------------------------------------------
    Status st = WriteCurrentMessage( pOutgoing );

    if( !st.IsOK() )
    {
      OnFault( st );
      return;
    }

    if( st.code == suRetry )
      return;

    Log *log = DefaultEnv::GetLog();
    log->Dump( AsyncSockMsg, "[%s] Successfully sent message: %s (0x%x).",
               pStreamName.c_str(), pOutgoing->GetDescription().c_str(),
               pOutgoing );

    pStream->OnMessageSent( pSubStreamNum, pOutgoing, pOutMsgSize );
    pOutgoing = 0;

    //--------------------------------------------------------------------------
    // Disable the respective substream if empty
    //--------------------------------------------------------------------------
    pStream->DisableIfEmpty( pSubStreamNum );
  }

  //----------------------------------------------------------------------------
  // Got a write readiness event while handshaking
  //----------------------------------------------------------------------------
  void AsyncTlsSocketHandler::OnWriteWhileHandshaking()
  {
    Status st;
    if( !pHSOutgoing )
    {
      if( !(st = DisableUplink()).IsOK() )
        OnFaultWhileHandshaking( st );
      return;
    }

    if( !(st = WriteCurrentMessage( pHSOutgoing )).IsOK() )
    {
      OnFaultWhileHandshaking( st );
      return;
    }

    if( st.code != suRetry )
    {
      delete pHSOutgoing;
      pHSOutgoing = 0;
      if( !(st = DisableUplink()).IsOK() )
        OnFaultWhileHandshaking( st );
      return;
    }
  }

  //----------------------------------------------------------------------------
  // Write the current message
  //----------------------------------------------------------------------------
  Status AsyncTlsSocketHandler::WriteCurrentMessage( Message *toWrite )
  {
    Log *log = DefaultEnv::GetLog();

    //--------------------------------------------------------------------------
    // Try to write down the current message
    //--------------------------------------------------------------------------
    Message  *msg             = toWrite;
    uint32_t  leftToBeWritten = msg->GetSize()-msg->GetCursor();

    while( leftToBeWritten )
    {
      int bytesWritten = 0;
      Status status = pTls->Write( msg->GetBufferAtCursor(), leftToBeWritten, bytesWritten );

      //------------------------------------------------------------------------
      // Writing operation would block! So we are done for now, but we will
      // return
      //------------------------------------------------------------------------
      if( status.IsOK() && status.code == suRetry )
        return status;

      if( !status.IsOK() )
      {
        //----------------------------------------------------------------------
        // Actual tls error error!
        //----------------------------------------------------------------------
        toWrite->SetCursor( 0 );
        return status;
      }

      msg->AdvanceCursor( bytesWritten );
      leftToBeWritten -= bytesWritten;
    }

    //--------------------------------------------------------------------------
    // We have written the message successfully
    //--------------------------------------------------------------------------
    log->Dump( AsyncSockMsg, "[%s] Wrote a message: %s (0x%x), %d bytes",
               pStreamName.c_str(), toWrite->GetDescription().c_str(),
               toWrite, toWrite->GetSize() );
    return Status();
  }

  //----------------------------------------------------------------------------
  // Got a read readiness event
  //----------------------------------------------------------------------------
  void AsyncTlsSocketHandler::OnRead()
  {
    //--------------------------------------------------------------------------
    // There is no incoming message currently being processed so we create
    // a new one
    //--------------------------------------------------------------------------
    if( !pIncoming )
    {
      pHeaderDone  = false;
      pIncoming    = new Message();
      pIncHandler  = std::make_pair( (IncomingMsgHandler*)0, false );
      pIncMsgSize  = 0;
    }

    Status  st;
    Log    *log = DefaultEnv::GetLog();

    //--------------------------------------------------------------------------
    // We need to read the header first
    //--------------------------------------------------------------------------
    if( !pHeaderDone )
    {
      st = pXrdTransport->GetHeader( pIncoming, pTls.get() );
      if( !st.IsOK() )
      {
        OnFault( st );
        return;
      }

      if( st.code == suRetry )
        return;

      log->Dump( AsyncSockMsg, "[%s] Received message header for 0x%x size: %d",
                pStreamName.c_str(), pIncoming, pIncoming->GetCursor() );
      pIncMsgSize = pIncoming->GetCursor();
      pHeaderDone = true;
      std::pair<IncomingMsgHandler *, bool> raw;
      pIncHandler = pStream->InstallIncHandler( pIncoming, pSubStreamNum );

      if( pIncHandler.first )
      {
        log->Dump( AsyncSockMsg, "[%s] Will use the raw handler to read body "
                   "of message 0x%x", pStreamName.c_str(), pIncoming );
      }
    }

    //--------------------------------------------------------------------------
    // We need to call a raw message handler to get the data from the socket
    //--------------------------------------------------------------------------
    if( pIncHandler.first )
    {
      if( pXrdHandler != pIncHandler.first )
        pXrdHandler = dynamic_cast<XRootDMsgHandler*>( pIncHandler.first );

      if( !pXrdHandler )
      {
        OnFault( Status( stError, errNotSupported ) );
        return;
      }

      uint32_t bytesRead = 0;
      st = pXrdHandler->ReadMessageBody( pIncoming, pTls.get(), bytesRead );
      if( !st.IsOK() )
      {
        OnFault( st );
        return;
      }
      pIncMsgSize += bytesRead;

      if( st.code == suRetry )
        return;
    }
    //--------------------------------------------------------------------------
    // No raw handler, so we read the message to the buffer
    //--------------------------------------------------------------------------
    else
    {
      st = pXrdTransport->GetBody( pIncoming, pTls.get() );
      if( !st.IsOK() )
      {
        OnFault( st );
        return;
      }

      if( st.code == suRetry )
        return;

      pIncMsgSize = pIncoming->GetSize();
    }

    //--------------------------------------------------------------------------
    // Report the incoming message
    //--------------------------------------------------------------------------
    log->Dump( AsyncSockMsg, "[%s] Received message 0x%x of %d bytes",
               pStreamName.c_str(), pIncoming, pIncMsgSize );

    pStream->OnIncoming( pSubStreamNum, pIncoming, pIncMsgSize );
    pIncoming = 0;
  }

  //----------------------------------------------------------------------------
  // Got a read readiness event while handshaking
  //----------------------------------------------------------------------------
  void AsyncTlsSocketHandler::OnReadWhileHandshaking()
  {
    //--------------------------------------------------------------------------
    // Read the message and let the transport handler look at it when
    // reading has finished
    //--------------------------------------------------------------------------
    Status st = ReadMessage( pHSIncoming );
    if( !st.IsOK() )
    {
      OnFaultWhileHandshaking( st );
      return;
    }

    if( st.code != suDone )
      return;

    AsyncSocketHandler::HandleHandShake();
  }

  //----------------------------------------------------------------------------
  // Read a message
  //----------------------------------------------------------------------------
  Status AsyncTlsSocketHandler::ReadMessage( Message *&toRead )
  {
    if( !toRead )
    {
      pHeaderDone = false;
      toRead      = new Message();
    }

    Status  st;
    Log    *log = DefaultEnv::GetLog();
    if( !pHeaderDone )
    {
      st = pXrdTransport->GetHeader( toRead, pTls.get() );
      if( st.IsOK() && st.code == suDone )
      {
        log->Dump( AsyncSockMsg,
                  "[%s] Received message header, size: %d",
                  pStreamName.c_str(), toRead->GetCursor() );
        pHeaderDone = true;
      }
      else
        return st;
    }

    st = pXrdTransport->GetBody( toRead, pTls.get() );
    if( st.IsOK() && st.code == suDone )
    {
      log->Dump( AsyncSockMsg, "[%s] Received a message of %d bytes",
                 pStreamName.c_str(), toRead->GetSize() );
    }
    return st;
  }
}
