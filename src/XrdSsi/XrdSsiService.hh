#ifndef __XRDSSISERVICE_HH__
#define __XRDSSISERVICE_HH__
/******************************************************************************/
/*                                                                            */
/*                      X r d S s i S e r v i c e . h h                       */
/*                                                                            */
/* (c) 2015 by the Board of Trustees of the Leland Stanford, Jr., University  */
/*   Produced by Andrew Hanushevsky for Stanford University under contract    */
/*              DE-AC02-76-SFO0515 with the Department of Energy              */
/*                                                                            */
/* This file is part of the XRootD software suite.                            */
/*                                                                            */
/* XRootD is free software: you can redistribute it and/or modify it under    */
/* the terms of the GNU Lesser General Public License as published by the     */
/* Free Software Foundation, either version 3 of the License, or (at your     */
/* option) any later version.                                                 */
/*                                                                            */
/* XRootD is distributed in the hope that it will be useful, but WITHOUT      */
/* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or      */
/* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public       */
/* License for more details.                                                  */
/*                                                                            */
/* You should have received a copy of the GNU Lesser General Public License   */
/* along with XRootD in a file called COPYING.LESSER (LGPL license) and file  */
/* COPYING (GPL license).  If not, see <http://www.gnu.org/licenses/>.        */
/*                                                                            */
/* The copyright holder's institutional names and contributor's names may not */
/* be used to endorse or promote products derived from this software without  */
/* specific prior written permission of the institution or contributor.       */
/******************************************************************************/

#include "XrdSsi/XrdSsiErrInfo.hh"
#include "XrdSsi/XrdSsiResource.hh"
  
//-----------------------------------------------------------------------------
//! The XrdSsiService object is used by the Scalable Service Interface to
//! process client requests.
//!
//! There may be many client-side service objects, as needed. However, only
//! one such object is obtained server-side. The object is used to effect all
//! service requests and handle responses.
//!
//! Client-side: the service object is obtained via the object pointed to by
//!              XrdSsiProviderClient defined in libXrdSsi.so
//!
//! Server-side: the service object is obtained via the object pointed to by
//!              XrdSsiProviderServer defined in the plugin shared library.
//-----------------------------------------------------------------------------

class XrdSsiEntity;
class XrdSsiSession;

class XrdSsiService
{
public:

//-----------------------------------------------------------------------------
//! Obtain the version of the abstract class used by underlying implementation.
//! The version returned must match the version compiled in the loading library.
//! If it does not, initialization fails.
//-----------------------------------------------------------------------------

static const int SsiVersion = 0x00010000;

       int     GetVersion() {return SsiVersion;}

//-----------------------------------------------------------------------------
//! The Resource class describes the session resource to be provisioned and is
//! and is used to communicate the results of the provisioning request.
//-----------------------------------------------------------------------------

class          Resource
{
public:
XrdSsiResource rDesc;  //!< The resource description
XrdSsiErrInfo  eInfo;  //!< Holds error information upon failure

//-----------------------------------------------------------------------------
//! Handle the ending results of a Provision() call. It is called by the
//! Service object when provisioning that has actually started completes.
//!
//! @param  sessP    !0 -> to the successfully provisioned session object.
//!                  =0 Provisioning failed, the eInfo object holds the reason.
//-----------------------------------------------------------------------------

virtual void   ProvisionDone(XrdSsiSession *sessP) = 0; //!< Callback

//-----------------------------------------------------------------------------
//! Constructor - See XrdSsiResource for details on the arguments as they are
//! the same here as there. All XrdSsiResource member pointers must remain
//! stable until ProvisionDone() is called.
//-----------------------------------------------------------------------------

               Resource(const char *rname,
                        const char *havoid=0,
                        const char *ruser=0,
                        const char *rinfo=0,
                        XrdSsiResource::Affinity raff=XrdSsiResource::Default
                       ) : rDesc(rname, havoid, ruser, rinfo, raff) {}

//-----------------------------------------------------------------------------
//! Destructor
//-----------------------------------------------------------------------------

virtual       ~Resource() {}
};

//-----------------------------------------------------------------------------
//! Provision of service session; client-side or server-side.
//!
//! @param  resP     Pointer to the Resource object (see above) that describes
//!                  the resource to be provisioned.
//!
//! @param  timeOut  the maximum number seconds the operation may last before
//!                  it is considered to fail. A zero value uses the default.
//!
//! @param  userConn when false, prexisting TCP connections are shared even when
//!                  rUser is unique. Otherwise, TCP connections are only
//!                  shared for the same rUser to the same endpoint.
//!
//! @return The method returns all results via resP->ProvisionDone() callback
//!         which may use the calling thread or a new thread.
//!
//! Special notes for server-side processing:
//!
//! 1) Two special errors are recognized that allow for a client retry:
//!
//!    resP->eInfo.eNum = EAGAIN (client should retry elsewhere)
//!    resP->eInfo.eMsg = the host name where the client is redirected
//!    resP->eInfo.eArg = the port number to be used by the client
//!
//!    resP->eInfo.eNum = EBUSY  (client should wait and then retry).
//!    resP->eInfo.eMsg = an optional reason for the wait.
//!    resP->eInfo.eArg = the number of seconds the client should wait.
//-----------------------------------------------------------------------------

virtual void   Provision(Resource       *resP,
                         unsigned short  timeOut=0,
                         bool            userConn=false
                        ) = 0;

//-----------------------------------------------------------------------------
//! Stop the client-side service. This is never called server-side.
//!
//! @return true     Service has been stopped and this object has been deleted.
//! @return false    Service cannot be stopped because there are still active
//!                  sessions. Unprovision all the sessions then call Stop().
//-----------------------------------------------------------------------------

virtual bool   Stop() {return false;}

//-----------------------------------------------------------------------------
//! Constructor
//-----------------------------------------------------------------------------

               XrdSsiService() {}
protected:

//-----------------------------------------------------------------------------
//! Destructor. The service object canot be explicitly deleted. Use Stop().
//-----------------------------------------------------------------------------

virtual       ~XrdSsiService() {}
};
#endif