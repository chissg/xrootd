
include( XRootDCommon )

#-------------------------------------------------------------------------------
# Shared library version
#-------------------------------------------------------------------------------
set( XRD_TLS_VERSION   1.0.0 )
set( XRD_TLS_SOVERSION 1 )

#-------------------------------------------------------------------------------
# The XrdCl lib
#-------------------------------------------------------------------------------
#add_library(
#  XrdTls
#  SHARED
#  XrdTls.hh
#)
#
#target_link_libraries(
#  ssl)
#
#set_target_properties(
#  XrdTls
#  PROPERTIES
#  INTERFACE_LINK_LIBRARIES ""
#  LINK_INTERFACE_LIBRARIES ""
#  VERSION   ${XRD_TLS_VERSION}
#  SOVERSION ${XRD_TLS_SOVERSION} )
#
#-------------------------------------------------------------------------------
# Install
#-------------------------------------------------------------------------------
#install(
#  TARGETS XrdTls
#  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} )
