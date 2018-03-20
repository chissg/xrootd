/*
Copyright (c) 2017 Darren Smith

ssl_examples is free software; you can redistribute it and/or modify
it under the terms of the MIT license. See LICENSE for details.
*/

#ifndef __XRD_TLS_HH__
#define __XRD_TLS_HH__

#include <openssl/bio.h>
#include <openssl/err.h>

namespace XrdTls
{
  struct Exception
  {
      enum Error
      {
        ALLOC_ERR,
        CERT_ERR,
        KEY_ERR,
        CERT_KEY_MISMATCH,
      };

      Exception( const char* file, int line, Error code ) : file( file ), line( line ), error( code )
      {

      }

      const std::string file;
      const int         line;
      Error             error;
  };

#define make_tlserr( code ) Exception( __FILE__, __LINE__, code )

  class Context
  {
    public:

      static Context& Instance()
      {
        static Context ctx;
        return ctx;
      }

      ~Context()
      {
        SSL_CTX_free( ctx );
      }

      operator SSL_CTX*()
      {
        return ctx;
      }

    private:

      Context()
      {
        /* SSL library initialisation */
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        /* create the SSL server context */
        ctx = SSL_CTX_new( SSLv23_method() );
        if( !ctx )
          throw make_tlserr( Exception::ALLOC_ERR );

//        /* Load certificate and private key files, and check consistency */
//        if( SSL_CTX_use_certificate_file( ctx, certfile.c_str(),  SSL_FILETYPE_PEM ) != 1 )
//          throw make_tlserr( TlsErr::CERT_ERR );
//
//        if (SSL_CTX_use_PrivateKey_file( ctx, keyfile.c_str(), SSL_FILETYPE_PEM ) != 1 )
//          throw make_tlserr( TlsErr::KEY_ERR );
//
//        /* Make sure the key and certificate file match. */
//        if( SSL_CTX_check_private_key( ctx ) != 1 )
//          throw make_tlserr( TlsErr::MISMATCH_ERR );
//
//        /* TODO log: "certificate and private key loaded and verified\n" */
//        std::cerr << "certificate and private key loaded and verified" << std::endl;

        /* Recommended to avoid SSLv2 & SSLv3 */
        SSL_CTX_set_options( ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 );
      }

      Context( const Context  &ctx ) = delete;
      Context(       Context &&ctx ) = delete;
      Context& operator=( const Context  &ctx ) = delete;
      Context& operator=(       Context &&ctx ) = delete;

      SSL_CTX *ctx;
  };
}

#endif // __XRD_TLS_HH__

