#ifndef TLSSERVERHANDSHAKE_H_INCLUDED
#define TLSSERVERHANDSHAKE_H_INCLUDED

#include "tls/TlsHandshake.h"

namespace CK {

class TCPConnection;

class TlsServerHandshake :public TlsHandshake {

    public:
       TlsServerHandshake(TCPConnection *c);
       ~TlsServerHandshake();

    private:
       TlsServerHandshake(const TlsServerHandshake& other);
       TlsServerHandshake& operator= (const TlsServerHandshake& other);

    public:
       // Handles hello handshake. Returns true if handshake
       // successful.
       bool startHello();

    private:
       TCPConnection *conn;

};

}
#endif  // TLSSERVERHANDSHAKE_H_INCLUDED
