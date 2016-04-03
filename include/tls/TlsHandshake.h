#ifndef TLSHANDSHAKE_H_INCLUDED
#define TLSHANDSHAKE_H_INCLUDED

namespace CK {

class TlsHandshake {

    public:
       enum HandshakeType { server, client };

    protected:
       TlsHandshake() {}

    public:
       virtual ~TlsHandshake() {}

    private:
       TlsHandshake(const TlsHandshake& other);
       TlsHandshake& operator= (const TlsHandshake& other);

    public:
       virtual bool startHello()=0;

};

}
#endif  // TLSHANDSHAKE_H_INCLUDED
