#ifndef HANDSHAKEBODY_H_INCLUDED
#define HANDSHAKEBODY_H_INCLUDED

#include "data/ByteArray.h"
#include <iostream>

namespace CKTLS {

class HandshakeBody {

    protected:
        HandshakeBody();

    public:
        virtual ~HandshakeBody();

    private:
        HandshakeBody(const HandshakeBody& other);
        HandshakeBody& operator= (const HandshakeBody& other);

    public:
        virtual void debugOut(std::ostream& out) {}
        virtual void decode(const CK::ByteArray& stream);
        virtual const CK::ByteArray& encode()=0;
        virtual void initState()=0;

    protected:
        virtual void decode()=0;

    protected:
        CK::ByteArray encoded;

};

}

#endif // HANDSHAKEBODY_H_INCLUDED
