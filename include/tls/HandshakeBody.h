#ifndef HANDSHAKEBODY_H_INCLUDED
#define HANDSHAKEBODY_H_INCLUDED

#include "data/ByteArray.h"

namespace CKTLS {

class HandshakeBody {

    protected:
        HandshakeBody() {}

    public:
        virtual ~HandshakeBody() {}

    public:
        virtual void decode(const CK::ByteArray& stream)=0;
        virtual CK::ByteArray encode() const=0;
        virtual void initState()=0;

};

}

#endif // HANDSHAKEBODY_H_INCLUDED
