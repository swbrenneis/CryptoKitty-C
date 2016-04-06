#ifndef HELLOREQUEST_H_INCLUDED
#define HELLOREQUEST_H_INCLUDED

#include "tls/HandshakeBody.h"

namespace CKTLS {

class HelloRequest : public HandshakeBody {

    public:
        HelloRequest() {}
        ~HelloRequest() {}

    public:
        void decode(const CK::ByteArray& stream) {}
        CK::ByteArray encode() const { CK::ByteArray empty;
                                    return empty; }
        void initState() {}

};

}

#endif // HELLOREQUEST_H_INCLUDED
