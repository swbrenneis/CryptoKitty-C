#ifndef SERVERHELLODONE_H_INCLUDED
#define SERVERHELLODONE_H_INCLUDED

#include "tls/HandshakeBody.h"

namespace CKTLS {

class ServerHelloDone : public HandshakeBody {

    public:
        ServerHelloDone() {}
        ~ServerHelloDone() {}

    private:
        ServerHelloDone(const ServerHelloDone& other);
        ServerHelloDone& operator= (const ServerHelloDone& other);

        void decode(const CK::ByteArray& stream) {}
        CK::ByteArray encode() const { return CK::ByteArray(0); }
        void initState() {}

};

}

#endif  // SERVERHELLODONE_H_INCLUDED
