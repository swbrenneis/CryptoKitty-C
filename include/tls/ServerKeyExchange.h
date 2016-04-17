#ifndef SERVERKEYEXCHANGE_H_INCLUDED
#define SERVERKEYEXCHANGE_H_INCLUDED

#include "tls/HandshakeBody.h"

namespace CKTLS {

class ServerKeyExchange : public HandshakeBody {

    public:
        ServerKeyExchange();
        ~ServerKeyExchange();

    private:
        ServerKeyExchange(const ServerKeyExchange& other);
        ServerKeyExchange& operator= (const ServerKeyExchange& other);

    public:
        void decode(const CK::ByteArray& stream);
        CK::ByteArray encode() const;
        void initState();

};

}

#endif  // SERVERKEYEXCHANGE_H_INCLUDED
