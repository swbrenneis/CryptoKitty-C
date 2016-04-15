#ifndef SERVERKEYEXCHANGE_H_INCLUDED
#define SERVERKEYEXCHANGE_H_INCLUDED

#include "tls/HandshakeRecord.h"

namespace CKTLS {

class ServerKeyExchange : public HandshakeRecord {

    public:
        ServerKeyExchange();
        ~ServerKeyExchange();

    private:
        ServerKeyExchange(const ServerKeyExchange& other);
        ServerKeyExchange& operator= (const ServerKeyExchange& other);

};

}

#endif  // SERVERKEYEXCHANGE_H_INCLUDED
