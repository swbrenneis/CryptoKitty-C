#ifndef HANDSHAKERECORD_H_INCLUDED
#define HANDSHAKERECORD_H_INCLUDED

#include "data/ByteArray.h"
#include "tls/Plaintext.h"
#include "tls/Constants.h"

namespace CKTLS {

class HandshakeBody;
class ConnectionState;

class HandshakeRecord : public Plaintext {

    public:
        HandshakeRecord();
        HandshakeRecord(HandshakeType h);
        HandshakeRecord(const HandshakeRecord& other);
        HandshakeRecord& operator= (const HandshakeRecord& other);
        ~HandshakeRecord();

    public:
        void decode();
        CK::ByteArray encode();
        HandshakeBody *getBody();
        HandshakeType getType() const;

    private:
        HandshakeBody *body;
        HandshakeType type;

};

}
#endif  // HANDSHAKERECORD_H_INCLUDED
