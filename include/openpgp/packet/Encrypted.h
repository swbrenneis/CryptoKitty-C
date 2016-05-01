#ifndef ENCRYPTED_H_INCLUDED
#define ENCRYPTED_H_INCLUDED

#include "openpgp/packet/Packet.h"

namespace CKPGP {

class Encrypted : public Packet {


    public:
        Encrypted();
        Encrypted(const CK::ByteArray& encoded);
        Encrypted(const Encrypted& other);
        Encrypted& operator= (const Encrypted& other);
        ~Encrypted();

    public:
        const CK::ByteArray& getCiphertext() const;
        void setCiphertext(const CK::ByteArray& c);

    private:
        void decode(const CK::ByteArray& encoded);
        void encode();

    private:
        CK::ByteArray ciphertext;

};

}

#endif  // ENCRYPTED_H_INCLUDED
