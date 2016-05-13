#ifndef ENCRYPTED_H_INCLUDED
#define ENCRYPTED_H_INCLUDED

#include "openpgp/packet/Packet.h"

namespace CKPGP {

class Encrypted : public Packet {


    public:
        Encrypted();
        Encrypted(const coder::ByteArray& encoded);
        Encrypted(const Encrypted& other);
        Encrypted& operator= (const Encrypted& other);
        ~Encrypted();

    public:
        const coder::ByteArray& getCiphertext() const;
        void setCiphertext(const coder::ByteArray& c);

    private:
        void decode(const coder::ByteArray& encoded);
        void encode();

    private:
        coder::ByteArray ciphertext;

};

}

#endif  // ENCRYPTED_H_INCLUDED
