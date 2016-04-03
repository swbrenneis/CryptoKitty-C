#ifndef HMAC_H_INCLUDED
#define HMAC_H_INCLUDED

#include "data/ByteArray.h"

namespace CK {

class Digest;

/*
 * Hash-based message authentication.
 * See RFC-2104 for details.
 */
class HMAC {

    private:
        HMAC();

    public:
        HMAC(Digest *digest);
        ~HMAC();

    private:
        HMAC(const HMAC& other);
        HMAC& operator= (const HMAC& other);

    public:
        bool authenticate(const ByteArray& hmac);
        ByteArray generateKey(unsigned bitsize);
        unsigned getDigestLength() const;
        ByteArray getHMAC();
        void setKey(const ByteArray& k);
        void setMessage(const ByteArray& m);

    private:
        Digest *hash;
        ByteArray K;
        ByteArray ipad;
        ByteArray opad;
        unsigned B;
        unsigned L;
        ByteArray text;

};

}

#endif  // HMAC_H_INCLUDED
