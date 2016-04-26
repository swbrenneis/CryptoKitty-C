#ifndef PUBLICSUBKEY_H_INCLUDED
#define PUBLICSUBKEY_H_INCLUDED

#include "openpgp/packet/PublicKey.h"
#include "data/BigInteger.h"

namespace CKPGP {

class PublicSubkey : public PublicKey {

    public:
        PublicSubkey();
        PublicSubkey(const CK::BigInteger& m, const CK::BigInteger& e,
                                                        uint8_t flag);    // RSA key
        PublicSubkey(const CK::BigInteger& p, const CK::BigInteger& o,
                    const CK::BigInteger g, const CK::BigInteger& v);    // DSA key
        PublicSubkey(const CK::BigInteger& p, const CK::BigInteger& g,
                    const CK::BigInteger& v);                           // Elgamal key
        PublicSubkey(const CK::ByteArray& encoded);
        ~PublicSubkey();

    public:
        PublicSubkey(const PublicSubkey& other);
        PublicSubkey& operator= (const PublicSubkey& other);

};

}

#endif  // PUBLICSUBKEY_H_INCLUDED
