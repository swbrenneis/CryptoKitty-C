#include "openpgp/packet/PublicSubkey.h"

namespace CKPGP {

PublicSubkey::PublicSubkey()
: PublicKey(PUBLICSUBKEY) {
}

PublicSubkey::PublicSubkey(const CK::ByteArray& encoded)
: PublicKey(encoded) {
}

PublicSubkey::PublicSubkey(const CK::BigInteger& m, const CK::BigInteger& e, uint8_t flag)
: PublicKey(m, e, flag) {
}

PublicSubkey::PublicSubkey(const CK::BigInteger& p, const CK::BigInteger& o,
                    const CK::BigInteger g, const CK::BigInteger& v)
: PublicKey(p, o, g, v) {
}

PublicSubkey::PublicSubkey(const CK::BigInteger& p, const CK::BigInteger& g,
                                            const CK::BigInteger& v)
: PublicKey(p, g, v) {
}

PublicSubkey::PublicSubkey(const PublicSubkey& other)
: PublicKey(other) {
}

PublicSubkey::PublicSubkey(PublicSubkey *other)
: PublicKey(*other) {

    delete other;

}

PublicSubkey::~PublicSubkey() {
}

PublicSubkey& PublicSubkey:: operator= (const PublicSubkey& other) {

    PublicKey::operator= (other);
    return *this;

}

PublicSubkey& PublicSubkey:: operator= (PublicSubkey *other) {

    PublicKey::operator= (*other);
    delete other;

    return *this;

}

}

