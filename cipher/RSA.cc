#include "cipher/RSA.h"
#include "exceptions/BadParameterException.h"

namespace CK {

// Static initialization.
const BigInteger RSA::MASK(0xff);

RSA::RSA() {
}

RSA::~RSA() {
}

/*
 * Convert an integer representation to an octet string.
 */
ByteArray RSA::i2osp(const BigInteger& x, int xLen) {

    if (x > (BigInteger(256).pow(xLen))) {
        throw BadParameterException("Integer too large");
    }

    ByteArray work(x.encode(BigInteger::BIGENDIAN));
    return work.range(0, xLen);

}

}
