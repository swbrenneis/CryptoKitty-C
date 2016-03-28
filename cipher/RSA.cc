#include "cipher/RSA.h"
#include "keys/RSAPublicKey.h"
#include "random/CMWCRandom.h"
#include "data/NanoTime.h"
#include "exceptions/BadParameterException.h"
#include "exceptions/SignatureException.h"
#include <cmath>

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
ByteArray RSA::i2osp(const BigInteger& x, unsigned xLen) {

    // This was a Java limitation. Since I don't want
    // to have to configure the memory size kernel parameters,
    // I'll leave it in. Any reasonable sized key won't even come
    // close to violating this.
    if (x > (BigInteger(256).pow(xLen))) {
        throw BadParameterException("Integer too large");
    }

    //std::cout << "i2sop x = " << x << std::endl;
    ByteArray work(x.encode(BigInteger::BIGENDIAN));
    if (work.getLength() != xLen) {
        throw BadParameterException("Encoding size mismatch");
    }
    //BigInteger worked(work, BigInteger::BIGENDIAN);
    //std::cout << "worked = " << worked << std::endl;
    return work;

}

/*
 * Convert an octet string to an integer. Just using the constructor gives
 * unreliable results, so we'll do it the hard way.
 */
BigInteger RSA::os2ip(const ByteArray& X) {

    return BigInteger(X, BigInteger::BIGENDIAN);

}

/*
 * Signature verification primitive.
 * 
 * K is the ublic key. s is the signature representative.
 * 
 * Returns the message representative.
 * 
 */
BigInteger RSA::rsavp1(const RSAPublicKey& K, const BigInteger& s) {

    // 1. If the signature representative m is not between 0 and n - 1, output
    //  "signature representative out of range" and stop.
    if (s < BigInteger::ZERO || s >= K.getModulus()) {
        throw SignatureException("Signature representative out of range");
    }

    // Randomize the amount of time to decrypt to prevent timing attacks.
    CMWCRandom rnd;
    NanoTime nt;
    rnd.setSeed(nt.getFullTime());
    int count = std::abs(rnd.nextInt());
    count = count % 65536;
    for (int n = 0; n < count; ++n){
        int s = n * count;
        s = s * count;
    }

    //std:: cout << "rsavp1 s = " << s << std::endl;
    // 2. Let m = s^e mod n.
    BigInteger result(s.modPow(K.getExponent(), K.getModulus()));
    //std::cout << "rsavp1 result = " << result << std::endl;
    return result;

}

/*
 * Byte array bitwise exclusive or.
 */
ByteArray RSA::rsaXor(const ByteArray& a, const ByteArray& b) const {

    if (a.getLength() != b.getLength()) {
        throw BadParameterException("Xor byte arrays must be same length");
    }

    ByteArray result(a.getLength());
    for (unsigned i = 0; i < a.getLength(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;

}

}
